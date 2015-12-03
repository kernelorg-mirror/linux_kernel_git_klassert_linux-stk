/*
 * xfrm_device.c - IPsec device offloading code.
 *
 * Copyright (c) 2015 secunet Security Networks AG
 *
 * Author:
 * Steffen Klassert <steffen.klassert@secunet.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/errno.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <net/dst.h>
#include <net/xfrm.h>
#include <linux/notifier.h>

static void xfrm_dev_resume(struct sk_buff *skb, int err)
{
	int ret = NETDEV_TX_BUSY;
	unsigned long flags;
	struct netdev_queue *txq;
	struct softnet_data *sd;
	struct xfrm_state *x = skb_dst(skb)->xfrm;
	struct net_device *dev = skb->dev;

	if (err) {
		XFRM_INC_STATS(xs_net(x), LINUX_MIB_XFRMOUTSTATEPROTOERROR);
		return;
	}

	txq = netdev_pick_tx(dev, skb, NULL);

	HARD_TX_LOCK(dev, txq, smp_processor_id());
	if (!netif_xmit_frozen_or_stopped(txq))
		skb = dev_hard_start_xmit(skb, dev, txq, &ret);
	HARD_TX_UNLOCK(dev, txq);

	if (!dev_xmit_complete(ret)) {
		local_irq_save(flags);
		sd = this_cpu_ptr(&softnet_data);
		skb_queue_tail(&sd->xfrm_backlog, skb);
		raise_softirq_irqoff(NET_TX_SOFTIRQ);
		local_irq_restore(flags);
	}
}

void xfrm_dev_backlog(struct sk_buff_head *xfrm_backlog)
{
	struct sk_buff *skb;
	struct sk_buff_head list;

	__skb_queue_head_init(&list);

	spin_lock(&xfrm_backlog->lock);
	skb_queue_splice_init(xfrm_backlog, &list);
	spin_unlock(&xfrm_backlog->lock);

	while (!skb_queue_empty(&list)) {
		skb = __skb_dequeue(&list);
		xfrm_dev_resume(skb, 0);
	}

}

static int xfrm_dev_validate(struct sk_buff *skb)
{
	struct xfrm_state *x = skb_dst(skb)->xfrm;

	return x->type->output_tail(x, skb);
}

static int xfrm_skb_check_space(struct sk_buff *skb, struct dst_entry *dst)
{
	int nhead = dst->header_len + LL_RESERVED_SPACE(dst->dev)
		- skb_headroom(skb);
	int ntail =  0;

	if (!(skb_shinfo(skb)->gso_type & SKB_GSO_ESP))
		ntail = dst->dev->needed_tailroom - skb_tailroom(skb);

	if (nhead <= 0) {
		if (ntail <= 0)
			return 0;
		nhead = 0;
	} else if (ntail < 0)
		ntail = 0;

	return pskb_expand_head(skb, nhead, ntail, GFP_ATOMIC);
}

static int xfrm_dev_prepare(struct sk_buff *skb)
{
	int err;
	struct dst_entry *dst = skb_dst(skb);
	struct xfrm_state *x = dst->xfrm;
	struct net *net = xs_net(x);

	do {
		spin_lock_bh(&x->lock);

		if (unlikely(x->km.state != XFRM_STATE_VALID)) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTSTATEINVALID);
			err = -EINVAL;
			goto error;
		}

		err = xfrm_state_check_expire(x);
		if (err) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTSTATEEXPIRED);
			goto error;
		}

		err = x->repl->overflow(x, skb);
		if (err) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTSTATESEQERROR);
			goto error;
		}

		x->curlft.bytes += skb->len;
		x->curlft.packets++;

		spin_unlock_bh(&x->lock);

		skb_dst_force(skb);

		skb->hw_xfrm = 1;

		err = x->type->output(x, skb);
		if (err == -EINPROGRESS)
			goto out;

		if (err) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTSTATEPROTOERROR);
			goto error_nolock;
		}

		dst = dst->child;
		if (!dst) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTERROR);
			err = -EHOSTUNREACH;
			goto error_nolock;
		}
		x = dst->xfrm;
	} while (x && !(x->outer_mode->flags & XFRM_MODE_FLAG_TUNNEL));

	return 0;

error:
	spin_unlock_bh(&x->lock);
error_nolock:
	kfree_skb(skb);
out:
	return err;
}

static int xfrm_dev_encap(struct sk_buff *skb)
{
	int err;
	struct dst_entry *dst = skb_dst(skb);
	struct dst_entry *path = dst->path;
	struct xfrm_state *x = dst->xfrm;
	struct net *net = xs_net(x);

	err = xfrm_skb_check_space(skb, dst);
	if (err) {
		XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTERROR);
		return err;
	}

	err = x->outer_mode->output(x, skb);
	if (err) {
		XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTSTATEMODEERROR);
		return err;
	}

	x->type->encap(x, skb);

	return path->output(net, skb->sk, skb);
}

static const struct xfrmdev_ops xfrmdev_soft_ops = {
	.xdo_dev_encap	= xfrm_dev_encap,
	.xdo_dev_prepare = xfrm_dev_prepare,
	.xdo_dev_validate = xfrm_dev_validate,
	.xdo_dev_resume = xfrm_dev_resume,
};

static int xfrm_dev_register(struct net_device *dev)
{
	if (dev->hw_features & NETIF_F_ESP_OFFLOAD)
		goto out;

	dev->priv_flags &= ~IFF_XMIT_DST_RELEASE;

	dev->xfrmdev_ops = &xfrmdev_soft_ops;
out:
	return NOTIFY_DONE;
}

static int xfrm_dev_unregister(struct net_device *dev)
{

	return NOTIFY_DONE;
}

static int xfrm_dev_feat_change(struct net_device *dev)
{
	if (!(dev->hw_features & NETIF_F_ESP_OFFLOAD) &&
	    dev->features & NETIF_F_ESP_OFFLOAD)
		dev->xfrmdev_ops = &xfrmdev_soft_ops;

	return NOTIFY_DONE;
}

static int xfrm_dev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	switch (event) {
	case NETDEV_REGISTER:
		return xfrm_dev_register(dev);

	case NETDEV_UNREGISTER:
		return xfrm_dev_unregister(dev);

	case NETDEV_FEAT_CHANGE:
		return xfrm_dev_feat_change(dev);

	case NETDEV_DOWN:
		xfrm_garbage_collect(dev_net(dev));
	}
	return NOTIFY_DONE;
}

static struct notifier_block xfrm_dev_notifier = {
	.notifier_call	= xfrm_dev_event,
};

void __net_init xfrm_dev_init(void)
{
	register_netdevice_notifier(&xfrm_dev_notifier);
}
