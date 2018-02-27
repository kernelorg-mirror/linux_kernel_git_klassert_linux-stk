#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/types.h>

#include <net/xfrm.h>
#include <net/arp.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <net/esp.h>
#include <net/protocol.h>

#include <crypto/aead.h>

static const struct net_offload __rcu *nft_offloads[MAX_INET_PROTOS] __read_mostly;

/* XXX: Maybe export this from net/core/skbuff.c
 * instead of holding a local copy */
static void skb_headers_offset_update(struct sk_buff *skb, int off)
{
	/* Only adjust this if it actually is csum_start rather than csum */
	if (skb->ip_summed == CHECKSUM_PARTIAL)
		skb->csum_start += off;
	/* {transport,network,mac}_header and tail are relative to skb->head */
	skb->transport_header += off;
	skb->network_header   += off;
	if (skb_mac_header_was_set(skb))
		skb->mac_header += off;
	skb->inner_transport_header += off;
	skb->inner_network_header += off;
	skb->inner_mac_header += off;
}

static struct sk_buff *nft_skb_segment(struct sk_buff *head_skb)
{
	int err = -ENOMEM;
	unsigned int headroom;
	struct sk_buff *nskb;
	struct sk_buff *segs = NULL;
	struct sk_buff *tail = NULL;
	unsigned int doffset = head_skb->data - skb_mac_header(head_skb);
	struct sk_buff *list_skb = skb_shinfo(head_skb)->frag_list;
	unsigned int tnl_hlen = skb_tnl_header_len(head_skb);
	unsigned int delta_segs, delta_len, delta_truesize;

	__skb_push(head_skb, doffset);

	headroom = skb_headroom(head_skb);

	delta_segs = delta_len = delta_truesize = 0;

	skb_shinfo(head_skb)->frag_list = NULL;

	segs = skb_clone(head_skb, GFP_ATOMIC);
	if (unlikely(!segs))
		return ERR_PTR(err);

	do {
		nskb = list_skb;

		list_skb = list_skb->next;

		if (!tail)
			segs->next = nskb;
		else
			tail->next = nskb;

		tail = nskb;

		delta_len += nskb->len;
		delta_truesize += nskb->truesize;

		skb_push(nskb, doffset);

		nskb->dev = head_skb->dev;
		nskb->queue_mapping = head_skb->queue_mapping;
		nskb->network_header = head_skb->network_header;
		nskb->mac_len = head_skb->mac_len;
		nskb->mac_header = head_skb->mac_header;
		nskb->transport_header = head_skb->transport_header;

		if (!secpath_exists(nskb))
			nskb->sp = secpath_get(head_skb->sp);

		skb_headers_offset_update(nskb, skb_headroom(nskb) - headroom);

		skb_copy_from_linear_data_offset(head_skb, -tnl_hlen,
						 nskb->data - tnl_hlen,
						 doffset + tnl_hlen);

	} while (list_skb);

	segs->len = head_skb->len - delta_len;
	segs->data_len = head_skb->data_len - delta_len;
	segs->truesize += head_skb->data_len - delta_truesize;

	head_skb->len = segs->len;
	head_skb->data_len = segs->data_len;
	head_skb->truesize += segs->truesize;

	skb_shinfo(segs)->gso_size = 0;
	skb_shinfo(segs)->gso_segs = 0;
	skb_shinfo(segs)->gso_type = 0;

	segs->prev = tail;

	return segs;

	kfree_skb_list(segs);
	return ERR_PTR(err);
}

static struct sk_buff *nft_udp4_gso_segment(struct sk_buff *skb,
					    netdev_features_t features)
{
	skb_push(skb, sizeof(struct iphdr));
	return nft_skb_segment(skb);
}

static struct sk_buff *nft_tcp4_gso_segment(struct sk_buff *skb,
					    netdev_features_t features)
{
	skb_push(skb, sizeof(struct iphdr));
	return nft_skb_segment(skb);
}

static struct sk_buff *nft_esp4_gso_segment(struct sk_buff *skb,
					    netdev_features_t features)
{
	struct xfrm_offload *xo = xfrm_offload(skb);
	netdev_features_t esp_features = features;
	struct crypto_aead *aead;
	struct ip_esp_hdr *esph;
	struct xfrm_state *x;

	if (!xo)
		return ERR_PTR(-EINVAL);

	x = skb->sp->xvec[skb->sp->len - 1];
	aead = x->data;
	esph = ip_esp_hdr(skb);

	if (esph->spi != x->id.spi)
		return ERR_PTR(-EINVAL);

	if (!pskb_may_pull(skb, sizeof(*esph) + crypto_aead_ivsize(aead)))
		return ERR_PTR(-EINVAL);

	__skb_pull(skb, sizeof(*esph) + crypto_aead_ivsize(aead));

	skb->encap_hdr_csum = 1;

	if (!(features & NETIF_F_HW_ESP) || !x->xso.offload_handle ||
	    (x->xso.dev != skb->dev))
		esp_features = features & ~(NETIF_F_SG | NETIF_F_CSUM_MASK);

	xo->flags |= XFRM_GSO_SEGMENT;

	return x->outer_mode->gso_segment(x, skb, esp_features);
}

static struct sk_buff *nft_ipv4_gso_segment(struct sk_buff *skb,
					    netdev_features_t features)
{
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	const struct net_offload *ops;
	struct packet_offload *ptype;
	struct iphdr *iph;
	int proto;
	int ihl;

	if (!(skb_shinfo(skb)->gso_type & SKB_GSO_NFT)) {
		ptype = dev_get_packet_offload(skb->protocol, 1);
		if (ptype) {
			return ptype->callbacks.gso_segment(skb, features);
		}

		return ERR_PTR(-EPROTONOSUPPORT);

	}

	if (SKB_GSO_CB(skb)->encap_level == 0) {
		iph = ip_hdr(skb);
		skb_reset_network_header(skb);
	} else {
		iph = (struct iphdr *)skb->data;
	}

	if (unlikely(!pskb_may_pull(skb, sizeof(*iph))))
		goto out;

	ihl = iph->ihl * 4;
	if (ihl < sizeof(*iph))
		goto out;

	SKB_GSO_CB(skb)->encap_level += ihl;

	if (unlikely(!pskb_may_pull(skb, ihl)))
		goto out;

	__skb_pull(skb, ihl);

	proto = iph->protocol;

	segs = ERR_PTR(-EPROTONOSUPPORT);

	ops = rcu_dereference(nft_offloads[proto]);
	if (likely(ops && ops->callbacks.gso_segment))
		segs = ops->callbacks.gso_segment(skb, features);

out:
	return segs;
}

static int nft_skb_gro_receive(struct sk_buff **head, struct sk_buff *skb)
{
	struct sk_buff *p = *head;

	if (NAPI_GRO_CB(p)->last == p)
		skb_shinfo(p)->frag_list = skb;
	else
		NAPI_GRO_CB(p)->last->next = skb;
	NAPI_GRO_CB(p)->last = skb;

	NAPI_GRO_CB(p)->count++;
	p->data_len += skb->len;
	p->truesize += skb->truesize;
	p->len += skb->len;

	NAPI_GRO_CB(skb)->same_flow = 1;
	return 0;
}

static struct sk_buff **udp_gro_ffwd_receive(struct sk_buff **head,
					     struct sk_buff *skb,
					     struct udphdr *uh)
{
	struct sk_buff *p = NULL;
	struct sk_buff **pp = NULL;
	struct udphdr *uh2;
	int flush = 0;

	for (; (p = *head); head = &p->next) {

		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		uh2 = udp_hdr(p);

		/* Match ports and either checksums are either both zero
		 * or nonzero.
		 */
		if ((*(u32 *)&uh->source != *(u32 *)&uh2->source) ||
		    (!uh->check ^ !uh2->check)) {
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}

		goto found;
	}

	goto out;

found:
	p = *head;

	if (nft_skb_gro_receive(head, skb))
		flush = 1;

out:
	if (p && (!NAPI_GRO_CB(skb)->same_flow || flush))
		pp = head;

	NAPI_GRO_CB(skb)->flush |= flush;
	return pp;
}

static struct sk_buff **nft_udp4_gro_receive(struct sk_buff **head,
					     struct sk_buff *skb)
{
	struct udphdr *uh;

	uh = skb_gro_header_slow(skb, skb_transport_offset(skb) + sizeof(struct udphdr),
				 skb_transport_offset(skb));

	if (unlikely(!uh))
		goto flush;

	if (NAPI_GRO_CB(skb)->flush)
		goto flush;

	if (NAPI_GRO_CB(skb)->is_ffwd)
		return udp_gro_ffwd_receive(head, skb, uh);

flush:
	NAPI_GRO_CB(skb)->flush = 1;
	return NULL;
}

static struct sk_buff **nft_tcp4_gro_receive(struct sk_buff **head,
					     struct sk_buff *skb)
{
	struct sk_buff **pp = NULL;
	struct sk_buff *p;
	struct tcphdr *th;
	struct tcphdr *th2;
	unsigned int len;
	unsigned int thlen;
	__be32 flags;
	unsigned int mss = 1;
	unsigned int hlen;
	int flush = 1;
	int i;

	th = skb_gro_header_slow(skb, skb_transport_offset(skb) + sizeof(struct tcphdr),
				 skb_transport_offset(skb));
	if (unlikely(!th))
		goto out;

	thlen = th->doff * 4;
	if (thlen < sizeof(*th))
		goto out;

	hlen = skb_transport_offset(skb) + thlen;

	th = skb_gro_header_slow(skb, hlen, skb_transport_offset(skb));
	if (unlikely(!th))
		goto out;

	skb_gro_pull(skb, thlen);
	len = skb_gro_len(skb);
	flags = tcp_flag_word(th);

	for (; (p = *head); head = &p->next) {
		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		th2 = tcp_hdr(p);

		if (*(u32 *)&th->source ^ *(u32 *)&th2->source) {
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}

		goto found;
	}

	goto out_check_final;

found:
	flush = NAPI_GRO_CB(p)->flush;
	flush |= (__force int)(flags & TCP_FLAG_CWR);
	flush |= (__force int)((flags ^ tcp_flag_word(th2)) &
		  ~(TCP_FLAG_CWR | TCP_FLAG_FIN | TCP_FLAG_PSH));
	flush |= (__force int)(th->ack_seq ^ th2->ack_seq);
	for (i = sizeof(*th); i < thlen; i += 4)
		flush |= *(u32 *)((u8 *)th + i) ^
			 *(u32 *)((u8 *)th2 + i);

	mss = skb_shinfo(p)->gso_size;

	flush |= (len - 1) >= mss;
	flush |= (ntohl(th2->seq) + (skb_gro_len(p) - (hlen * (NAPI_GRO_CB(p)->count - 1)))) ^ ntohl(th->seq);

	if (flush || nft_skb_gro_receive(head, skb)) {
		mss = 1;
		goto out_check_final;
	}

	p = *head;

out_check_final:
	flush = len < mss;
	flush |= (__force int)(flags & (TCP_FLAG_URG | TCP_FLAG_PSH |
					TCP_FLAG_RST | TCP_FLAG_SYN |
					TCP_FLAG_FIN));

	if (p && (!NAPI_GRO_CB(skb)->same_flow || flush))
		pp = head;

out:
	NAPI_GRO_CB(skb)->flush |= (flush != 0);

	return pp;
}

static struct sk_buff **__nft_ipv4_gro_receive(struct sk_buff **head,
					       struct sk_buff *skb)
{
	const struct net_offload *ops;
	struct sk_buff **pp = NULL;
	struct sk_buff *p;
	struct iphdr *iph;
	unsigned int hlen;
	unsigned int off;
	int flush = 1;
	int proto;

	off = skb_gro_offset(skb);
	hlen = off + sizeof(*iph);

	iph = skb_gro_header_slow(skb, hlen, off);
	if (unlikely(!iph))
		goto out;

	proto = iph->protocol;

	rcu_read_lock();
	ops = rcu_dereference(nft_offloads[proto]);
	if (!ops || !ops->callbacks.gro_receive)
		goto out_unlock;

	if (*(u8 *)iph != 0x45)
		goto out_unlock;

	if (iph->ihl > 5)
		goto out_unlock;

	if (unlikely(ip_fast_csum((u8 *)iph, 5)))
		goto out_unlock;

	if (ip_is_fragment(iph))
		goto out_unlock;

	skb_forward_csum(skb);

	if (iph->ttl <= 1)
		goto out_unlock;

	flush = 0;

	for (p = *head; p; p = p->next) {
		struct iphdr *iph2;

		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		if (!NAPI_GRO_CB(p)->is_ffwd)
			continue;

		if (!skb_dst(p))
			continue;

		iph2 = ip_hdr(p);
		/* The above works because, with the exception of the top
		 * (inner most) layer, we only aggregate pkts with the same
		 * hdr length so all the hdrs we'll need to verify will start
		 * at the same offset.
		 */
		if ((iph->protocol ^ iph2->protocol) |
		    ((__force u32)iph->saddr ^ (__force u32)iph2->saddr) |
		    ((__force u32)iph->daddr ^ (__force u32)iph2->daddr)) {
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}

		/* All fields must match except length and checksum. */
		NAPI_GRO_CB(p)->flush |=
			((iph->ttl - 1) ^ iph2->ttl) |
			(iph->tos ^ iph2->tos) |
			((iph->frag_off ^ iph2->frag_off) & htons(IP_DF));

		NAPI_GRO_CB(skb)->is_ffwd = 1;
		skb_dst_set_noref(skb, skb_dst(p));
		pp = &p;

		goto found;
	}

	if (ip_route_input_noref(skb, iph->daddr, iph->saddr, iph->tos,
				 skb->dev)) {
		flush = 1;
		goto out_unlock;
	}

	if (!(skb_dst(skb)->flags & DST_FFWD)) {
		flush = 1;
		goto out_unlock;
	}

	/* XXX: Maybe better drop if the policy check fails? */
	if (!xfrm4_policy_check(NULL, XFRM_POLICY_FWD, skb)) {
		flush = 1;
		skb_dst_drop(skb);
		goto out_unlock;
	}

	/* XXX: Only with IPsec offload (GRO/GSO) enabled!!! */
	if (!xfrm4_route_forward(skb)) {
		flush = 1;
		skb_dst_drop(skb);
		goto out_unlock;
	}

	if (skb->len > dst_mtu(skb_dst(skb))) {
		flush = 1;
		skb_dst_drop(skb);
		goto out_unlock;
	}

	NAPI_GRO_CB(skb)->is_ffwd = 1;


found:
	NAPI_GRO_CB(skb)->is_atomic = !!(iph->frag_off & htons(IP_DF));
	NAPI_GRO_CB(skb)->flush |= flush;

	ip_decrease_ttl(iph);
	skb->priority = rt_tos2priority(iph->tos);

	skb_pull(skb, off);
	NAPI_GRO_CB(skb)->data_offset = sizeof(*iph);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, sizeof(*iph));

	pp = call_gro_receive(ops->callbacks.gro_receive, head, skb);
out_unlock:
	rcu_read_unlock();

out:
	skb_gro_flush_final(skb, pp, flush);

	return pp;
}

static inline bool nf_hook_gro_active(const struct sk_buff *skb)
{
#ifdef HAVE_JUMP_LABEL
	if (!static_key_false(&nf_hooks_needed[NFPROTO_NETDEV][NF_NETDEV_GRO]))
		return false;
#endif
	return rcu_access_pointer(skb->dev->nf_hooks_gro);
}

static int nf_hook_gro(struct sk_buff *skb, int *err)
{
	struct nf_hook_entries *e = rcu_dereference(skb->dev->nf_hooks_gro);
	struct nf_hook_state state;
	int ret = NF_ACCEPT;

	if (nf_hook_gro_active(skb)) {
		if (unlikely(!e))
			return 0;

		nf_hook_state_init(&state, NF_NETDEV_GRO,
				   NFPROTO_NETDEV, skb->dev, NULL, NULL,
				   dev_net(skb->dev), NULL);

		__skb_pull(skb, skb->mac_len);
		ret = nf_hook_netdev(skb, &state, e, err);
		__skb_push(skb, skb->mac_len);
	}

	return ret;
}

static struct sk_buff **nft_ipv4_gro_receive(struct sk_buff **head,
					     struct sk_buff *skb)
{
	struct packet_offload *ptype;
	struct sk_buff **pp = NULL;
	int ret, err;

	rcu_read_lock();
	ret = nf_hook_gro(skb, &err);
	switch (ret) {
	case NF_AGGREGATE:
		pp = __nft_ipv4_gro_receive(head, skb);
		if (NAPI_GRO_CB(skb)->is_ffwd)
			break;
		/* Fall through */
	case NF_ACCEPT:
		ptype = dev_get_packet_offload(skb->protocol, 1);
		if (ptype)
			pp = ptype->callbacks.gro_receive(head, skb);
		break;
	case NF_DROP:
		pp = ERR_PTR(-EPERM);
		break;
	}
	rcu_read_unlock();

	return pp;
}

static int nft_ipv4_gro_complete(struct sk_buff *skb, int nhoff)
{
	struct iphdr *iph = (struct iphdr *)(skb->data + nhoff);
	struct dst_entry *dst = skb_dst(skb);
	struct rtable *rt = (struct rtable *)dst;
	const struct net_offload *ops;
	struct packet_offload *ptype;
	struct net_device *dev;
	struct neighbour *neigh;
	int proto = iph->protocol;
	u32 nexthop;
	unsigned int hh_len;
	int err = 0;

	if (!NAPI_GRO_CB(skb)->is_ffwd) {
		ptype = dev_get_packet_offload(skb->protocol, 1);
		if (ptype) {
			return ptype->callbacks.gro_complete(skb, nhoff);
		}

		return 0;
	}

	rcu_read_lock();
	ops = rcu_dereference(nft_offloads[proto]);
	if (!ops || !ops->callbacks.gro_complete)
		goto out_unlock;

	/* Only need to add sizeof(*iph) to get to the next hdr below
	 * because any hdr with option will have been flushed in
	 * inet_gro_receive().
	 */
	err = ops->callbacks.gro_complete(skb, nhoff + sizeof(*iph));

out_unlock:
	rcu_read_unlock();

	if (err)
		return err;

	skb_shinfo(skb)->gso_type |= SKB_GSO_NFT;

	dev = dst->dev;
	dev_hold(dev);
	skb->dev = dev;

	if (NAPI_GRO_CB(skb)->count <= 1)
		skb_gso_reset(skb);
	else
		skb_shinfo(skb)->gso_segs = NAPI_GRO_CB(skb)->count;

	if (skb_dst(skb)->xfrm) {
		err = dst_output(dev_net(dev), NULL, skb);
		if (err != -EREMOTE)
			return -EINPROGRESS;
	}

	hh_len = LL_RESERVED_SPACE(dev);

	if (unlikely(skb_headroom(skb) < hh_len && dev->header_ops)) {
		struct sk_buff *skb2;

		skb2 = skb_realloc_headroom(skb, LL_RESERVED_SPACE(dev));
		if (!skb2) {
			kfree_skb(skb);
			return -ENOMEM;
		}
		consume_skb(skb);
		skb = skb2;
	}
	rcu_read_lock();
	nexthop = (__force u32) rt_nexthop(rt, iph->daddr);
	neigh = __ipv4_neigh_lookup_noref(dev, nexthop);
	if (unlikely(!neigh))
		neigh = __neigh_create(&arp_tbl, &nexthop, dev, false);
	if (!IS_ERR(neigh))
		neigh_output(neigh, skb);
	rcu_read_unlock();

	return -EINPROGRESS;
}

static struct packet_offload nft_packet_offload __read_mostly = {
	.type = cpu_to_be16(ETH_P_IP),
	.priority = 0,
	.callbacks = {
		.gro_receive = nft_ipv4_gro_receive,
		.gro_complete = nft_ipv4_gro_complete,
		.gso_segment = nft_ipv4_gso_segment,
	},
};

static const struct net_offload nft_udp4_offload = {
	.callbacks = {
		.gso_segment = nft_udp4_gso_segment,
		.gro_receive  =	nft_udp4_gro_receive,
	},
};

static const struct net_offload nft_tcp4_offload = {
	.callbacks = {
		.gso_segment = nft_tcp4_gso_segment,
		.gro_receive  =	nft_tcp4_gro_receive,
	},
};

static const struct net_offload nft_esp4_offload = {
	.callbacks = {
		.gso_segment = nft_esp4_gso_segment,
	},
};

static int nft_add_offload(const struct net_offload *prot, unsigned char protocol)
{
	return !cmpxchg((const struct net_offload **)&nft_offloads[protocol],
			NULL, prot) ? 0 : -1;
}

static int nft_del_offload(const struct net_offload *prot, unsigned char protocol)
{
	int ret;

	ret = (cmpxchg((const struct net_offload **)&nft_offloads[protocol],
		       prot, NULL) == prot) ? 0 : -1;

	synchronize_net();

	return ret;
}

void nf_gro_enable(void)
{
	/* XXX: Add these offload structures to enable the hook. */
	nft_add_offload(&nft_udp4_offload, IPPROTO_UDP);
	nft_add_offload(&nft_tcp4_offload, IPPROTO_TCP);
	nft_add_offload(&nft_esp4_offload, IPPROTO_ESP);
	dev_add_offload(&nft_packet_offload);
}
EXPORT_SYMBOL_GPL(nf_gro_enable);

void nf_gro_disable(void)
{
	/* XXX: dev_remove_offload() somewhere! */
	dev_remove_offload(&nft_packet_offload);
	nft_del_offload(&nft_esp4_offload, IPPROTO_ESP);
	nft_del_offload(&nft_tcp4_offload, IPPROTO_TCP);
	nft_del_offload(&nft_udp4_offload, IPPROTO_UDP);
}
EXPORT_SYMBOL_GPL(nf_gro_disable);
