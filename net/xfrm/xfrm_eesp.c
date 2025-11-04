// SPDX-License-Identifier: GPL-2.0-only

#include <crypto/aead.h>
#include <crypto/authenc.h>
#include <linux/err.h>
#include <linux/module.h>
#include <net/ip.h>
#include <net/xfrm.h>
#include <net/eesp.h>
#include <linux/scatterlist.h>
#include <linux/kernel.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/in6.h>
#include <net/icmp.h>
#include <net/protocol.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <net/espintcp.h>
#include <linux/skbuff_ref.h>

#include <linux/highmem.h>

struct eesp_skb_cb {
	struct xfrm_skb_cb xfrm;
	void *tmp;
};

#define EESP_SKB_CB(__skb) ((struct eesp_skb_cb *)&((__skb)->cb[0]))

/*
 * Allocate an AEAD request structure with extra space for SG and IV.
 *
 * For alignment considerations the IV is placed at the front, followed
 * by the request and finally the SG list.
 *
 * TODO: Use spare space in skb for this where possible.
 */
static void *eesp_alloc_tmp(struct crypto_aead *aead, int nfrags)
{
	unsigned int len;

	len = crypto_aead_ivsize(aead);

	if (len) {
		len += crypto_aead_alignmask(aead) &
		       ~(crypto_tfm_ctx_alignment() - 1);
		len = ALIGN(len, crypto_tfm_ctx_alignment());
	}

	len += sizeof(struct aead_request) + crypto_aead_reqsize(aead);
	len = ALIGN(len, __alignof__(struct scatterlist));

	len += sizeof(struct scatterlist) * nfrags;

	return kmalloc(len, GFP_ATOMIC);
}

static inline u8 *eesp_tmp_iv(struct crypto_aead *aead, void *tmp)
{
	return crypto_aead_ivsize(aead) ?
	       PTR_ALIGN((u8 *)tmp,
			 crypto_aead_alignmask(aead) + 1) : tmp;
}

static inline struct aead_request *eesp_tmp_req(struct crypto_aead *aead, u8 *iv)
{
	struct aead_request *req;

	req = (void *)PTR_ALIGN(iv + crypto_aead_ivsize(aead),
				crypto_tfm_ctx_alignment());
	aead_request_set_tfm(req, aead);
	return req;
}

static inline struct scatterlist *eesp_req_sg(struct crypto_aead *aead,
					     struct aead_request *req)
{
	return (void *)ALIGN((unsigned long)(req + 1) +
			     crypto_aead_reqsize(aead),
			     __alignof__(struct scatterlist));
}

static void eesp_ssg_unref(struct xfrm_state *x, void *tmp, struct sk_buff *skb)
{
	struct crypto_aead *aead = x->data;
	u8 *iv;
	struct aead_request *req;
	struct scatterlist *sg;

	iv = eesp_tmp_iv(aead, tmp);
	req = eesp_tmp_req(aead, iv);

	/* Unref skb_frag_pages in the src scatterlist if necessary.
	 * Skip the first sg which comes from skb->data.
	 */
	if (req->src != req->dst)
		for (sg = sg_next(req->src); sg; sg = sg_next(sg))
			skb_page_unref(page_to_netmem(sg_page(sg)),
				       skb->pp_recycle);
}

#ifdef CONFIG_INET_ESPINTCP
static int eesp_output_tcp_finish(struct xfrm_state *x, struct sk_buff *skb)
{
	struct sock *sk;
	int err;

	rcu_read_lock();

	sk = x->type->find_tcp_sk(x);
	err = PTR_ERR_OR_ZERO(sk);
	if (err) {
		kfree_skb(skb);
		goto out;
	}

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk))
		err = espintcp_queue_out(sk, skb);
	else
		err = espintcp_push_skb(sk, skb);
	bh_unlock_sock(sk);

	sock_put(sk);

out:
	rcu_read_unlock();
	return err;
}

static int eesp_output_tcp_encap_cb(struct net *net, struct sock *sk,
				   struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct xfrm_state *x = dst->xfrm;

	return eesp_output_tcp_finish(x, skb);
}

static int eesp_output_tail_tcp(struct xfrm_state *x, struct sk_buff *skb)
{
	int err;

	local_bh_disable();
	err = xfrm_trans_queue_net(xs_net(x), skb, eesp_output_tcp_encap_cb);
	local_bh_enable();

	/* EINPROGRESS just happens to do the right thing.  It
	 * actually means that the skb has been consumed and
	 * isn't coming back.
	 */
	return err ?: -EINPROGRESS;
}
#else
static int eesp_output_tail_tcp(struct xfrm_state *x, struct sk_buff *skb)
{
	WARN_ON(1);
	return -EOPNOTSUPP;
}
#endif

static void eesp_output_done(void *data, int err)
{
	struct sk_buff *skb = data;
	struct xfrm_offload *xo = xfrm_offload(skb);
	void *tmp;
	struct xfrm_state *x;

	if (xo && (xo->flags & XFRM_DEV_RESUME)) {
		struct sec_path *sp = skb_sec_path(skb);

		x = sp->xvec[sp->len - 1];
	} else {
		x = skb_dst(skb)->xfrm;
	}

	tmp = EESP_SKB_CB(skb)->tmp;
	eesp_ssg_unref(x, tmp, skb);
	kfree(tmp);

	x->type->output_encap_csum(skb);

	if (xo && (xo->flags & XFRM_DEV_RESUME)) {
		if (err) {
			XFRM_INC_STATS(xs_net(x), LINUX_MIB_XFRMOUTSTATEPROTOERROR);
			kfree_skb(skb);
			return;
		}

		skb_push(skb, skb->data - skb_mac_header(skb));
		secpath_reset(skb);
		xfrm_dev_resume(skb);
	} else {
		if (!err &&
		    x->encap && x->encap->encap_type == TCP_ENCAP_ESPINTCP)
			eesp_output_tail_tcp(x, skb);
		else
			xfrm_output_resume(skb_to_full_sk(skb), skb, err);
	}
}

static void eesp_output_done_esn(void *data, int err)
{
	eesp_output_done(data, err);
}

static struct ip_eesp_hdr *eesp_output_udp_encap(struct sk_buff *skb,
					         int encap_type,
					         struct eesp_info *eesp,
					         __be16 sport,
					         __be16 dport)
{
	struct udphdr *uh;
	unsigned int len;
	struct xfrm_offload *xo = xfrm_offload(skb);

	len = skb->len + eesp->tailen - skb_transport_offset(skb);
	if (len + sizeof(struct iphdr) > IP_MAX_MTU)
		return ERR_PTR(-EMSGSIZE);

	uh = (struct udphdr *)eesp->eesph;
	uh->source = sport;
	uh->dest = dport;
	uh->len = htons(len);
	uh->check = 0;

	/* For IPv4 ESP with UDP encapsulation, if xo is not null, the skb is in the crypto offload
	 * data path, which means that esp_output_udp_encap is called outside of the XFRM stack.
	 * In this case, the mac header doesn't point to the IPv4 protocol field, so don't set it.
	 */
	if (!xo || encap_type != UDP_ENCAP_ESPINUDP)
		*skb_mac_header(skb) = IPPROTO_UDP;

	return (struct ip_eesp_hdr *)(uh + 1);
}



#ifdef CONFIG_INET_ESPINTCP
static struct ip_eesp_hdr *eesp_output_tcp_encap(struct xfrm_state *x,
						 struct sk_buff *skb,
						 struct eesp_info *eesp)
{
	__be16 *lenp = (void *)eesp->eesph;
	struct ip_eesp_hdr *eesph;
	unsigned int len;
	struct sock *sk;

	len = skb->len + eesp->tailen - skb_transport_offset(skb);
	if (len > IP_MAX_MTU)
		return ERR_PTR(-EMSGSIZE);

	rcu_read_lock();
	sk = x->type->find_tcp_sk(x);
	rcu_read_unlock();

	if (IS_ERR(sk))
		return ERR_CAST(sk);

	sock_put(sk);

	*lenp = htons(len);
	eesph = (struct ip_eesp_hdr *)(lenp + 1);

	return eesph;
}
#else
static struct ip_eesp_hdr *eesp_output_tcp_encap(struct xfrm_state *x,
						 struct sk_buff *skb,
						 struct eesp_info *esp)
{
	return ERR_PTR(-EOPNOTSUPP);
}
#endif

static int eesp_output_encap(struct xfrm_state *x, struct sk_buff *skb,
			    struct eesp_info *eesp)
{
	struct xfrm_encap_tmpl *encap = x->encap;
	struct ip_eesp_hdr *eesph;
	__be16 sport, dport;
	int encap_type;

	eesph = ERR_PTR(-EOPNOTSUPP);

	spin_lock_bh(&x->lock);
	sport = encap->encap_sport;
	dport = encap->encap_dport;
	encap_type = encap->encap_type;
	spin_unlock_bh(&x->lock);

	switch (encap_type) {
	default:
	case UDP_ENCAP_ESPINUDP:
		eesph = eesp_output_udp_encap(skb, encap_type, eesp, sport, dport);
		break;
	case TCP_ENCAP_ESPINTCP:
		eesph = eesp_output_tcp_encap(x, skb, eesp);
		break;
	}

	if (IS_ERR(eesph))
		return PTR_ERR(eesph);

	eesp->eesph = eesph;

	return 0;
}

int eesp_output_head(struct xfrm_state *x, struct sk_buff *skb, struct eesp_info *eesp)
{
	u8 *tail;
	int nfrags;
	int eesph_offset;
	struct page *page;
	struct sk_buff *trailer;
	int tailen = eesp->tailen;

	/* this is non-NULL only with TCP/UDP Encapsulation */
	if (x->encap) {
		int err = eesp_output_encap(x, skb, eesp);
		if (err < 0)
			return err;
	}

	if (ALIGN(tailen, L1_CACHE_BYTES) > PAGE_SIZE ||
	    ALIGN(skb->data_len, L1_CACHE_BYTES) > PAGE_SIZE)
		goto cow;

	if (!skb_cloned(skb)) {
		if (tailen <= skb_tailroom(skb)) {
			nfrags = 1;
			trailer = skb;
			tail = skb_tail_pointer(trailer);

			goto skip_cow;
		} else if ((skb_shinfo(skb)->nr_frags < MAX_SKB_FRAGS)
			   && !skb_has_frag_list(skb)) {
			int allocsize;
			struct sock *sk = skb->sk;
			struct page_frag *pfrag = &x->xfrag;

			eesp->inplace = false;

			allocsize = ALIGN(tailen, L1_CACHE_BYTES);

			spin_lock_bh(&x->lock);

			if (unlikely(!skb_page_frag_refill(allocsize, pfrag, GFP_ATOMIC))) {
				spin_unlock_bh(&x->lock);
				goto cow;
			}

			page = pfrag->page;
			get_page(page);

			tail = page_address(page) + pfrag->offset;

			/* Fill padding... */
			memset(tail, 0, eesp->plen);

			nfrags = skb_shinfo(skb)->nr_frags;

			__skb_fill_page_desc(skb, nfrags, page, pfrag->offset,
					     tailen);
			skb_shinfo(skb)->nr_frags = ++nfrags;

			pfrag->offset = pfrag->offset + allocsize;

			spin_unlock_bh(&x->lock);

			nfrags++;

			skb_len_add(skb, tailen);
			if (sk && sk_fullsock(sk))
				refcount_add(tailen, &sk->sk_wmem_alloc);

			goto out;
		}
	}

cow:
	eesph_offset = (unsigned char *)eesp->eesph - skb_transport_header(skb);

	nfrags = skb_cow_data(skb, tailen, &trailer);
	if (nfrags < 0)
		goto out;
	tail = skb_tail_pointer(trailer);
	eesp->eesph = (struct ip_eesp_hdr *)(skb_transport_header(skb) + eesph_offset);

skip_cow:
	/* Fill padding... */
//	memset(tail, 0, eesp->plen);
	memset(tail, 0, eesp->plen);
	pskb_put(skb, trailer, tailen);

out:
	return nfrags;
}
EXPORT_SYMBOL_GPL(eesp_output_head);

int eesp_output_tail(struct xfrm_state *x, struct sk_buff *skb, struct eesp_info *eesp)
{
	u8 *iv;
	int alen;
	void *tmp;
	int ivlen;
	int assoclen;
	struct page *page;
	struct ip_eesp_peer_hdr *eesp_ph;
	struct ip_eesp_hdr *eesph;
	struct crypto_aead *aead;
	struct aead_request *req;
	struct scatterlist *sg, *dsg;
	int err = -ENOMEM;

	aead = x->data;
	ivlen = crypto_aead_ivsize(aead);
	assoclen = sizeof(struct ip_eesp_hdr) + sizeof(struct ip_eesp_peer_hdr) - ivlen;

//	alen = crypto_aead_authsize(aead);
	alen = crypto_aead_authsize(aead);

	tmp = eesp_alloc_tmp(aead, eesp->nfrags + 2);
	if (!tmp)
		goto error;

	iv = eesp_tmp_iv(aead, tmp);
	req = eesp_tmp_req(aead, iv);
	sg = eesp_req_sg(aead, req);

	if (eesp->inplace)
		dsg = sg;
	else
		dsg = &sg[eesp->nfrags];

	eesph = eesp->eesph;
	eesp_ph = (struct ip_eesp_peer_hdr *)eesph + sizeof(struct ip_eesp_hdr);

	sg_init_table(sg, eesp->nfrags);
	err = skb_to_sgvec(skb, sg,
		           (unsigned char *)eesph - skb->data,
//		           assoclen + ivlen + eesp->clen);
		           assoclen + ivlen + eesp->clen + alen);
	if (unlikely(err < 0)) {
		printk("exit1\n");
		goto error_free;
	}

	if (!eesp->inplace) {
		int allocsize;
		struct page_frag *pfrag = &x->xfrag;

		allocsize = ALIGN(skb->data_len, L1_CACHE_BYTES);

		spin_lock_bh(&x->lock);
		if (unlikely(!skb_page_frag_refill(allocsize, pfrag, GFP_ATOMIC))) {
			spin_unlock_bh(&x->lock);
			printk("exit2\n");
			goto error_free;
		}

		skb_shinfo(skb)->nr_frags = 1;

		page = pfrag->page;
		get_page(page);
		/* replace page frags in skb with new page */
		__skb_fill_page_desc(skb, 0, page, pfrag->offset, skb->data_len);
		pfrag->offset = pfrag->offset + allocsize;
		spin_unlock_bh(&x->lock);

		sg_init_table(dsg, skb_shinfo(skb)->nr_frags + 1);
		err = skb_to_sgvec(skb, dsg,
			           (unsigned char *)eesph - skb->data,
//			           assoclen + ivlen + eesp->clen);
			           assoclen + ivlen + eesp->clen + alen);
		if (unlikely(err < 0)) {
			printk("exit3\n");
			goto error_free;
		}
	}

	aead_request_set_callback(req, 0, eesp_output_done_esn, skb);
	aead_request_set_crypt(req, sg, dsg, ivlen + eesp->clen, iv);
	aead_request_set_ad(req, assoclen);

	memset(iv, 0, ivlen);
	memcpy(iv + ivlen - min(ivlen, 8), (u8 *)&eesp_ph->iv + 8 - min(ivlen, 8),
	       min(ivlen, 8));

	skb_dump(KERN_WARNING, skb, true);
	EESP_SKB_CB(skb)->tmp = tmp;
	err = crypto_aead_encrypt(req);
	printk("crypto_aead_encrypt err %d\n", err);

	switch (err) {
	case -EINPROGRESS:
		goto error;

	case -ENOSPC:
		err = NET_XMIT_DROP;
		break;

	case 0:
		x->type->output_encap_csum(skb);
	}

	if (sg != dsg)
		eesp_ssg_unref(x, tmp, skb);

	if (!err && x->encap && x->encap->encap_type == TCP_ENCAP_ESPINTCP)
		err = eesp_output_tail_tcp(x, skb);

	printk("eesp_output: eesp_ph->iv 0x%lld\n", be64_to_cpu(eesp_ph->iv)); 
error_free:
	kfree(tmp);
error:
	printk("eesp_output_tail err %d\n", err);
	return err;
}
EXPORT_SYMBOL_GPL(eesp_output_tail);

int eesp_output(struct xfrm_state *x, struct sk_buff *skb)
{
	int alen;
	int blksize;
	struct ip_eesp_pyld_hdr *eesp_pyldh;
	struct ip_eesp_peer_hdr *eesp_ph;
	struct ip_eesp_hdr *eesph;
	struct crypto_aead *aead;
	struct eesp_info eesp;

	eesp.inplace = true;

	eesp.proto = *skb_mac_header(skb);
	*skb_mac_header(skb) = IPPROTO_EESP;

	/* skb is pure payload to encrypt */

	aead = x->data;
	alen = crypto_aead_authsize(aead);

	blksize = ALIGN(crypto_aead_blocksize(aead), 4);
	eesp.clen = ALIGN(skb->len + sizeof(struct ip_eesp_pyld_hdr), blksize);
	eesp.plen = eesp.clen - skb->len - sizeof(struct ip_eesp_pyld_hdr);
	eesp.tailen = eesp.plen + alen;

	eesp.eesph = ip_eesp_hdr(skb);

	eesp.nfrags = eesp_output_head(x, skb, &eesp);
	if (eesp.nfrags < 0)
		return eesp.nfrags;

	eesph = eesp.eesph;
	eesp_ph = (void *)eesph + sizeof(struct ip_eesp_hdr);
//	eesp_ph = (struct ip_eesp_peer_hdr *)eesph + sizeof(struct ip_eesp_hdr);
	eesp_pyldh = (void *)eesp_ph + sizeof(struct ip_eesp_peer_hdr);
//	eesp_pyldh = (struct ip_eesp_pyld_hdr *)eesp_ph + sizeof(struct ip_eesp_peer_hdr);

	/* EESP base header */
	eesph->one = 1;
	eesph->version = 0;
	eesph->optlen = 0;
	eesph->session_id = 0;
	eesph->spi = x->id.spi;

	/* EESP peer header */
	eesp_ph->seq_no = cpu_to_be32(XFRM_SKB_CB(skb)->seq.output.low);
	eesp_ph->seq_hi = cpu_to_be32(XFRM_SKB_CB(skb)->seq.output.hi);

	/* EESP peer header: IV is inserted from the crypto layer */

	printk("eesp_output: eesp->spi 0x%x\n", eesph->spi);
	printk("eesp_output: eesp_ph->seq_no %d\n", be32_to_cpu(eesp_ph->seq_no));
	printk("eesp_output: eesp_ph->seq_hi %d\n", be32_to_cpu(eesp_ph->seq_hi));
	/* EESP payload header */
	eesp_pyldh->zero = 0;
	eesp_pyldh->reserved1 = 0;
	eesp_pyldh->reserved2 = 0;
	eesp_pyldh->nexthdr = eesp.proto;
	eesp_pyldh->padlen = eesp.plen;

//	eesp.seqno = eesp_ph->seq_no;

	skb_push(skb, -skb_network_offset(skb));

	return eesp_output_tail(x, skb, &eesp);
}
EXPORT_SYMBOL_GPL(eesp_output);

static inline int eesp_remove_trailer(struct sk_buff *skb)
{
	struct xfrm_state *x = xfrm_input_state(skb);
	struct crypto_aead *aead = x->data;
	struct ip_eesp_pyld_hdr *eesp_pyldh;
	struct ip_eesp_hdr *eesph;
	int alen, hlen, elen;
	int padlen, trimlen;
	__wsum csumdiff;
	u8 nexthdr;
	int ret;
	u8 reserved1, reserved2, zero;

	struct ip_eesp_peer_hdr *eesp_ph;

	alen = crypto_aead_authsize(aead);
	hlen = sizeof(struct ip_eesp_hdr) + sizeof(struct ip_eesp_peer_hdr);
	elen = skb->len - hlen;

//	skb_reset_transport_header(skb);
	eesph = ip_eesp_hdr(skb);
	
//	eesph = (void *)(skb_network_header(skb) + skb_network_header_len(skb));
	eesp_ph = (void *)eesph + sizeof(struct ip_eesp_hdr);
	eesp_pyldh = (void *)eesph + hlen;

	padlen = eesp_pyldh->padlen;
	nexthdr = eesp_pyldh->nexthdr;
	zero = eesp_pyldh->zero;
	reserved1 = eesp_pyldh->reserved1;
	reserved2 = eesp_pyldh->reserved2;

	printk("eesp_remove_trailer: zero 0x%x, reserved1, 0x%x, reserved2 0x%x\n", zero, reserved1, reserved2);
	printk("eesp_remove_trailer: padlen 0x%x, nexthdr 0x%x\n", padlen, nexthdr);
	printk("eesp_remove_trailer: spi 0x%x\n", eesph->spi);
	printk("eesp_remove_trailer: eesp_ph->seq_no 0x%x\n", be32_to_cpu(eesp_ph->seq_no));
	printk("eesp_remove_trailer: eesp_ph->seq_hi 0x%x\n", be32_to_cpu(eesp_ph->seq_hi));
	printk("eesp_remove_trailer: eesp_ph->iv 0x%llx\n", be64_to_cpu(eesp_ph->iv));
//	printk("eesp_remove_trailer: eesp_ph->iv 0x%lld\n", be64_to_cpu(eesp_ph->iv));



	skb_dump(KERN_WARNING, skb, true);
	ret = -EINVAL;

	if (padlen + alen >= elen) {
		net_dbg_ratelimited("ipsec eesp packet is garbage padlen=%d, elen=%d\n",
				    padlen, elen - alen);
		goto out;
	}

	trimlen = alen + padlen;
	if (skb->ip_summed == CHECKSUM_COMPLETE) {
		csumdiff = skb_checksum(skb, skb->len - trimlen, trimlen, 0);
		skb->csum = csum_block_sub(skb->csum, csumdiff,
					   skb->len - trimlen);
	}
	ret = pskb_trim(skb, skb->len - trimlen);
	if (unlikely(ret))
		return ret;

	ret = nexthdr;

out:
	return ret;
}

int eesp_input_done2(struct sk_buff *skb, int err)
{
	struct xfrm_state *x = xfrm_input_state(skb);
	struct xfrm_offload *xo = xfrm_offload(skb);
	/* IV size! */
	int hlen = sizeof(struct ip_eesp_hdr) + sizeof(struct ip_eesp_peer_hdr) + sizeof(struct ip_eesp_pyld_hdr);
	int hdr_len = skb_network_header_len(skb);
	int nexthdr;

	if (!xo || !(xo->flags & CRYPTO_DONE))
		kfree(EESP_SKB_CB(skb)->tmp);

	if (unlikely(err))
		goto out;

	err = eesp_remove_trailer(skb);
	if (unlikely(err < 0))
		goto out;

	nexthdr = err;

	if (x->encap) {
		err = x->type->input_encap(skb, x);
		if (unlikely(err))
			goto out;

		switch (x->encap->encap_type) {
		case TCP_ENCAP_ESPINTCP:
			hdr_len -= sizeof(struct tcphdr);
			break;
		case UDP_ENCAP_ESPINUDP:
			hdr_len -= sizeof(struct udphdr);
			break;
		}
	}

	skb_pull_rcsum(skb, hlen);
	if (x->props.mode == XFRM_MODE_TUNNEL ||
	    x->props.mode == XFRM_MODE_IPTFS)
		skb_reset_transport_header(skb);
	else
		skb_set_transport_header(skb, -hdr_len);

	/* RFC4303: Drop dummy packets without any error */
	if (nexthdr == IPPROTO_NONE)
		err = -EINVAL;
	else
		err = nexthdr;

out:
	return err;
}
EXPORT_SYMBOL_GPL(eesp_input_done2);

static void eesp_input_done(void *data, int err)
{
	struct sk_buff *skb = data;

	xfrm_input_resume(skb, eesp_input_done2(skb, err));
}

static void eesp_input_done_esn(void *data, int err)
{
	eesp_input_done(data, err);
}

/*
 * Note: detecting truncated vs. non-truncated authentication data is very
 * expensive, so we only support truncated data, which is the recommended
 * and common case.
 */
int eesp_input(struct xfrm_state *x, struct sk_buff *skb)
{
	struct crypto_aead *aead = x->data;
	struct aead_request *req;
	struct sk_buff *trailer;
	int ivlen = crypto_aead_ivsize(aead);
	/* What if IV size is not 8? */
	int elen = skb->len - sizeof(struct ip_eesp_hdr) - sizeof(struct ip_eesp_peer_hdr);
	int nfrags;
	int assoclen;
	void *tmp;
	u8 *iv;
	struct scatterlist *sg;
	int err = -EINVAL;

	if (!pskb_may_pull(skb, sizeof(struct ip_eesp_hdr) + sizeof(struct ip_eesp_peer_hdr) + sizeof(struct ip_eesp_pyld_hdr)))
		goto out;

	if (elen <= 0)
		goto out;

	assoclen = sizeof(struct ip_eesp_hdr) + sizeof(struct ip_eesp_peer_hdr) - ivlen;

	if (!skb_cloned(skb)) {
		if (!skb_is_nonlinear(skb)) {
			nfrags = 1;

			goto skip_cow;
		} else if (!skb_has_frag_list(skb)) {
			nfrags = skb_shinfo(skb)->nr_frags;
			nfrags++;

			goto skip_cow;
		}
	}

	err = skb_cow_data(skb, 0, &trailer);
	if (err < 0)
		goto out;

	nfrags = err;

skip_cow:
	err = -ENOMEM;
	tmp = eesp_alloc_tmp(aead, nfrags);
	if (!tmp)
		goto out;

	EESP_SKB_CB(skb)->tmp = tmp;
	iv = eesp_tmp_iv(aead, tmp);
	req = eesp_tmp_req(aead, iv);
	sg = eesp_req_sg(aead, req);

	sg_init_table(sg, nfrags);
	err = skb_to_sgvec(skb, sg, 0, skb->len);
	if (unlikely(err < 0)) {
		kfree(tmp);
		goto out;
	}

	skb->ip_summed = CHECKSUM_NONE;

	aead_request_set_callback(req, 0, eesp_input_done_esn, skb);
	aead_request_set_crypt(req, sg, sg, elen + ivlen, iv);
	aead_request_set_ad(req, assoclen);

	err = crypto_aead_decrypt(req);
	if (err == -EINPROGRESS)
		goto out;

	err = eesp_input_done2(skb, err);

out:
	return err;
}
EXPORT_SYMBOL_GPL(eesp_input);

void eesp_destroy(struct xfrm_state *x)
{
	struct crypto_aead *aead = x->data;

	if (!aead)
		return;

	crypto_free_aead(aead);
}
EXPORT_SYMBOL_GPL(eesp_destroy);

int eesp_init_aead(struct xfrm_state *x, struct netlink_ext_ack *extack)
{
	char aead_name[CRYPTO_MAX_ALG_NAME];
	struct crypto_aead *aead;
	int err;

	if (snprintf(aead_name, CRYPTO_MAX_ALG_NAME, "%s(%s)",
		     x->geniv, x->aead->alg_name) >= CRYPTO_MAX_ALG_NAME) {
		NL_SET_ERR_MSG(extack, "Algorithm name is too long");
		return -ENAMETOOLONG;
	}

	aead = crypto_alloc_aead(aead_name, 0, 0);
	err = PTR_ERR(aead);
	if (IS_ERR(aead))
		goto error;

	x->data = aead;

	err = crypto_aead_setkey(aead, x->aead->alg_key,
				 (x->aead->alg_key_len + 7) / 8);
	if (err)
		goto error;

	err = crypto_aead_setauthsize(aead, x->aead->alg_icv_len / 8);
	if (err)
		goto error;

	return 0;

error:
	NL_SET_ERR_MSG(extack, "Kernel was unable to initialize cryptographic operations");
	return err;
}
EXPORT_SYMBOL_GPL(eesp_init_aead);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Generic EESP");

