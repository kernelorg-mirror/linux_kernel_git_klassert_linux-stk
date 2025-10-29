// SPDX-License-Identifier: GPL-2.0-only

#include <crypto/aead.h>
#include <net/ip.h>
#include <net/eesp.h>
#include <net/icmp.h>
#include <net/espintcp.h>

#ifdef CONFIG_INET_ESPINTCP
static struct sock *eesp_find_tcp_sk(struct xfrm_state *x)
{
	struct xfrm_encap_tmpl *encap = x->encap;
	struct net *net = xs_net(x);
	__be16 sport, dport;
	struct sock *sk;

	spin_lock_bh(&x->lock);
	sport = encap->encap_sport;
	dport = encap->encap_dport;
	spin_unlock_bh(&x->lock);

	sk = inet_lookup_established(net, x->id.daddr.a4, dport,
				     x->props.saddr.a4, sport, 0);
	if (!sk)
		return ERR_PTR(-ENOENT);

	if (!tcp_is_ulp_esp(sk)) {
		sock_put(sk);
		return ERR_PTR(-EINVAL);
	}

	return sk;
}

#else
static struct sock *eesp_find_tcp_sk(struct xfrm_state *x)
{
	WARN_ON(1);
	return ERR_PTR(-EOPNOTSUPP);
}
#endif

static void eesp4_output_encap_csum(struct sk_buff *skb)
{
}

static int eesp4_input_encap(struct sk_buff *skb, struct xfrm_state *x)
{
	const struct iphdr *iph = ip_hdr(skb);
	int ihl = iph->ihl * 4;
	struct xfrm_encap_tmpl *encap = x->encap;
	struct tcphdr *th = (void *)(skb_network_header(skb) + ihl);
	struct udphdr *uh = (void *)(skb_network_header(skb) + ihl);
	int err = 0;
	__be16 source;

	switch (x->encap->encap_type) {
	case TCP_ENCAP_ESPINTCP:
		source = th->source;
		break;
	case UDP_ENCAP_ESPINUDP:
		source = uh->source;
		break;
	default:
		WARN_ON_ONCE(1);
		err = -EINVAL;
		goto out;
	}

	/*
	 * 1) if the NAT-T peer's IP or port changed then
	 *    advertise the change to the keying daemon.
	 *    This is an inbound SA, so just compare
	 *    SRC ports.
	 */
	if (iph->saddr != x->props.saddr.a4 ||
	    source != encap->encap_sport) {
		xfrm_address_t ipaddr;

		ipaddr.a4 = iph->saddr;
		km_new_mapping(x, &ipaddr, source);

		/* XXX: perhaps add an extra
		 * policy check here, to see
		 * if we should allow or
		 * reject a packet from a
		 * different source
		 * address/port.
		 */
	}

	/*
	 * 2) ignore UDP/TCP checksums in case
	 *    of NAT-T in Transport Mode, or
	 *    perform other post-processing fixes
	 *    as per draft-ietf-ipsec-udp-encaps-06,
	 *    section 3.1.2
	 */
	if (x->props.mode == XFRM_MODE_TRANSPORT)
		skb->ip_summed = CHECKSUM_UNNECESSARY;

out:
	return err;
}

static int eesp4_err(struct sk_buff *skb, u32 info)
{
	struct net *net = dev_net(skb->dev);
	const struct iphdr *iph = (const struct iphdr *)skb->data;
	struct ip_eesp_hdr *eesph = (struct ip_eesp_hdr *)(skb->data+(iph->ihl<<2));
	struct xfrm_state *x;

	switch (icmp_hdr(skb)->type) {
	case ICMP_DEST_UNREACH:
		if (icmp_hdr(skb)->code != ICMP_FRAG_NEEDED)
			return 0;
		break;
	case ICMP_REDIRECT:
		break;
	default:
		return 0;
	}

	x = xfrm_state_lookup(net, skb->mark, (const xfrm_address_t *)&iph->daddr,
			      eesph->spi, IPPROTO_EESP, AF_INET);
	if (!x)
		return 0;

	if (icmp_hdr(skb)->type == ICMP_DEST_UNREACH)
		ipv4_update_pmtu(skb, net, info, 0, IPPROTO_EESP);
	else
		ipv4_redirect(skb, net, 0, IPPROTO_EESP);
	xfrm_state_put(x);

	return 0;
}

static int eesp_init_state(struct xfrm_state *x, struct netlink_ext_ack *extack)
{
	struct crypto_aead *aead;
	u32 align;
	int err;

	x->data = NULL;

	if (x->aead) {
		err = eesp_init_aead(x, extack);
	} else {
		NL_SET_ERR_MSG(extack, "ESP: AEAD must be provided");
		err = -EINVAL;
	}

	if (err)
		goto error;

	aead = x->data;

	x->props.header_len = sizeof(struct ip_eesp_hdr) + sizeof(struct ip_eesp_peer_hdr) + sizeof(struct ip_eesp_pyld_hdr);
	if (x->props.mode == XFRM_MODE_TUNNEL)
		x->props.header_len += sizeof(struct iphdr);
	else if (x->props.mode == XFRM_MODE_BEET && x->sel.family != AF_INET6)
		x->props.header_len += IPV4_BEET_PHMAXLEN;
	if (x->encap) {
		struct xfrm_encap_tmpl *encap = x->encap;

		switch (encap->encap_type) {
		default:
			NL_SET_ERR_MSG(extack, "Unsupported encapsulation type for ESP");
			err = -EINVAL;
			goto error;
		case UDP_ENCAP_ESPINUDP:
			x->props.header_len += sizeof(struct udphdr);
			break;
#ifdef CONFIG_INET_ESPINTCP
		case TCP_ENCAP_ESPINTCP:
			/* only the length field, TCP encap is done by
			 * the socket
			 */
			x->props.header_len += 2;
			break;
#endif
		}
	}

	align = ALIGN(crypto_aead_blocksize(aead), 4);
	x->props.trailer_len = align + 1 + crypto_aead_authsize(aead);

error:
	return err;
}

static int eesp4_rcv_cb(struct sk_buff *skb, int err)
{
	return 0;
}

static const struct xfrm_type eesp_type =
{
	.owner			= THIS_MODULE,
	.proto	     		= IPPROTO_EESP,
	.flags			= XFRM_TYPE_REPLAY_PROT,
	.init_state		= eesp_init_state,
	.destructor		= eesp_destroy,
	.input			= eesp_input,
	.input_encap		= eesp4_input_encap,
	.output			= eesp_output,
	.find_tcp_sk		= eesp_find_tcp_sk,
	.output_encap_csum	= eesp4_output_encap_csum,
};

static struct xfrm4_protocol eesp4_protocol = {
	.handler	=	xfrm4_rcv,
	.input_handler	=	xfrm_input,
	.cb_handler	=	eesp4_rcv_cb,
	.err_handler	=	eesp4_err,
	.priority	=	0,
};

static int __init eesp4_init(void)
{
	if (xfrm_register_type(&eesp_type, AF_INET) < 0) {
		pr_info("%s: can't add xfrm type\n", __func__);
		return -EAGAIN;
	}
	if (xfrm4_protocol_register(&eesp4_protocol, IPPROTO_ESP) < 0) {
		pr_info("%s: can't add protocol\n", __func__);
		xfrm_unregister_type(&eesp_type, AF_INET);
		return -EAGAIN;
	}
	return 0;
}

static void __exit eesp4_fini(void)
{
	if (xfrm4_protocol_deregister(&eesp4_protocol, IPPROTO_EESP) < 0)
		pr_info("%s: can't remove protocol\n", __func__);
	xfrm_unregister_type(&eesp_type, AF_INET);
}

module_init(eesp4_init);
module_exit(eesp4_fini);
MODULE_DESCRIPTION("IPv4 EESP transformation library");
MODULE_LICENSE("GPL");
MODULE_ALIAS_XFRM_TYPE(AF_INET, XFRM_PROTO_EESP);
