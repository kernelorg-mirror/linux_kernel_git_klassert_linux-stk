/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NET_ESP_H
#define _NET_ESP_H

#include <linux/skbuff.h>

struct ip_eesp_hdr;
struct xfrm_state;

static inline struct ip_eesp_hdr *ip_eesp_hdr(const struct sk_buff *skb)
{
	return (struct ip_eesp_hdr *)skb_transport_header(skb);
}

struct eesp_info {
	struct	ip_eesp_hdr *eesph;
	__be64	seqno;
	int	tfclen;
	int	tailen;
	int	plen;
	int	clen;
	int 	len;
	int 	nfrags;
	__u8	proto;
	bool	inplace;
};

int eesp_output_head(struct xfrm_state *x, struct sk_buff *skb, struct eesp_info *eesp);
int eesp_output_tail(struct xfrm_state *x, struct sk_buff *skb, struct eesp_info *eesp);
int eesp_input_done2(struct sk_buff *skb, int err);
int eesp6_output_head(struct xfrm_state *x, struct sk_buff *skb, struct eesp_info *eesp);
int eesp6_output_tail(struct xfrm_state *x, struct sk_buff *skb, struct eesp_info *eesp);
int eesp6_input_done2(struct sk_buff *skb, int err);
int eesp_init_aead(struct xfrm_state *x, struct netlink_ext_ack *extack);
void eesp_destroy(struct xfrm_state *x);
int eesp_input(struct xfrm_state *x, struct sk_buff *skb);
int eesp_output(struct xfrm_state *x, struct sk_buff *skb);

#endif
