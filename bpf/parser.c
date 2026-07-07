#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "parser.h"

#define IPV4_FRAG_OFFSET_MASK 0x1fff
#define IPV4_MORE_FRAGMENTS   0x2000

struct arp_hdr {
	__be16 ar_hrd;
	__be16 ar_pro;
	__u8 ar_hln;
	__u8 ar_pln;
	__be16 ar_op;
};

struct icmp_hdr {
	__u8 type;
	__u8 code;
	__sum16 checksum;
};

struct icmp6_hdr {
	__u8 type;
	__u8 code;
	__sum16 checksum;
};

struct vlan_hdr_local {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

struct ipv6_frag_hdr {
	__u8 nexthdr;
	__u8 reserved;
	__be16 frag_off;
	__be32 identification;
};

struct parse_cursor {
	void *pos;
	void *data_end;
};

static __always_inline int cursor_pull(struct parse_cursor *cursor,
				       __u64 len, void **hdr)
{
	void *pos = cursor->pos;
	void *next = pos + len;

	if (next > cursor->data_end)
		return XDP_SHIELD_PARSE_MALFORMED;

	*hdr = pos;
	cursor->pos = next;
	return XDP_SHIELD_PARSE_OK;
}

static __always_inline void copy_ipv6_addr(__u8 dst[XDP_SHIELD_IPV6_ADDR_LEN],
					   const struct in6_addr *src)
{
	__u8 *raw = (__u8 *)src;
	int i;

#pragma clang loop unroll(full)
	for (i = 0; i < XDP_SHIELD_IPV6_ADDR_LEN; i++)
		dst[i] = raw[i];
}

static __always_inline int is_vlan_eth_type(__be16 eth_type)
{
	__u16 proto = bpf_ntohs(eth_type);

	return proto == ETH_P_8021Q || proto == ETH_P_8021AD;
}

static __always_inline int parse_tcp(struct parse_cursor *cursor,
				     struct xdp_shield_packet_info *pkt)
{
	struct tcphdr *tcp;
	__u8 data_offset;
	int ret;

	ret = cursor_pull(cursor, sizeof(*tcp), (void **)&tcp);
	if (ret)
		return ret;

	data_offset = tcp->doff * 4;
	if (data_offset < sizeof(*tcp))
		return XDP_SHIELD_PARSE_MALFORMED;
	if ((void *)tcp + data_offset > cursor->data_end)
		return XDP_SHIELD_PARSE_MALFORMED;

	pkt->src_port = bpf_ntohs(tcp->source);
	pkt->dst_port = bpf_ntohs(tcp->dest);
	pkt->tcp_flags = ((__u8)tcp->fin * XDP_SHIELD_TCP_FIN) |
			 ((__u8)tcp->syn * XDP_SHIELD_TCP_SYN) |
			 ((__u8)tcp->rst * XDP_SHIELD_TCP_RST) |
			 ((__u8)tcp->psh * XDP_SHIELD_TCP_PSH) |
			 ((__u8)tcp->ack * XDP_SHIELD_TCP_ACK) |
			 ((__u8)tcp->urg * XDP_SHIELD_TCP_URG) |
			 ((__u8)tcp->ece * XDP_SHIELD_TCP_ECE) |
			 ((__u8)tcp->cwr * XDP_SHIELD_TCP_CWR);
	return XDP_SHIELD_PARSE_OK;
}

static __always_inline int parse_udp(struct parse_cursor *cursor,
				     struct xdp_shield_packet_info *pkt)
{
	struct udphdr *udp;
	int ret;

	ret = cursor_pull(cursor, sizeof(*udp), (void **)&udp);
	if (ret)
		return ret;

	pkt->src_port = bpf_ntohs(udp->source);
	pkt->dst_port = bpf_ntohs(udp->dest);
	return XDP_SHIELD_PARSE_OK;
}

static __always_inline int parse_icmp(struct parse_cursor *cursor,
				      struct xdp_shield_packet_info *pkt)
{
	struct icmp_hdr *icmp;
	int ret;

	ret = cursor_pull(cursor, sizeof(*icmp), (void **)&icmp);
	if (ret)
		return ret;

	pkt->icmp_type = icmp->type;
	return XDP_SHIELD_PARSE_OK;
}

static __always_inline int parse_icmpv6(struct parse_cursor *cursor,
					struct xdp_shield_packet_info *pkt)
{
	struct icmp6_hdr *icmp6;
	int ret;

	ret = cursor_pull(cursor, sizeof(*icmp6), (void **)&icmp6);
	if (ret)
		return ret;

	pkt->icmp_type = icmp6->type;
	return XDP_SHIELD_PARSE_OK;
}

static __always_inline int parse_arp(struct parse_cursor *cursor,
				     struct xdp_shield_packet_info *pkt)
{
	struct arp_hdr *arp;
	int ret;

	ret = cursor_pull(cursor, sizeof(*arp), (void **)&arp);
	if (ret)
		return ret;

	pkt->arp_operation = bpf_ntohs(arp->ar_op);
	return XDP_SHIELD_PARSE_OK;
}

static __always_inline int parse_l4(struct parse_cursor *cursor,
				    struct xdp_shield_packet_info *pkt)
{
	switch (pkt->protocol) {
	case IPPROTO_TCP:
		return parse_tcp(cursor, pkt);
	case IPPROTO_UDP:
		return parse_udp(cursor, pkt);
	case IPPROTO_ICMP:
		return parse_icmp(cursor, pkt);
	case IPPROTO_ICMPV6:
		return parse_icmpv6(cursor, pkt);
	default:
		return XDP_SHIELD_PARSE_UNSUPPORTED_L4;
	}
}

static __always_inline int parse_ipv4(struct parse_cursor *cursor,
				      struct xdp_shield_packet_info *pkt)
{
	struct iphdr *iph;
	__u16 frag_off;
	__u32 ihl;
	int ret;

	ret = cursor_pull(cursor, sizeof(*iph), (void **)&iph);
	if (ret)
		return ret;

	if (iph->version != 4)
		return XDP_SHIELD_PARSE_MALFORMED;

	ihl = iph->ihl * 4;
	if (ihl < sizeof(*iph))
		return XDP_SHIELD_PARSE_MALFORMED;
	if ((void *)iph + ihl > cursor->data_end)
		return XDP_SHIELD_PARSE_MALFORMED;

	cursor->pos = (void *)iph + ihl;

	pkt->ip_version = 4;
	pkt->protocol = iph->protocol;
	pkt->src_ipv4 = iph->saddr;
	pkt->dst_ipv4 = iph->daddr;

	frag_off = bpf_ntohs(iph->frag_off);
	pkt->fragment_offset = frag_off & IPV4_FRAG_OFFSET_MASK;
	pkt->is_fragment = !!(frag_off & (IPV4_FRAG_OFFSET_MASK |
					  IPV4_MORE_FRAGMENTS));
	pkt->is_first_fragment = pkt->is_fragment &&
				 pkt->fragment_offset == 0;

	if (pkt->is_fragment && !pkt->is_first_fragment)
		return XDP_SHIELD_PARSE_OK;

	return parse_l4(cursor, pkt);
}

static __always_inline int parse_ipv6_fragment(struct parse_cursor *cursor,
					       struct xdp_shield_packet_info *pkt,
					       __u8 *next_header)
{
	struct ipv6_frag_hdr *frag;
	__u16 frag_off;
	int ret;

	ret = cursor_pull(cursor, sizeof(*frag), (void **)&frag);
	if (ret)
		return ret;

	*next_header = frag->nexthdr;
	frag_off = bpf_ntohs(frag->frag_off);
	pkt->fragment_offset = (frag_off & 0xfff8) >> 3;
	pkt->is_fragment = 1;
	pkt->is_first_fragment = pkt->fragment_offset == 0;
	return XDP_SHIELD_PARSE_OK;
}

static __always_inline int parse_ipv6_ext_headers(struct parse_cursor *cursor,
						  struct xdp_shield_packet_info *pkt,
						  __u8 *next_header)
{
	int i;

#pragma clang loop unroll(full)
	for (i = 0; i < XDP_SHIELD_MAX_IPV6_EXT_HEADERS; i++) {
		struct ipv6_opt_hdr *opt;
		__u32 hdr_len;
		int ret;

		switch (*next_header) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_DSTOPTS:
			ret = cursor_pull(cursor, sizeof(*opt), (void **)&opt);
			if (ret)
				return ret;
			hdr_len = ((__u32)opt->hdrlen + 1) * 8;
			if (hdr_len < sizeof(*opt))
				return XDP_SHIELD_PARSE_MALFORMED;
			if ((void *)opt + hdr_len > cursor->data_end)
				return XDP_SHIELD_PARSE_MALFORMED;
			cursor->pos = (void *)opt + hdr_len;
			*next_header = opt->nexthdr;
			break;
		case IPPROTO_AH:
			ret = cursor_pull(cursor, sizeof(*opt), (void **)&opt);
			if (ret)
				return ret;
			hdr_len = ((__u32)opt->hdrlen + 2) * 4;
			if (hdr_len < sizeof(*opt))
				return XDP_SHIELD_PARSE_MALFORMED;
			if ((void *)opt + hdr_len > cursor->data_end)
				return XDP_SHIELD_PARSE_MALFORMED;
			cursor->pos = (void *)opt + hdr_len;
			*next_header = opt->nexthdr;
			break;
		case IPPROTO_FRAGMENT:
			ret = parse_ipv6_fragment(cursor, pkt, next_header);
			if (ret)
				return ret;
			if (!pkt->is_first_fragment)
				return XDP_SHIELD_PARSE_OK;
			break;
		default:
			return XDP_SHIELD_PARSE_OK;
		}
	}

	return XDP_SHIELD_PARSE_UNSUPPORTED_L4;
}

static __always_inline int parse_ipv6(struct parse_cursor *cursor,
				      struct xdp_shield_packet_info *pkt)
{
	struct ipv6hdr *ip6h;
	__u8 next_header;
	int ret;

	ret = cursor_pull(cursor, sizeof(*ip6h), (void **)&ip6h);
	if (ret)
		return ret;

	if ((ip6h->version) != 6)
		return XDP_SHIELD_PARSE_MALFORMED;

	pkt->ip_version = 6;
	next_header = ip6h->nexthdr;
	copy_ipv6_addr(pkt->src_ipv6, &ip6h->saddr);
	copy_ipv6_addr(pkt->dst_ipv6, &ip6h->daddr);

	ret = parse_ipv6_ext_headers(cursor, pkt, &next_header);
	if (ret)
		return ret;

	pkt->protocol = next_header;
	if (pkt->is_fragment && !pkt->is_first_fragment)
		return XDP_SHIELD_PARSE_OK;

	return parse_l4(cursor, pkt);
}

static __always_inline int parse_vlan(struct parse_cursor *cursor,
				      struct xdp_shield_packet_info *pkt,
				      __be16 *eth_type)
{
	struct vlan_hdr_local *vlan;
	int i;

#pragma clang loop unroll(full)
	for (i = 0; i < XDP_SHIELD_MAX_VLAN_DEPTH; i++) {
		int ret;

		if (!is_vlan_eth_type(*eth_type))
			return XDP_SHIELD_PARSE_OK;

		ret = cursor_pull(cursor, sizeof(*vlan), (void **)&vlan);
		if (ret)
			return ret;

		pkt->vlan_tci[pkt->vlan_depth] = bpf_ntohs(vlan->h_vlan_TCI);
		pkt->vlan_depth++;
		*eth_type = vlan->h_vlan_encapsulated_proto;
	}

	return XDP_SHIELD_PARSE_OK;
}

static __always_inline int parse_eth(struct parse_cursor *cursor,
				     struct xdp_shield_packet_info *pkt)
{
	struct ethhdr *eth;
	__be16 eth_type;
	int ret;

	ret = cursor_pull(cursor, sizeof(*eth), (void **)&eth);
	if (ret)
		return ret;

	eth_type = eth->h_proto;
	ret = parse_vlan(cursor, pkt, &eth_type);
	if (ret)
		return ret;

	pkt->eth_type = eth_type;
	return XDP_SHIELD_PARSE_OK;
}

static __always_inline int parse_packet(struct xdp_md *ctx,
					struct xdp_shield_packet_info *pkt)
{
	struct parse_cursor cursor = {
		.pos = (void *)(long)ctx->data,
		.data_end = (void *)(long)ctx->data_end,
	};
	int ret;

	__builtin_memset(pkt, 0, sizeof(*pkt));
	pkt->packet_len = (__u32)((char *)cursor.data_end - (char *)cursor.pos);

	ret = parse_eth(&cursor, pkt);
	if (ret)
		return ret;

	switch (bpf_ntohs(pkt->eth_type)) {
	case ETH_P_ARP:
		return parse_arp(&cursor, pkt);
	case ETH_P_IP:
		return parse_ipv4(&cursor, pkt);
	case ETH_P_IPV6:
		return parse_ipv6(&cursor, pkt);
	default:
		return XDP_SHIELD_PARSE_UNSUPPORTED_L3;
	}
}
