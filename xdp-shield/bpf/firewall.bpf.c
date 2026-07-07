#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "common.h"
#include "maps.h"
#include "parser.h"
#include "engine.h"
#include "rules.h"

/*
 * Keep the BPF side as one translation unit for a simple clang build:
 *
 *   clang -target bpf -c bpf/firewall.bpf.c -o bpf/firewall.bpf.o
 *
 * The module boundaries remain in separate files, but the entrypoint can be
 * compiled without relying on BPF static linking.
 */
#include "parser.c"
#include "engine.c"
#include "rules.c"

#define STATS_INC(stats, field)					\
	do {							\
		if (stats)					\
			__sync_fetch_and_add(&(stats)->field, 1);	\
	} while (0)

struct rewrite_headers {
	struct ethhdr *eth;
	struct iphdr *iph;
	struct tcphdr *tcp;
	struct udphdr *udp;
	__u16 src_port;
	__u16 dst_port;
};

struct rewrite_vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

static __always_inline __u16 csum_fold(__u64 sum)
{
#pragma clang loop unroll(full)
	for (int i = 0; i < 4; i++)
		sum = (sum & 0xffff) + (sum >> 16);
	return ~sum;
}

static __always_inline __sum16 csum_replace16(__sum16 checksum,
					      __be16 from, __be16 to)
{
	__u64 sum = ~bpf_ntohs(checksum) & 0xffff;

	sum += ~bpf_ntohs(from) & 0xffff;
	sum += bpf_ntohs(to);
	return bpf_htons(csum_fold(sum));
}

static __always_inline __sum16 csum_replace32(__sum16 checksum,
					      __be32 from, __be32 to)
{
	__u64 sum = ~bpf_ntohs(checksum) & 0xffff;
	__u32 old = bpf_ntohl(from);
	__u32 new = bpf_ntohl(to);

	sum += ~(old >> 16) & 0xffff;
	sum += ~old & 0xffff;
	sum += new >> 16;
	sum += new & 0xffff;
	return bpf_htons(csum_fold(sum));
}

static __always_inline void copy_mac(__u8 dst[ETH_ALEN], const __u8 src[ETH_ALEN])
{
#pragma clang loop unroll(full)
	for (int i = 0; i < ETH_ALEN; i++)
		dst[i] = src[i];
}

static __noinline int parse_rewrite_headers(struct xdp_md *ctx,
					    struct rewrite_headers *headers)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	__be16 eth_type;
	void *pos;

	if ((void *)(eth + 1) > data_end)
		return -1;

	eth_type = eth->h_proto;
	pos = eth + 1;
#pragma clang loop unroll(full)
	for (int i = 0; i < XDP_SHIELD_MAX_VLAN_DEPTH; i++) {
		struct rewrite_vlan_hdr *vlan;
		__u16 proto = bpf_ntohs(eth_type);

		if (proto != ETH_P_8021Q && proto != ETH_P_8021AD)
			break;
		vlan = pos;
		if ((void *)(vlan + 1) > data_end)
			return -1;
		eth_type = vlan->h_vlan_encapsulated_proto;
		pos = vlan + 1;
	}

	if (bpf_ntohs(eth_type) != ETH_P_IP)
		return -1;

	headers->eth = eth;
	headers->iph = pos;
	if ((void *)(headers->iph + 1) > data_end)
		return -1;
	if (headers->iph->version != 4)
		return -1;
	if (headers->iph->ihl < 5)
		return -1;
	if ((void *)headers->iph + headers->iph->ihl * 4 > data_end)
		return -1;
	if (headers->iph->frag_off & bpf_htons(0x3fff))
		return -1;

	pos = (void *)headers->iph + headers->iph->ihl * 4;
	headers->tcp = NULL;
	headers->udp = NULL;
	headers->src_port = 0;
	headers->dst_port = 0;
	if (headers->iph->protocol == XDP_SHIELD_PROTO_TCP) {
		headers->tcp = pos;
		if ((void *)(headers->tcp + 1) > data_end)
			return -1;
		headers->src_port = bpf_ntohs(headers->tcp->source);
		headers->dst_port = bpf_ntohs(headers->tcp->dest);
		return 0;
	}
	if (headers->iph->protocol == XDP_SHIELD_PROTO_UDP) {
		headers->udp = pos;
		if ((void *)(headers->udp + 1) > data_end)
			return -1;
		headers->src_port = bpf_ntohs(headers->udp->source);
		headers->dst_port = bpf_ntohs(headers->udp->dest);
		return 0;
	}

	return -1;
}

static __always_inline void update_l4_daddr(struct rewrite_headers *headers,
					    __be32 from, __be32 to)
{
	if (headers->tcp)
		headers->tcp->check = csum_replace32(headers->tcp->check,
						     from, to);
	else if (headers->udp && headers->udp->check)
		headers->udp->check = csum_replace32(headers->udp->check,
						     from, to);
}

static __always_inline void update_l4_saddr(struct rewrite_headers *headers,
					    __be32 from, __be32 to)
{
	update_l4_daddr(headers, from, to);
}

static __always_inline void update_l4_dport(struct rewrite_headers *headers,
					    __be16 from, __be16 to)
{
	if (headers->tcp)
		headers->tcp->check = csum_replace16(headers->tcp->check,
						     from, to);
	else if (headers->udp && headers->udp->check)
		headers->udp->check = csum_replace16(headers->udp->check,
						     from, to);
}

static __always_inline void update_l4_sport(struct rewrite_headers *headers,
					    __be16 from, __be16 to)
{
	update_l4_dport(headers, from, to);
}

static __always_inline int canary_port_hit(const struct xdp_shield_packet_info *pkt)
{
	struct xdp_shield_port_key key = {
		.port = pkt->dst_port,
	};
	__u8 *enabled;

	if (!pkt->dst_port)
		return 0;
	if (pkt->protocol != XDP_SHIELD_PROTO_TCP &&
	    pkt->protocol != XDP_SHIELD_PROTO_UDP)
		return 0;

	enabled = bpf_map_lookup_elem(&xdp_shield_canary_port_map, &key);
	return enabled && *enabled;
}

static __always_inline int source_is_trapped(const struct xdp_shield_packet_info *pkt,
					     __u64 now_ns)
{
	struct xdp_shield_honeypot_source *source;
	struct xdp_shield_ip_addr ip = {};

	if (pkt->ip_version != 4 || !pkt->src_ipv4)
		return 0;

	ip.ipv4 = pkt->src_ipv4;
	source = bpf_map_lookup_elem(&xdp_shield_honeypot_source_map, &ip);
	if (!source)
		return 0;
	if (source->expiration_ns && source->expiration_ns <= now_ns) {
		bpf_map_delete_elem(&xdp_shield_honeypot_source_map, &ip);
		return 0;
	}

	source->last_seen_ns = now_ns;
	source->hits++;
	return 1;
}

static __noinline void trap_source(const struct xdp_shield_packet_info *pkt,
				   __u64 now_ns, __u64 duration_ns,
				   __u32 reason)
{
	struct xdp_shield_ip_addr ip = {};
	struct xdp_shield_honeypot_source *existing;
	struct xdp_shield_honeypot_scratch *scratch;
	__u32 scratch_key = 0;

	if (pkt->ip_version != 4 || !pkt->src_ipv4)
		return;

	ip.ipv4 = pkt->src_ipv4;
	existing = bpf_map_lookup_elem(&xdp_shield_honeypot_source_map, &ip);
	if (existing) {
		existing->last_seen_ns = now_ns;
		existing->expiration_ns = now_ns + duration_ns;
		existing->reason = reason;
		existing->hits++;
		return;
	}

	scratch = bpf_map_lookup_elem(&xdp_shield_honeypot_scratch_map,
				      &scratch_key);
	if (!scratch)
		return;
	__builtin_memset(&scratch->source, 0, sizeof(scratch->source));
	scratch->source.first_seen_ns = now_ns;
	scratch->source.last_seen_ns = now_ns;
	scratch->source.expiration_ns = now_ns + duration_ns;
	scratch->source.reason = reason;
	scratch->source.hits = 1;
	bpf_map_update_elem(&xdp_shield_honeypot_source_map, &ip,
			    &scratch->source,
			    BPF_ANY);
}

static __noinline int redirect_to_honeypot(struct xdp_md *ctx,
					   const struct xdp_shield_packet_info *pkt,
					   struct xdp_shield_honeypot_config *config,
					   __u64 now_ns)
{
	struct xdp_shield_honeypot_scratch *scratch;
	struct rewrite_headers headers = {};
	__be32 old_daddr;
	__be16 old_dport;
	__be16 new_dport;
	__u32 scratch_key = 0;

	if (!config || !config->enabled || !config->redirect_tcp)
		return XDP_PASS;
	if (pkt->ip_version != 4 || pkt->protocol != XDP_SHIELD_PROTO_TCP)
		return XDP_PASS;
	if (parse_rewrite_headers(ctx, &headers))
		return XDP_PASS;
	if (!headers.tcp)
		return XDP_PASS;
	scratch = bpf_map_lookup_elem(&xdp_shield_honeypot_scratch_map,
				      &scratch_key);
	if (!scratch)
		return XDP_PASS;
	__builtin_memset(&scratch->flow_key, 0, sizeof(scratch->flow_key));
	__builtin_memset(&scratch->flow_value, 0, sizeof(scratch->flow_value));

	old_daddr = headers.iph->daddr;
	old_dport = headers.tcp->dest;
	new_dport = bpf_htons(config->honeypot_port);

	scratch->flow_key.client_ipv4 = headers.iph->saddr;
	scratch->flow_key.client_port = headers.tcp->source;
	scratch->flow_key.honeypot_port = config->honeypot_port;
	scratch->flow_key.protocol = headers.iph->protocol;

	scratch->flow_value.original_dst_ipv4 = old_daddr;
	scratch->flow_value.original_dst_port = bpf_ntohs(old_dport);
	copy_mac(scratch->flow_value.external_mac.bytes,
		 config->external_mac.bytes);
	copy_mac(scratch->flow_value.gateway_mac.bytes, headers.eth->h_source);
	scratch->flow_value.created_ns = now_ns;
	scratch->flow_value.last_seen_ns = now_ns;
	bpf_map_update_elem(&xdp_shield_honeypot_flow_map,
			    &scratch->flow_key, &scratch->flow_value,
			    BPF_ANY);

	update_l4_daddr(&headers, old_daddr, config->honeypot_ipv4);
	if (old_dport != new_dport)
		update_l4_dport(&headers, old_dport, new_dport);
	headers.iph->check = csum_replace32(headers.iph->check, old_daddr,
					    config->honeypot_ipv4);
	headers.iph->daddr = config->honeypot_ipv4;
	headers.tcp->dest = new_dport;

	copy_mac(headers.eth->h_dest, config->honeypot_mac.bytes);
	copy_mac(headers.eth->h_source, config->external_mac.bytes);
	return bpf_redirect_map(&xdp_shield_honeypot_devmap,
				XDP_SHIELD_DEVMAP_HONEYPOT_KEY, 0);
}

static __noinline int redirect_from_honeypot(struct xdp_md *ctx,
					     struct xdp_shield_honeypot_config *config)
{
	struct xdp_shield_honeypot_flow_value *value;
	struct xdp_shield_honeypot_scratch *scratch;
	struct rewrite_headers headers = {};
	__be32 old_saddr;
	__be16 old_sport;
	__be16 new_sport;
	__u32 scratch_key = 0;

	if (!config || !config->enabled)
		return XDP_PASS;
	if (parse_rewrite_headers(ctx, &headers))
		return XDP_PASS;
	if (headers.iph->saddr != config->honeypot_ipv4 ||
	    headers.iph->protocol != XDP_SHIELD_PROTO_TCP || !headers.tcp)
		return XDP_PASS;

	scratch = bpf_map_lookup_elem(&xdp_shield_honeypot_scratch_map,
				      &scratch_key);
	if (!scratch)
		return XDP_PASS;
	__builtin_memset(&scratch->flow_key, 0, sizeof(scratch->flow_key));
	scratch->flow_key.client_ipv4 = headers.iph->daddr;
	scratch->flow_key.client_port = headers.tcp->dest;
	scratch->flow_key.honeypot_port = bpf_ntohs(headers.tcp->source);
	scratch->flow_key.protocol = headers.iph->protocol;
	value = bpf_map_lookup_elem(&xdp_shield_honeypot_flow_map,
				    &scratch->flow_key);
	if (!value)
		return XDP_PASS;

	old_saddr = headers.iph->saddr;
	old_sport = headers.tcp->source;
	new_sport = bpf_htons(value->original_dst_port);

	update_l4_saddr(&headers, old_saddr, value->original_dst_ipv4);
	if (old_sport != new_sport)
		update_l4_sport(&headers, old_sport, new_sport);
	headers.iph->check = csum_replace32(headers.iph->check, old_saddr,
					    value->original_dst_ipv4);
	headers.iph->saddr = value->original_dst_ipv4;
	headers.tcp->source = new_sport;

	copy_mac(headers.eth->h_dest, value->gateway_mac.bytes);
	copy_mac(headers.eth->h_source, value->external_mac.bytes);
	value->last_seen_ns = bpf_ktime_get_ns();
	return bpf_redirect_map(&xdp_shield_honeypot_devmap,
				XDP_SHIELD_DEVMAP_EXTERNAL_KEY, 0);
}

static __always_inline void emit_event(const struct xdp_shield_packet_info *pkt,
				       __u8 event_type, __u32 reason)
{
	struct xdp_shield_event event = {};

	event.timestamp_ns = bpf_ktime_get_ns();
	event.src_ipv4 = pkt->src_ipv4;
	event.dst_ipv4 = pkt->dst_ipv4;
	event.src_port = pkt->src_port;
	event.dst_port = pkt->dst_port;
	event.protocol = pkt->protocol;
	event.event_type = event_type;
	event.reason = reason;
	bpf_ringbuf_output(&xdp_shield_events, &event, sizeof(event), 0);
}

static __always_inline int
firewall_lpm_key_from_packet(const struct xdp_shield_packet_info *pkt,
			     struct xdp_shield_lpm_key *key)
{
	__builtin_memset(key, 0, sizeof(*key));

	if (pkt->ip_version == 4) {
		__u8 *raw = (__u8 *)&pkt->src_ipv4;

		key->prefix_len = XDP_SHIELD_IPV4_LPM_PREFIX_BITS + 8;
		key->is_ipv6 = 0;
		key->addr[0] = raw[0];
		key->addr[1] = raw[1];
		key->addr[2] = raw[2];
		key->addr[3] = raw[3];
		return 0;
	}

	if (pkt->ip_version == 6) {
		int i;

		key->prefix_len = XDP_SHIELD_IPV6_LPM_PREFIX_BITS + 8;
		key->is_ipv6 = 1;
#pragma clang loop unroll(full)
		for (i = 0; i < XDP_SHIELD_IPV6_ADDR_LEN; i++)
			key->addr[i] = pkt->src_ipv6[i];
		return 0;
	}

	return -1;
}

static __always_inline int packet_is_blacklisted(const struct xdp_shield_packet_info *pkt)
{
	struct xdp_shield_threat_feed_entry *threat;
	struct xdp_shield_lpm_key key;

	if (firewall_lpm_key_from_packet(pkt, &key))
		return 0;

	threat = bpf_map_lookup_elem(&xdp_shield_threat_feed_map, &key);
	if (!threat)
		return 0;

	switch (threat->category) {
	case XDP_SHIELD_THREAT_MALWARE:
	case XDP_SHIELD_THREAT_BOTNET:
	case XDP_SHIELD_THREAT_TOR_EXIT:
	case XDP_SHIELD_THREAT_UNKNOWN:
		return 1;
	default:
		return 0;
	}
}

SEC("xdp")
int xdp_shield_firewall(struct xdp_md *ctx)
{
	struct xdp_shield_engine_result detection = {};
	struct xdp_shield_honeypot_config *honeypot_config;
	struct xdp_shield_packet_info pkt = {};
	struct xdp_shield_stats_entry *stats;
	enum xdp_shield_rule_result rule_result;
	__u32 config_key = XDP_SHIELD_CONFIG_KEY;
	__u32 stats_key = 0;
	__u64 now_ns;
	int parse_status;

	parse_status = parse_packet(ctx, &pkt);
	if (parse_status < 0)
		return XDP_PASS;

	honeypot_config = bpf_map_lookup_elem(&xdp_shield_honeypot_config_map,
					      &config_key);
	if (honeypot_config && honeypot_config->enabled &&
	    ctx->ingress_ifindex == honeypot_config->honeypot_ifindex)
		return redirect_from_honeypot(ctx, honeypot_config);

	stats = bpf_map_lookup_elem(&xdp_shield_stats_map, &stats_key);
	STATS_INC(stats, packets_processed);
	now_ns = bpf_ktime_get_ns();

	if (packet_is_blacklisted(&pkt)) {
		STATS_INC(stats, threat_feed_hits);
		STATS_INC(stats, packets_dropped);
		emit_event(&pkt, XDP_SHIELD_EVENT_THREAT_HIT,
			   XDP_SHIELD_BAN_REASON_THREAT_FEED);
		return XDP_DROP;
	}

	if (honeypot_config && honeypot_config->enabled &&
	    ctx->ingress_ifindex == honeypot_config->external_ifindex) {
		int trapped = source_is_trapped(&pkt, now_ns);

		if (canary_port_hit(&pkt)) {
			STATS_INC(stats, canary_hits);
			trap_source(&pkt, now_ns,
				    honeypot_config->redirect_duration_ns,
				    XDP_SHIELD_BAN_REASON_CANARY_PORT);
			emit_event(&pkt, XDP_SHIELD_EVENT_CANARY_HIT,
				   XDP_SHIELD_BAN_REASON_CANARY_PORT);
			trapped = 1;
		}
		if (trapped) {
			int result = redirect_to_honeypot(ctx, &pkt,
							 honeypot_config, now_ns);

			if (result == XDP_REDIRECT) {
				STATS_INC(stats, honeypot_redirects);
				emit_event(&pkt, XDP_SHIELD_EVENT_HONEYPOT_REDIRECT,
					   XDP_SHIELD_BAN_REASON_HONEYPOT);
				return result;
			}
		}
	}

	run_detection_engine(&pkt, &detection);
	if (detection.result == XDP_SHIELD_DETECTION_MALICIOUS) {
		STATS_INC(stats, temporary_ban_hits);
		STATS_INC(stats, packets_dropped);
		emit_event(&pkt, XDP_SHIELD_EVENT_TEMP_BAN, detection.reason);
		return XDP_DROP;
	}

	rule_result = check_rules(&pkt);
	if (rule_result == XDP_SHIELD_RULE_RESULT_DROP) {
		STATS_INC(stats, rule_hits);
		STATS_INC(stats, packets_dropped);
		emit_event(&pkt, XDP_SHIELD_EVENT_RULE_HIT,
			   XDP_SHIELD_BAN_REASON_MANUAL);
		return XDP_DROP;
	}

	STATS_INC(stats, packets_accepted);
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
