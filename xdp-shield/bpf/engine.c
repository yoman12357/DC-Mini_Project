#include <bpf/bpf_helpers.h>

#include "engine.h"
#include "maps.h"

static __always_inline int packet_has_ipv4_source(const struct xdp_shield_packet_info *pkt)
{
	return pkt->ip_version == 4 && pkt->src_ipv4 != 0;
}

static __always_inline void packet_source_ip(const struct xdp_shield_packet_info *pkt,
					     struct xdp_shield_ip_addr *ip)
{
	__builtin_memset(ip, 0, sizeof(*ip));
	ip->is_ipv6 = 0;
	ip->ipv4 = pkt->src_ipv4;
}

static __always_inline int is_tcp_syn_without_ack(const struct xdp_shield_packet_info *pkt)
{
	return pkt->protocol == XDP_SHIELD_PROTO_TCP &&
	       (pkt->tcp_flags & XDP_SHIELD_TCP_SYN) &&
	       !(pkt->tcp_flags & XDP_SHIELD_TCP_ACK);
}

static __always_inline void reset_detection_window(struct xdp_shield_detection_state *state,
						   __u64 now_ns)
{
	state->window_start_ns = now_ns;
	state->syn_count = 0;
	state->udp_count = 0;
	state->icmp_count = 0;
	state->connection_count = 0;
	state->unique_port_count = 0;
}

static __always_inline int window_expired(__u64 start_ns, __u64 now_ns)
{
	struct xdp_shield_runtime_config *config;
	__u32 key = XDP_SHIELD_CONFIG_KEY;
	__u64 window_ns = XDP_SHIELD_DETECTION_WINDOW_NS;

	config = bpf_map_lookup_elem(&xdp_shield_config_map, &key);
	if (config && config->detection_window_ns)
		window_ns = config->detection_window_ns;

	return now_ns - start_ns > window_ns;
}

static __always_inline struct xdp_shield_runtime_config *runtime_config(void)
{
	__u32 key = XDP_SHIELD_CONFIG_KEY;

	return bpf_map_lookup_elem(&xdp_shield_config_map, &key);
}

static __always_inline __u32 config_u32(__u32 value, __u32 fallback)
{
	return value ? value : fallback;
}

static __always_inline __u64 config_u64(__u64 value, __u64 fallback)
{
	return value ? value : fallback;
}

static __always_inline struct xdp_shield_detection_state *
get_detection_state(const struct xdp_shield_packet_info *pkt, __u64 now_ns,
		    struct xdp_shield_ip_addr *src_ip)
{
	struct xdp_shield_detection_state init = {};
	struct xdp_shield_detection_state *state;

	packet_source_ip(pkt, src_ip);
	state = bpf_map_lookup_elem(&xdp_shield_detection_map, src_ip);
	if (!state) {
		init.window_start_ns = now_ns;
		bpf_map_update_elem(&xdp_shield_detection_map, src_ip, &init,
				    BPF_ANY);
		state = bpf_map_lookup_elem(&xdp_shield_detection_map,
					    src_ip);
	}

	if (state && window_expired(state->window_start_ns, now_ns))
		reset_detection_window(state, now_ns);

	return state;
}

static __always_inline int
check_temporary_ban(const struct xdp_shield_packet_info *pkt, __u64 now_ns,
		    struct xdp_shield_engine_result *result)
{
	struct xdp_shield_temp_ban_entry *ban;
	struct xdp_shield_ip_addr src_ip;

	result->result = XDP_SHIELD_DETECTION_CLEAN;
	result->reason = XDP_SHIELD_BAN_REASON_UNKNOWN;

	if (!packet_has_ipv4_source(pkt))
		return 0;

	packet_source_ip(pkt, &src_ip);
	ban = bpf_map_lookup_elem(&xdp_shield_temp_ban_map, &src_ip);
	if (!ban)
		return 0;

	if (ban->expiration_timestamp_ns <= now_ns) {
		bpf_map_delete_elem(&xdp_shield_temp_ban_map, &src_ip);
		return 0;
	}

	result->result = XDP_SHIELD_DETECTION_MALICIOUS;
	result->reason = ban->reason;
	return 1;
}

static __always_inline int
apply_temporary_ban(const struct xdp_shield_packet_info *pkt, __u64 now_ns,
		    __u32 reason)
{
	struct xdp_shield_temp_ban_entry ban = {};
	struct xdp_shield_ip_addr src_ip;

	if (!packet_has_ipv4_source(pkt))
		return 0;

	packet_source_ip(pkt, &src_ip);
	ban.ip = src_ip;
	ban.ban_timestamp_ns = now_ns;
	{
		struct xdp_shield_runtime_config *config = runtime_config();
		__u64 ban_ns = XDP_SHIELD_TEMP_BAN_DURATION_NS;

		if (config)
			ban_ns = config_u64(config->temp_ban_duration_ns, ban_ns);
		ban.expiration_timestamp_ns = now_ns + ban_ns;
	}
	ban.reason = reason;

	return bpf_map_update_elem(&xdp_shield_temp_ban_map, &src_ip, &ban,
				   BPF_ANY);
}

static __always_inline int
detect_syn_flood(const struct xdp_shield_packet_info *pkt,
		 struct xdp_shield_detection_state *state, __u64 now_ns)
{
	struct xdp_shield_runtime_config *config = runtime_config();
	__u32 threshold = XDP_SHIELD_SYN_FLOOD_THRESHOLD;

	(void)now_ns;

	if (!is_tcp_syn_without_ack(pkt))
		return 0;

	if (config)
		threshold = config_u32(config->syn_flood_threshold, threshold);
	state->syn_count++;
	return state->syn_count > threshold;
}

static __always_inline int
detect_udp_flood(const struct xdp_shield_packet_info *pkt,
		 struct xdp_shield_detection_state *state, __u64 now_ns)
{
	struct xdp_shield_runtime_config *config = runtime_config();
	__u32 threshold = XDP_SHIELD_UDP_FLOOD_THRESHOLD;

	(void)now_ns;

	if (pkt->protocol != XDP_SHIELD_PROTO_UDP)
		return 0;

	if (config)
		threshold = config_u32(config->udp_flood_threshold, threshold);
	state->udp_count++;
	return state->udp_count > threshold;
}

static __always_inline int
detect_icmp_flood(const struct xdp_shield_packet_info *pkt,
		  struct xdp_shield_detection_state *state, __u64 now_ns)
{
	struct xdp_shield_runtime_config *config = runtime_config();
	__u32 threshold = XDP_SHIELD_ICMP_FLOOD_THRESHOLD;

	(void)now_ns;

	if (pkt->protocol != XDP_SHIELD_PROTO_ICMP &&
	    pkt->protocol != XDP_SHIELD_PROTO_ICMPV6)
		return 0;
	if (pkt->protocol == XDP_SHIELD_PROTO_ICMP && pkt->icmp_type != 8)
		return 0;
	if (pkt->protocol == XDP_SHIELD_PROTO_ICMPV6 && pkt->icmp_type != 128)
		return 0;

	if (config)
		threshold = config_u32(config->icmp_flood_threshold, threshold);
	state->icmp_count++;
	return state->icmp_count > threshold;
}

static __always_inline int
detect_port_scan(const struct xdp_shield_packet_info *pkt,
		 struct xdp_shield_detection_state *state, __u64 now_ns)
{
	struct xdp_shield_port_scan_value seen = {};
	struct xdp_shield_port_scan_value *old;
	struct xdp_shield_port_scan_key key = {};
	struct xdp_shield_runtime_config *config = runtime_config();
	__u32 threshold = XDP_SHIELD_PORT_SCAN_THRESHOLD;

	if (pkt->dst_port == 0)
		return 0;

	packet_source_ip(pkt, &key.src_ip);
	key.dst_port = pkt->dst_port;

	old = bpf_map_lookup_elem(&xdp_shield_port_scan_map, &key);
	if (old && !window_expired(old->window_start_ns, now_ns))
		return 0;

	if (config)
		threshold = config_u32(config->port_scan_threshold, threshold);
	seen.window_start_ns = state->window_start_ns;
	bpf_map_update_elem(&xdp_shield_port_scan_map, &key, &seen, BPF_ANY);
	state->unique_port_count++;
	return state->unique_port_count > threshold;
}

static __always_inline int
detect_connection_rate(const struct xdp_shield_packet_info *pkt,
		       struct xdp_shield_detection_state *state, __u64 now_ns)
{
	struct xdp_shield_runtime_config *config = runtime_config();
	__u32 threshold = XDP_SHIELD_CONNECTION_RATE_THRESHOLD;

	(void)now_ns;

	if (!is_tcp_syn_without_ack(pkt))
		return 0;

	if (config)
		threshold = config_u32(config->connection_rate_threshold, threshold);
	state->connection_count++;
	return state->connection_count > threshold;
}

static __always_inline int
run_detection_engine(const struct xdp_shield_packet_info *pkt,
		     struct xdp_shield_engine_result *result)
{
	struct xdp_shield_detection_state *state;
	struct xdp_shield_ip_addr src_ip = {};
	__u64 now_ns = bpf_ktime_get_ns();
	__u32 reason = XDP_SHIELD_BAN_REASON_UNKNOWN;

	result->result = XDP_SHIELD_DETECTION_CLEAN;
	result->reason = XDP_SHIELD_BAN_REASON_UNKNOWN;

	if (!packet_has_ipv4_source(pkt))
		return 0;

	if (check_temporary_ban(pkt, now_ns, result))
		return 0;

	state = get_detection_state(pkt, now_ns, &src_ip);
	if (!state)
		return 0;

	if (detect_syn_flood(pkt, state, now_ns))
		reason = XDP_SHIELD_BAN_REASON_SYN_FLOOD;
	else if (detect_udp_flood(pkt, state, now_ns))
		reason = XDP_SHIELD_BAN_REASON_UDP_FLOOD;
	else if (detect_icmp_flood(pkt, state, now_ns))
		reason = XDP_SHIELD_BAN_REASON_ICMP_FLOOD;
	else if (detect_port_scan(pkt, state, now_ns))
		reason = XDP_SHIELD_BAN_REASON_PORT_SCAN;
	else if (detect_connection_rate(pkt, state, now_ns))
		reason = XDP_SHIELD_BAN_REASON_CONNECTION_RATE;

	if (reason == XDP_SHIELD_BAN_REASON_UNKNOWN)
		return 0;

	apply_temporary_ban(pkt, now_ns, reason);
	result->result = XDP_SHIELD_DETECTION_MALICIOUS;
	result->reason = reason;
	return 0;
}
