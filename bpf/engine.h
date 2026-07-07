#ifndef XDP_SHIELD_BPF_ENGINE_H
#define XDP_SHIELD_BPF_ENGINE_H

#include "common.h"

struct xdp_shield_engine_result {
	__u8 result;
	__u32 reason;
};

static __always_inline int
check_temporary_ban(const struct xdp_shield_packet_info *pkt, __u64 now_ns,
		    struct xdp_shield_engine_result *result);
static __always_inline int
apply_temporary_ban(const struct xdp_shield_packet_info *pkt, __u64 now_ns,
		    __u32 reason);
static __always_inline int
detect_syn_flood(const struct xdp_shield_packet_info *pkt,
		 struct xdp_shield_detection_state *state, __u64 now_ns);
static __always_inline int
detect_udp_flood(const struct xdp_shield_packet_info *pkt,
		 struct xdp_shield_detection_state *state, __u64 now_ns);
static __always_inline int
detect_icmp_flood(const struct xdp_shield_packet_info *pkt,
		  struct xdp_shield_detection_state *state, __u64 now_ns);
static __always_inline int
detect_port_scan(const struct xdp_shield_packet_info *pkt,
		 struct xdp_shield_detection_state *state, __u64 now_ns);
static __always_inline int
detect_connection_rate(const struct xdp_shield_packet_info *pkt,
		       struct xdp_shield_detection_state *state, __u64 now_ns);
static __always_inline int
run_detection_engine(const struct xdp_shield_packet_info *pkt,
		     struct xdp_shield_engine_result *result);

#endif
