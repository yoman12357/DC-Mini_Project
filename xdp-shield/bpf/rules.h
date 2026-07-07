#ifndef XDP_SHIELD_BPF_RULES_H
#define XDP_SHIELD_BPF_RULES_H

#include "common.h"

struct xdp_shield_rule_eval {
	__u32 rule_id;
	__u32 priority;
	__u8 action;
	__u8 result;
	__u8 matched;
	__u8 reserved;
};

static __always_inline enum xdp_shield_rule_result
check_rules(const struct xdp_shield_packet_info *pkt);
static __always_inline enum xdp_shield_rule_result
evaluate_rule(const struct xdp_shield_packet_info *pkt,
	      struct xdp_shield_rule_eval *eval);

#endif
