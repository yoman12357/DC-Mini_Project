#include <linux/if_ether.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "engine.h"
#include "maps.h"
#include "rules.h"

static __always_inline enum xdp_shield_rule_result
action_to_result(__u8 action)
{
	if (action == XDP_SHIELD_RULE_DROP)
		return XDP_SHIELD_RULE_RESULT_DROP;
	if (action == XDP_SHIELD_RULE_ALLOW)
		return XDP_SHIELD_RULE_RESULT_ALLOW;
	return XDP_SHIELD_RULE_NO_MATCH;
}

static __always_inline int decision_is_better(const struct xdp_shield_rule_decision *candidate,
					      const struct xdp_shield_rule_eval *best)
{
	if (!candidate || !candidate->enabled)
		return 0;
	if (!best->matched)
		return 1;
	return candidate->priority < best->priority;
}

static __always_inline int rule_has_src_ip_bpf(const struct xdp_shield_firewall_rule *rule)
{
	return rule->src_ip.ipv4 != 0 || rule->src_prefix_len != 0;
}

static __always_inline int rule_has_dst_ip_bpf(const struct xdp_shield_firewall_rule *rule)
{
	return rule->dst_ip.ipv4 != 0 || rule->dst_prefix_len != 0;
}

static __always_inline __u8 effective_prefix_len_bpf(__be32 addr, __u8 prefix_len)
{
	if (prefix_len)
		return prefix_len;
	if (addr)
		return XDP_SHIELD_IPV4_LPM_PREFIX_BITS;
	return 0;
}

static __always_inline int ipv4_prefix_match(__be32 packet_addr, __be32 rule_addr,
					     __u8 prefix_len)
{
	__u32 packet_host = bpf_ntohl(packet_addr);
	__u32 rule_host = bpf_ntohl(rule_addr);
	__u32 mask;

	if (prefix_len == 0)
		return 1;
	if (prefix_len >= 32)
		return packet_addr == rule_addr;

	mask = ~((1U << (32 - prefix_len)) - 1);
	return (packet_host & mask) == (rule_host & mask);
}

static __always_inline int full_rule_matches(const struct xdp_shield_packet_info *pkt,
					     const struct xdp_shield_firewall_rule *rule)
{
	__u8 prefix_len;

	if (!rule || !rule->enabled)
		return 0;
	if (rule->protocol != XDP_SHIELD_PROTOCOL_ANY &&
	    rule->protocol != pkt->protocol)
		return 0;
	if (rule->src_port != XDP_SHIELD_PORT_ANY &&
	    rule->src_port != pkt->src_port)
		return 0;
	if (rule->dst_port != XDP_SHIELD_PORT_ANY &&
	    rule->dst_port != pkt->dst_port)
		return 0;

	if (rule_has_src_ip_bpf(rule)) {
		if (pkt->ip_version != 4)
			return 0;
		prefix_len = effective_prefix_len_bpf(rule->src_ip.ipv4,
						      rule->src_prefix_len);
		if (!ipv4_prefix_match(pkt->src_ipv4, rule->src_ip.ipv4,
				       prefix_len))
			return 0;
	}

	if (rule_has_dst_ip_bpf(rule)) {
		if (pkt->ip_version != 4)
			return 0;
		prefix_len = effective_prefix_len_bpf(rule->dst_ip.ipv4,
						      rule->dst_prefix_len);
		if (!ipv4_prefix_match(pkt->dst_ipv4, rule->dst_ip.ipv4,
				       prefix_len))
			return 0;
	}

	return 1;
}

static __always_inline void consider_decision(const struct xdp_shield_rule_decision *candidate,
					      const struct xdp_shield_packet_info *pkt,
					      struct xdp_shield_rule_eval *best)
{
	struct xdp_shield_firewall_rule *rule;
	struct xdp_shield_rule_key key;

	if (!decision_is_better(candidate, best))
		return;

	key.rule_id = candidate->rule_id;
	rule = bpf_map_lookup_elem(&xdp_shield_rule_map, &key);
	if (!full_rule_matches(pkt, rule))
		return;

	best->rule_id = rule->rule_id;
	best->priority = rule->priority;
	best->action = rule->action;
	best->result = action_to_result(rule->action);
	best->matched = 1;
}

static __always_inline int packet_has_ipv4(const struct xdp_shield_packet_info *pkt)
{
	return pkt->ip_version == 4 && pkt->eth_type == __bpf_constant_htons(ETH_P_IP);
}

static __always_inline void fill_ipv4_lpm_key(struct xdp_shield_lpm_key *key,
					      __be32 addr)
{
	__u8 *raw = (__u8 *)&addr;

	__builtin_memset(key, 0, sizeof(*key));
	key->prefix_len = XDP_SHIELD_IPV4_LPM_PREFIX_BITS + 8;
	key->is_ipv6 = 0;
	key->addr[0] = raw[0];
	key->addr[1] = raw[1];
	key->addr[2] = raw[2];
	key->addr[3] = raw[3];
}

static __always_inline void fill_ipv6_lpm_key(struct xdp_shield_lpm_key *key,
					      const __u8 addr[XDP_SHIELD_IPV6_ADDR_LEN])
{
	int i;

	__builtin_memset(key, 0, sizeof(*key));
	key->prefix_len = XDP_SHIELD_IPV6_LPM_PREFIX_BITS + 8;
	key->is_ipv6 = 1;

#pragma clang loop unroll(full)
	for (i = 0; i < XDP_SHIELD_IPV6_ADDR_LEN; i++)
		key->addr[i] = addr[i];
}

static __always_inline void match_ip(const struct xdp_shield_packet_info *pkt,
				     struct xdp_shield_rule_eval *best)
{
	struct xdp_shield_rule_decision *decision;

	if (packet_has_ipv4(pkt)) {
		struct xdp_shield_ipv4_key exact_key;

		exact_key.addr = pkt->src_ipv4;
		decision = bpf_map_lookup_elem(&xdp_shield_src_ipv4_rule_map,
					       &exact_key);
		consider_decision(decision, pkt, best);

		exact_key.addr = pkt->dst_ipv4;
		decision = bpf_map_lookup_elem(&xdp_shield_dst_ipv4_rule_map,
					       &exact_key);
		consider_decision(decision, pkt, best);
	}
}

static __always_inline void match_cidr(const struct xdp_shield_packet_info *pkt,
				       struct xdp_shield_rule_eval *best)
{
	struct xdp_shield_rule_decision *decision;
	struct xdp_shield_lpm_key key;

	if (pkt->ip_version == 4) {
		fill_ipv4_lpm_key(&key, pkt->src_ipv4);
		decision = bpf_map_lookup_elem(&xdp_shield_src_cidr_rule_map,
					       &key);
		consider_decision(decision, pkt, best);

		fill_ipv4_lpm_key(&key, pkt->dst_ipv4);
		decision = bpf_map_lookup_elem(&xdp_shield_dst_cidr_rule_map,
					       &key);
		consider_decision(decision, pkt, best);
		return;
	}

	if (pkt->ip_version == 6) {
		fill_ipv6_lpm_key(&key, pkt->src_ipv6);
		decision = bpf_map_lookup_elem(&xdp_shield_src_cidr_rule_map,
					       &key);
		consider_decision(decision, pkt, best);

		fill_ipv6_lpm_key(&key, pkt->dst_ipv6);
		decision = bpf_map_lookup_elem(&xdp_shield_dst_cidr_rule_map,
					       &key);
		consider_decision(decision, pkt, best);
	}
}

static __always_inline void match_port(const struct xdp_shield_packet_info *pkt,
				       struct xdp_shield_rule_eval *best)
{
	struct xdp_shield_rule_decision *decision;
	struct xdp_shield_port_key key = {};

	if (!pkt->src_port && !pkt->dst_port)
		return;

	key.port = pkt->src_port;
	decision = bpf_map_lookup_elem(&xdp_shield_src_port_rule_map, &key);
	consider_decision(decision, pkt, best);

	key.port = pkt->dst_port;
	decision = bpf_map_lookup_elem(&xdp_shield_dst_port_rule_map, &key);
	consider_decision(decision, pkt, best);
}

static __always_inline void match_protocol(const struct xdp_shield_packet_info *pkt,
					   struct xdp_shield_rule_eval *best)
{
	struct xdp_shield_rule_decision *decision;
	struct xdp_shield_protocol_key key = {};

	if (pkt->protocol == XDP_SHIELD_PROTO_UNKNOWN)
		return;

	key.protocol = pkt->protocol;
	decision = bpf_map_lookup_elem(&xdp_shield_protocol_rule_map, &key);
	consider_decision(decision, pkt, best);
}

static __always_inline enum xdp_shield_rule_result
apply_default_policy(struct xdp_shield_rule_eval *eval)
{
	struct xdp_shield_rule_decision *policy;
	__u32 key = XDP_SHIELD_DEFAULT_POLICY_KEY;

	policy = bpf_map_lookup_elem(&xdp_shield_default_policy_map, &key);
	if (!policy || !policy->enabled)
		return XDP_SHIELD_RULE_NO_MATCH;

	eval->rule_id = policy->rule_id;
	eval->priority = policy->priority;
	eval->action = policy->action;
	eval->result = action_to_result(policy->action);
	eval->matched = 1;
	return eval->result;
}

static __always_inline enum xdp_shield_rule_result
match_rule(const struct xdp_shield_packet_info *pkt,
	   struct xdp_shield_rule_eval *eval)
{
	match_protocol(pkt, eval);
	match_port(pkt, eval);
	match_ip(pkt, eval);
	match_cidr(pkt, eval);

	if (eval->matched)
		return eval->result;

	return XDP_SHIELD_RULE_NO_MATCH;
}

static __always_inline enum xdp_shield_rule_result
evaluate_rule(const struct xdp_shield_packet_info *pkt,
	      struct xdp_shield_rule_eval *eval)
{
	struct xdp_shield_engine_result ban = {};
	enum xdp_shield_rule_result result;

	__builtin_memset(eval, 0, sizeof(*eval));
	eval->priority = XDP_SHIELD_RULE_PRIORITY_DEFAULT;
	eval->result = XDP_SHIELD_RULE_NO_MATCH;

	if (check_temporary_ban(pkt, bpf_ktime_get_ns(), &ban)) {
		eval->action = XDP_SHIELD_RULE_DROP;
		eval->result = XDP_SHIELD_RULE_RESULT_DROP;
		eval->matched = 1;
		return XDP_SHIELD_RULE_RESULT_DROP;
	}

	result = match_rule(pkt, eval);
	if (result != XDP_SHIELD_RULE_NO_MATCH)
		return result;

	return apply_default_policy(eval);
}

static __always_inline enum xdp_shield_rule_result
check_rules(const struct xdp_shield_packet_info *pkt)
{
	struct xdp_shield_rule_eval eval;

	return evaluate_rule(pkt, &eval);
}
