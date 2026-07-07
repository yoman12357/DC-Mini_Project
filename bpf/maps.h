#ifndef XDP_SHIELD_BPF_MAPS_H
#define XDP_SHIELD_BPF_MAPS_H

#include <bpf/bpf_helpers.h>

#include "common.h"

/*
 * Rule map
 *
 * Hash map keyed by rule ID. This gives predictable O(1) updates from
 * userspace and stable addressing for rule add/delete operations.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, XDP_SHIELD_MAX_RULES);
	__type(key, struct xdp_shield_rule_key);
	__type(value, struct xdp_shield_firewall_rule);
} xdp_shield_rule_map SEC(".maps");

/*
 * Default policy map
 *
 * Single-entry array keyed by XDP_SHIELD_DEFAULT_POLICY_KEY. Keeping default
 * policy in a map allows runtime changes without reloading the BPF program.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct xdp_shield_rule_decision);
} xdp_shield_default_policy_map SEC(".maps");

/*
 * Runtime configuration map
 *
 * Single-entry array holding thresholds and ban windows. Userspace can update
 * this map while the firewall is running, avoiding BPF recompiles for tuning.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct xdp_shield_runtime_config);
} xdp_shield_config_map SEC(".maps");

/*
 * Exact IPv4 rule indexes
 *
 * Hash maps provide O(1) exact source/destination IPv4 lookups. CIDR rules are
 * stored separately in LPM tries below to avoid scanning prefix rules.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, XDP_SHIELD_MAX_RULES);
	__type(key, struct xdp_shield_ipv4_key);
	__type(value, struct xdp_shield_rule_decision);
} xdp_shield_src_ipv4_rule_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, XDP_SHIELD_MAX_RULES);
	__type(key, struct xdp_shield_ipv4_key);
	__type(value, struct xdp_shield_rule_decision);
} xdp_shield_dst_ipv4_rule_map SEC(".maps");

/*
 * Port and protocol rule indexes
 *
 * These maps support direct source-port, destination-port, and protocol rules
 * without requiring the rule engine to iterate over unrelated rule IDs.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, XDP_SHIELD_MAX_RULES);
	__type(key, struct xdp_shield_port_key);
	__type(value, struct xdp_shield_rule_decision);
} xdp_shield_src_port_rule_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, XDP_SHIELD_MAX_RULES);
	__type(key, struct xdp_shield_port_key);
	__type(value, struct xdp_shield_rule_decision);
} xdp_shield_dst_port_rule_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, XDP_SHIELD_MAX_RULES);
	__type(key, struct xdp_shield_protocol_key);
	__type(value, struct xdp_shield_rule_decision);
} xdp_shield_protocol_rule_map SEC(".maps");

/*
 * CIDR rule indexes
 *
 * LPM tries perform efficient longest-prefix match for source and destination
 * IPv4/IPv6 CIDR rules. The rule engine performs one lookup per direction
 * instead of iterating through all configured CIDR rules.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, XDP_SHIELD_MAX_RULES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct xdp_shield_lpm_key);
	__type(value, struct xdp_shield_rule_decision);
} xdp_shield_src_cidr_rule_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, XDP_SHIELD_MAX_RULES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct xdp_shield_lpm_key);
	__type(value, struct xdp_shield_rule_decision);
} xdp_shield_dst_cidr_rule_map SEC(".maps");

/*
 * Threat feed map
 *
 * LPM trie supports CIDR-style threat intelligence feeds for IPv4 and IPv6.
 * The key carries an address-family byte plus the address bytes, allowing
 * longest-prefix matching instead of exact-IP-only lookups.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, XDP_SHIELD_MAX_THREAT_FEED_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct xdp_shield_lpm_key);
	__type(value, struct xdp_shield_threat_feed_entry);
} xdp_shield_threat_feed_map SEC(".maps");

/*
 * Whitelist map
 *
 * LPM trie mirrors the threat feed key format so trusted IPv4/IPv6 prefixes can
 * be checked with longest-prefix semantics before threat or rule decisions.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, XDP_SHIELD_MAX_THREAT_FEED_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct xdp_shield_lpm_key);
	__type(value, struct xdp_shield_threat_feed_entry);
} xdp_shield_whitelist_map SEC(".maps");

/*
 * Temporary ban map
 *
 * LRU hash map keeps short-lived bans bounded under attack pressure. Entries
 * can expire by timestamp, and least-recently-used eviction protects memory
 * when abusive sources exceed configured capacity.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, XDP_SHIELD_MAX_TEMP_BANS);
	__type(key, struct xdp_shield_ip_addr);
	__type(value, struct xdp_shield_temp_ban_entry);
} xdp_shield_temp_ban_map SEC(".maps");

/*
 * Detection state map
 *
 * LRU hash bounds per-source counter state during high-cardinality attacks.
 * Counters reset in-place when the configured detection window expires.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, XDP_SHIELD_MAX_TRACKED_FLOWS);
	__type(key, struct xdp_shield_ip_addr);
	__type(value, struct xdp_shield_detection_state);
} xdp_shield_detection_map SEC(".maps");

/*
 * Port scan map
 *
 * LRU hash remembers source/destination-port pairs seen in the current scan
 * window so unique-port counting remains bounded and verifier-friendly.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, XDP_SHIELD_MAX_TRACKED_FLOWS);
	__type(key, struct xdp_shield_port_scan_key);
	__type(value, struct xdp_shield_port_scan_value);
} xdp_shield_port_scan_map SEC(".maps");

/*
 * Flow tracking map
 *
 * LRU hash map is appropriate for high-cardinality flow state because stale
 * flows can be evicted automatically without userspace walking the whole map.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, XDP_SHIELD_MAX_TRACKED_FLOWS);
	__type(key, struct xdp_shield_flow_key);
	__type(value, struct xdp_shield_flow_value);
} xdp_shield_flow_map SEC(".maps");

/*
 * Statistics map
 *
 * Plain array for aggregated counters keyed by a small fixed index. Userspace
 * can read this when exact global counters are preferred over per-CPU speed.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, XDP_SHIELD_STATS_SLOTS);
	__type(key, __u32);
	__type(value, struct xdp_shield_stats_entry);
} xdp_shield_stats_map SEC(".maps");

/*
 * Per-CPU statistics map
 *
 * Per-CPU array avoids cache-line contention on hot packet counters. Userspace
 * should aggregate values across CPUs when reporting totals.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, XDP_SHIELD_STATS_SLOTS);
	__type(key, __u32);
	__type(value, struct xdp_shield_stats_entry);
} xdp_shield_percpu_stats_map SEC(".maps");

/*
 * Event ring buffer
 *
 * Carries compact drop/ban events to userspace without printing from BPF.
 * Userspace can poll this while the firewall is attached.
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, XDP_SHIELD_RINGBUF_SIZE);
} xdp_shield_events SEC(".maps");

/*
 * Honeypot configuration and redirect maps
 *
 * The devmap carries packets between the protected interface and the isolated
 * honeypot veth. Source and flow maps preserve deception state so replies can
 * be rewritten back to the original service address.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct xdp_shield_honeypot_config);
} xdp_shield_honeypot_config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u32);
} xdp_shield_honeypot_devmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, XDP_SHIELD_MAX_CANARY_PORTS);
	__type(key, struct xdp_shield_port_key);
	__type(value, __u8);
} xdp_shield_canary_port_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, XDP_SHIELD_MAX_HONEYPOT_SOURCES);
	__type(key, struct xdp_shield_ip_addr);
	__type(value, struct xdp_shield_honeypot_source);
} xdp_shield_honeypot_source_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, XDP_SHIELD_MAX_HONEYPOT_FLOWS);
	__type(key, struct xdp_shield_honeypot_flow_key);
	__type(value, struct xdp_shield_honeypot_flow_value);
} xdp_shield_honeypot_flow_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct xdp_shield_honeypot_scratch);
} xdp_shield_honeypot_scratch_map SEC(".maps");

#endif
