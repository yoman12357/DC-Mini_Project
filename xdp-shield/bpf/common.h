#ifndef XDP_SHIELD_BPF_COMMON_H
#define XDP_SHIELD_BPF_COMMON_H

#include <linux/types.h>

/*
 * xdp-shield shared ABI
 *
 * This header is included by both eBPF programs and userspace code. Keep all
 * structures fixed-size, explicitly typed, and free of kernel-only pointers.
 */

#define XDP_SHIELD_IPV6_ADDR_LEN              16
#define XDP_SHIELD_MAX_VLAN_DEPTH             2
#define XDP_SHIELD_MAX_IPV6_EXT_HEADERS       6

#define XDP_SHIELD_MAX_RULES                  65536
#define XDP_SHIELD_MAX_THREAT_FEED_ENTRIES    1048576
#define XDP_SHIELD_MAX_TEMP_BANS              1048576
#define XDP_SHIELD_MAX_TRACKED_FLOWS          1048576
#define XDP_SHIELD_STATS_SLOTS                1
#define XDP_SHIELD_RINGBUF_SIZE               (1 << 20)

#define XDP_SHIELD_MAX_REPUTATION_SCORE       100
#define XDP_SHIELD_DEFAULT_REPUTATION_SCORE   50
#define XDP_SHIELD_MAX_TEMP_BAN_SECONDS       86400

#define XDP_SHIELD_PORT_ANY                   0
#define XDP_SHIELD_PROTOCOL_ANY               0
#define XDP_SHIELD_RULE_PRIORITY_DEFAULT      1000
#define XDP_SHIELD_DEFAULT_POLICY_KEY         0
#define XDP_SHIELD_CONFIG_KEY                 0
#define XDP_SHIELD_IPV4_LPM_PREFIX_BITS       32
#define XDP_SHIELD_IPV6_LPM_PREFIX_BITS       128

#ifdef XDP_SHIELD_LAB_THRESHOLDS
#define XDP_SHIELD_SYN_FLOOD_THRESHOLD        50
#define XDP_SHIELD_UDP_FLOOD_THRESHOLD        100
#define XDP_SHIELD_ICMP_FLOOD_THRESHOLD       50
#define XDP_SHIELD_PORT_SCAN_THRESHOLD        10
#define XDP_SHIELD_CONNECTION_RATE_THRESHOLD  50
#else
#define XDP_SHIELD_SYN_FLOOD_THRESHOLD        10000
#define XDP_SHIELD_UDP_FLOOD_THRESHOLD        50000
#define XDP_SHIELD_ICMP_FLOOD_THRESHOLD       10000
#define XDP_SHIELD_PORT_SCAN_THRESHOLD        100
#define XDP_SHIELD_CONNECTION_RATE_THRESHOLD  20000
#endif
#define XDP_SHIELD_DETECTION_SCORE_MAX        100
#define XDP_SHIELD_DETECTION_WINDOW_NS        1000000000ULL
#define XDP_SHIELD_TEMP_BAN_DURATION_NS       300000000000ULL

#define XDP_SHIELD_TCP_FIN                    0x01
#define XDP_SHIELD_TCP_SYN                    0x02
#define XDP_SHIELD_TCP_RST                    0x04
#define XDP_SHIELD_TCP_PSH                    0x08
#define XDP_SHIELD_TCP_ACK                    0x10
#define XDP_SHIELD_TCP_URG                    0x20
#define XDP_SHIELD_TCP_ECE                    0x40
#define XDP_SHIELD_TCP_CWR                    0x80

/*
 * Packet protocol observed after L3/L4 parsing.
 */
enum xdp_shield_packet_protocol {
	XDP_SHIELD_PROTO_UNKNOWN = 0,
	XDP_SHIELD_PROTO_ICMP = 1,
	XDP_SHIELD_PROTO_TCP = 6,
	XDP_SHIELD_PROTO_UDP = 17,
	XDP_SHIELD_PROTO_ICMPV6 = 58,
};

/*
 * Parser outcome. The parser never makes firewall decisions; callers decide
 * how to handle unsupported or malformed packets.
 */
enum xdp_shield_parser_status {
	XDP_SHIELD_PARSE_OK = 0,
	XDP_SHIELD_PARSE_UNSUPPORTED_L2 = 1,
	XDP_SHIELD_PARSE_UNSUPPORTED_L3 = 2,
	XDP_SHIELD_PARSE_UNSUPPORTED_L4 = 3,
	XDP_SHIELD_PARSE_MALFORMED = -1,
};

/*
 * Firewall decision encoded in rules and detector results.
 */
enum xdp_shield_rule_action {
	XDP_SHIELD_RULE_ALLOW = 0,
	XDP_SHIELD_RULE_DROP = 1,
};

/*
 * Rule engine outcome. RULE_NO_MATCH means no configured rule matched and the
 * caller should apply the configured default policy.
 */
enum xdp_shield_rule_result {
	XDP_SHIELD_RULE_NO_MATCH = 0,
	XDP_SHIELD_RULE_RESULT_ALLOW = 1,
	XDP_SHIELD_RULE_RESULT_DROP = 2,
};

/*
 * Rule matching strategy. Later phases can add range, ASN, geo, or application
 * rule types without changing the base rule map.
 */
enum xdp_shield_rule_type {
	XDP_SHIELD_RULE_TYPE_EXACT = 0,
	XDP_SHIELD_RULE_TYPE_CIDR = 1,
	XDP_SHIELD_RULE_TYPE_PORT = 2,
	XDP_SHIELD_RULE_TYPE_PROTOCOL = 3,
	XDP_SHIELD_RULE_TYPE_COMPOSITE = 4,
};

/*
 * Result produced by future detector modules.
 */
enum xdp_shield_detection_result {
	XDP_SHIELD_DETECTION_CLEAN = 0,
	XDP_SHIELD_DETECTION_SUSPICIOUS = 1,
	XDP_SHIELD_DETECTION_MALICIOUS = 2,
};

/*
 * Threat intelligence category assigned by feed ingestion.
 */
enum xdp_shield_threat_category {
	XDP_SHIELD_THREAT_UNKNOWN = 0,
	XDP_SHIELD_THREAT_MALWARE = 1,
	XDP_SHIELD_THREAT_BOTNET = 2,
	XDP_SHIELD_THREAT_SCANNER = 3,
	XDP_SHIELD_THREAT_SPAM = 4,
	XDP_SHIELD_THREAT_TOR_EXIT = 5,
	XDP_SHIELD_THREAT_ABUSE = 6,
};

/*
 * Reason stored with temporary bans.
 */
enum xdp_shield_ban_reason {
	XDP_SHIELD_BAN_REASON_UNKNOWN = 0,
	XDP_SHIELD_BAN_REASON_MANUAL = 1,
	XDP_SHIELD_BAN_REASON_THREAT_FEED = 2,
	XDP_SHIELD_BAN_REASON_SYN_FLOOD = 3,
	XDP_SHIELD_BAN_REASON_UDP_FLOOD = 4,
	XDP_SHIELD_BAN_REASON_ICMP_FLOOD = 5,
	XDP_SHIELD_BAN_REASON_PORT_SCAN = 6,
	XDP_SHIELD_BAN_REASON_REPUTATION = 7,
	XDP_SHIELD_BAN_REASON_CONNECTION_RATE = 8,
	XDP_SHIELD_BAN_REASON_HONEYPOT = 9,
	XDP_SHIELD_BAN_REASON_CANARY_PORT = 10,
};

enum xdp_shield_event_type {
	XDP_SHIELD_EVENT_DROP = 1,
	XDP_SHIELD_EVENT_TEMP_BAN = 2,
	XDP_SHIELD_EVENT_THREAT_HIT = 3,
	XDP_SHIELD_EVENT_RULE_HIT = 4,
	XDP_SHIELD_EVENT_HONEYPOT_REDIRECT = 5,
	XDP_SHIELD_EVENT_CANARY_HIT = 6,
};

/*
 * Minimal TCP state for flow tracking.
 */
enum xdp_shield_tcp_state {
	XDP_SHIELD_TCP_STATE_NONE = 0,
	XDP_SHIELD_TCP_STATE_SYN_SENT = 1,
	XDP_SHIELD_TCP_STATE_SYN_RECV = 2,
	XDP_SHIELD_TCP_STATE_ESTABLISHED = 3,
	XDP_SHIELD_TCP_STATE_FIN_WAIT = 4,
	XDP_SHIELD_TCP_STATE_CLOSED = 5,
};

/*
 * IP address stored in a userspace/BPF-compatible layout.
 *
 * IPv4 addresses are stored in network byte order in ipv4.
 * IPv6 support is reserved through ipv6 and can be wired into matching later.
 */
struct xdp_shield_ip_addr {
	__u8 is_ipv6;
	__u8 reserved[3];
	union {
		__be32 ipv4;
		__u8 ipv6[XDP_SHIELD_IPV6_ADDR_LEN];
	};
};

/*
 * Packet metadata extracted by the parser.
 *
 * This is data only. It intentionally contains no packet pointers and no parser
 * implementation details.
 */
struct xdp_shield_packet_info {
	__be32 src_ipv4;
	__be32 dst_ipv4;
	__u8 src_ipv6[XDP_SHIELD_IPV6_ADDR_LEN];
	__u8 dst_ipv6[XDP_SHIELD_IPV6_ADDR_LEN];
	__u16 src_port;
	__u16 dst_port;
	__u8 protocol;
	__u8 ip_version;
	__be16 eth_type;
	__u8 tcp_flags;
	__u8 icmp_type;
	__u8 vlan_depth;
	__u16 vlan_tci[XDP_SHIELD_MAX_VLAN_DEPTH];
	__u32 packet_len;
	__u8 is_fragment;
	__u8 is_first_fragment;
	__u16 fragment_offset;
	__u16 arp_operation;
	__u16 reserved;
};

/*
 * Key for the rule map. Rules are addressed by stable rule ID.
 */
struct xdp_shield_rule_key {
	__u32 rule_id;
};

/*
 * Firewall rule stored in the rule map.
 *
 * Ports set to XDP_SHIELD_PORT_ANY match any port. Protocol set to
 * XDP_SHIELD_PROTOCOL_ANY matches any L4 protocol.
 */
struct xdp_shield_firewall_rule {
	__u32 rule_id;
	__u8 action;
	__u8 type;
	__u8 protocol;
	__u8 enabled;
	__u8 src_prefix_len;
	__u8 dst_prefix_len;
	struct xdp_shield_ip_addr src_ip;
	struct xdp_shield_ip_addr dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u32 priority;
};

/*
 * Compact value stored in rule index maps. Each index points to a rule decision
 * with enough metadata to resolve priority without scanning all rules.
 */
struct xdp_shield_rule_decision {
	__u32 rule_id;
	__u32 priority;
	__u8 action;
	__u8 type;
	__u8 enabled;
	__u8 reserved;
};

struct xdp_shield_ipv4_key {
	__be32 addr;
};

struct xdp_shield_port_key {
	__u16 port;
	__u16 reserved;
};

struct xdp_shield_protocol_key {
	__u8 protocol;
	__u8 reserved[3];
};

/*
 * Five-tuple key used for flow tracking.
 */
struct xdp_shield_flow_key {
	struct xdp_shield_ip_addr src_ip;
	struct xdp_shield_ip_addr dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u8 protocol;
	__u8 reserved[3];
};

/*
 * Per-flow state used by future detection modules.
 */
struct xdp_shield_flow_value {
	__u64 packet_count;
	__u64 byte_count;
	__u64 last_seen_ns;
	__u8 state;
	__u8 detection_score;
	__u8 reserved[6];
};

/*
 * LPM trie key for IP prefix maps.
 *
 * prefix_len is measured across the bytes following it. The first byte is
 * address family marker, so userspace should encode IPv4 prefix N as
 * 8 + N and IPv6 prefix N as 8 + N.
 */
struct xdp_shield_lpm_key {
	__u32 prefix_len;
	__u8 is_ipv6;
	__u8 addr[XDP_SHIELD_IPV6_ADDR_LEN];
};

/*
 * Threat intelligence record stored as an LPM trie value.
 */
struct xdp_shield_threat_feed_entry {
	struct xdp_shield_ip_addr ip;
	__u32 reputation_score;
	__u32 feed_source_id;
	__u32 category;
};

/*
 * Temporary ban map value.
 */
struct xdp_shield_temp_ban_entry {
	struct xdp_shield_ip_addr ip;
	__u64 ban_timestamp_ns;
	__u64 expiration_timestamp_ns;
	__u32 reason;
	__u32 reserved;
};

/*
 * Per-source detection counters for fixed-window attack detection.
 */
struct xdp_shield_detection_state {
	__u64 window_start_ns;
	__u32 syn_count;
	__u32 udp_count;
	__u32 icmp_count;
	__u32 connection_count;
	__u32 unique_port_count;
};

/*
 * Tracks whether a source touched a destination port during a scan window.
 */
struct xdp_shield_port_scan_key {
	struct xdp_shield_ip_addr src_ip;
	__u16 dst_port;
	__u16 reserved;
};

struct xdp_shield_port_scan_value {
	__u64 window_start_ns;
};

/*
 * Global and per-CPU statistics counters.
 */
struct xdp_shield_stats_entry {
	__u64 packets_processed;
	__u64 packets_accepted;
	__u64 packets_dropped;
	__u64 threat_feed_hits;
	__u64 temporary_ban_hits;
	__u64 rule_hits;
	__u64 honeypot_redirects;
	__u64 canary_hits;
};

struct xdp_shield_event {
	__u64 timestamp_ns;
	__be32 src_ipv4;
	__be32 dst_ipv4;
	__u16 src_port;
	__u16 dst_port;
	__u8 protocol;
	__u8 event_type;
	__u16 reserved;
	__u32 reason;
};

struct xdp_shield_runtime_config {
	__u32 syn_flood_threshold;
	__u32 udp_flood_threshold;
	__u32 icmp_flood_threshold;
	__u32 port_scan_threshold;
	__u32 connection_rate_threshold;
	__u64 detection_window_ns;
	__u64 temp_ban_duration_ns;
};

#define XDP_SHIELD_DEVMAP_HONEYPOT_KEY        0
#define XDP_SHIELD_DEVMAP_EXTERNAL_KEY        1
#define XDP_SHIELD_MAX_CANARY_PORTS           256
#define XDP_SHIELD_MAX_HONEYPOT_SOURCES       1048576
#define XDP_SHIELD_MAX_HONEYPOT_FLOWS         1048576
#define XDP_SHIELD_HONEYPOT_DEFAULT_SECONDS   600

struct xdp_shield_mac_addr {
	__u8 bytes[6];
	__u8 reserved[2];
};

struct xdp_shield_honeypot_config {
	__u8 enabled;
	__u8 redirect_tcp;
	__u16 honeypot_port;
	__be32 honeypot_ipv4;
	__u32 external_ifindex;
	__u32 honeypot_ifindex;
	__u64 redirect_duration_ns;
	struct xdp_shield_mac_addr external_mac;
	struct xdp_shield_mac_addr honeypot_mac;
};

struct xdp_shield_honeypot_source {
	__u64 first_seen_ns;
	__u64 last_seen_ns;
	__u64 expiration_ns;
	__u32 reason;
	__u32 hits;
};

struct xdp_shield_honeypot_flow_key {
	__be32 client_ipv4;
	__u16 client_port;
	__u16 honeypot_port;
	__u8 protocol;
	__u8 reserved[3];
};

struct xdp_shield_honeypot_flow_value {
	__be32 original_dst_ipv4;
	__u16 original_dst_port;
	__u16 reserved;
	struct xdp_shield_mac_addr external_mac;
	struct xdp_shield_mac_addr gateway_mac;
	__u64 created_ns;
	__u64 last_seen_ns;
};

struct xdp_shield_honeypot_scratch {
	struct xdp_shield_honeypot_flow_key flow_key;
	struct xdp_shield_honeypot_flow_value flow_value;
	struct xdp_shield_honeypot_source source;
};

#endif
