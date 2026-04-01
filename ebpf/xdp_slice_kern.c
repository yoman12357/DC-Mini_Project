#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct pkt_meta {
    __u8 outer_src_mac[6];
    __u8 outer_dst_mac[6];
    __u8 inner_src_mac[6];
    __u8 inner_dst_mac[6];
    __u32 outer_src_ip;
    __u32 outer_dst_ip;
    __u32 inner_src_ip;
    __u32 inner_dst_ip;
    __u16 outer_src_port;
    __u16 outer_dst_port;
    __u16 inner_src_port;
    __u16 inner_dst_port;
    __u8 link_protocol;
    __u8 transport_protocol;
    __u32 vxlan_id;
    __u32 gtp_id;
};

struct control_value {
    __u16 action;
    __u16 queue;
};

struct monitor_value {
    __u32 total_length;
    __u32 packet_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2097152);
    __type(key, __u32);
    __type(value, struct control_value);
} control_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2097152);
    __type(key, __u32);
    __type(value, struct monitor_value);
} monitor_map SEC(".maps");

static __always_inline __u32 simple_hash(struct pkt_meta *meta) {
    __u32 *words = (__u32 *)meta;
    __u32 hash = 0;
    int i;

#pragma clang loop unroll(full)
    for (i = 0; i < (int)(sizeof(*meta) / sizeof(__u32)); i++) {
        hash ^= words[i] + 0x9e3779b9 + (hash << 6) + (hash >> 2);
    }
    return hash;
}

SEC("xdp")
int xdp_slice_prog(struct xdp_md *ctx) {
    struct pkt_meta meta = {};
    __u32 key;
    struct control_value *control;
    struct monitor_value *monitor;

    /* Parsing is intentionally minimal here because this file is a skeleton
     * for the software prototype. In a full deployment, this section would
     * extract Ethernet, IP, UDP/TCP, VXLAN, and GTP fields.
     */

    key = simple_hash(&meta);
    control = bpf_map_lookup_elem(&control_map, &key);
    if (!control) {
        return XDP_PASS;
    }

    monitor = bpf_map_lookup_elem(&monitor_map, &key);
    if (monitor) {
        monitor->packet_count += 1;
    }

    if (control->action == 0) {
        return XDP_DROP;
    }

    if (control->action == 1) {
        /* In the real SmartNIC/AF_XDP path this would redirect to an XSK map
         * or hardware queue. The software prototype keeps queue selection in
         * user space, so the skeleton falls back to XDP_PASS here.
         */
        return XDP_PASS;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
