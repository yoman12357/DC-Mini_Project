#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define SEC(NAME) __attribute__((section(NAME), used))
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;

struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

struct control_value {
    __u32 action;
    __u32 queue;
};

struct monitor_value {
    __u64 packet_count;
    __u64 total_bytes;
    __u64 dropped_packets;
    __u64 passed_packets;
    __u64 steered_packets;
    __u32 last_action;
    __u32 last_queue;
};

struct bpf_map_def SEC("maps") control_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct control_value),
    .max_entries = 1024,
    .map_flags = 0,
};

struct bpf_map_def SEC("maps") monitor_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct monitor_value),
    .max_entries = 1024,
    .map_flags = 0,
};

static __always_inline __u16 bpf_ntohs(__u16 value) {
    return __builtin_bswap16(value);
}

static __always_inline __u32 bpf_ntohl(__u32 value) {
    return __builtin_bswap32(value);
}

static __always_inline __u32 mix_hash(__u32 hash, __u32 value) {
    return (hash ^ value) * 16777619;
}

static __always_inline __u32 flow_hash(
    __u32 src_ip,
    __u32 dst_ip,
    __u8 proto,
    __u16 dst_port,
    __u32 tunnel_id
) {
    __u32 hash = 2166136261u;
    hash = mix_hash(hash, src_ip);
    hash = mix_hash(hash, dst_ip);
    hash = mix_hash(hash, ((__u32)proto << 16) | dst_port);
    hash = mix_hash(hash, tunnel_id);
    return hash;
}

#define ACTION_DROP 0
#define ACTION_STEER 1
#define ACTION_PASS 2

struct vxlanhdr {
    __u8 flags;
    __u8 rsvd1[3];
    __u8 vni[3];
    __u8 rsvd2;
};

struct gtpu_base_hdr {
    __u8 flags;
    __u8 msg_type;
    __be16 length;
    __be32 teid;
};

SEC("xdp")
int xdp_runtime_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    __u32 key;
    __u8 proto;
    __u16 dst_port = 0;
    __u32 tunnel_id = 0;
    struct control_value *control;
    struct monitor_value *monitor;
    struct monitor_value zero = {};
    __u32 action = ACTION_PASS;
    __u32 queue = 0;
    __u64 pkt_len = (__u64)((char *)data_end - (char *)data);

    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != __builtin_bswap16(ETH_P_IP)) {
        return XDP_PASS;
    }

    iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    proto = iph->protocol;
    if (proto == 6) {
        __u32 ihl = iph->ihl * 4;
        struct tcphdr *tcp = (void *)iph + ihl;
        if ((void *)(tcp + 1) > data_end) {
            return XDP_PASS;
        }
        dst_port = bpf_ntohs(tcp->dest);
    } else if (proto == 17) {
        __u32 ihl = iph->ihl * 4;
        struct udphdr *udp = (void *)iph + ihl;
        if ((void *)(udp + 1) > data_end) {
            return XDP_PASS;
        }
        dst_port = bpf_ntohs(udp->dest);
        if (dst_port == 4789) {
            struct vxlanhdr *vxlan = (void *)(udp + 1);
            struct ethhdr *inner_eth;
            struct iphdr *inner_iph;
            if ((void *)(vxlan + 1) > data_end) {
                return XDP_PASS;
            }
            tunnel_id = ((__u32)vxlan->vni[0] << 16) | ((__u32)vxlan->vni[1] << 8) | (__u32)vxlan->vni[2];
            inner_eth = (void *)(vxlan + 1);
            if ((void *)(inner_eth + 1) > data_end) {
                return XDP_PASS;
            }
            if (inner_eth->h_proto == __builtin_bswap16(ETH_P_IP)) {
                inner_iph = (void *)(inner_eth + 1);
                if ((void *)(inner_iph + 1) > data_end) {
                    return XDP_PASS;
                }
                proto = inner_iph->protocol;
                if (proto == 6) {
                    struct tcphdr *inner_tcp = (void *)inner_iph + inner_iph->ihl * 4;
                    if ((void *)(inner_tcp + 1) > data_end) {
                        return XDP_PASS;
                    }
                    dst_port = bpf_ntohs(inner_tcp->dest);
                } else if (proto == 17) {
                    struct udphdr *inner_udp = (void *)inner_iph + inner_iph->ihl * 4;
                    if ((void *)(inner_udp + 1) > data_end) {
                        return XDP_PASS;
                    }
                    dst_port = bpf_ntohs(inner_udp->dest);
                } else {
                    dst_port = 0;
                }
                key = flow_hash(inner_iph->saddr, inner_iph->daddr, proto, dst_port, tunnel_id);
                goto lookup;
            }
        } else if (dst_port == 2152) {
            struct gtpu_base_hdr *gtpu = (void *)(udp + 1);
            struct iphdr *inner_iph;
            if ((void *)(gtpu + 1) > data_end) {
                return XDP_PASS;
            }
            tunnel_id = bpf_ntohl(gtpu->teid);
            inner_iph = (void *)(gtpu + 1);
            if ((void *)(inner_iph + 1) > data_end) {
                return XDP_PASS;
            }
            if (inner_iph->version == 4) {
                proto = inner_iph->protocol;
                if (proto == 6) {
                    struct tcphdr *inner_tcp = (void *)inner_iph + inner_iph->ihl * 4;
                    if ((void *)(inner_tcp + 1) > data_end) {
                        return XDP_PASS;
                    }
                    dst_port = bpf_ntohs(inner_tcp->dest);
                } else if (proto == 17) {
                    struct udphdr *inner_udp = (void *)inner_iph + inner_iph->ihl * 4;
                    if ((void *)(inner_udp + 1) > data_end) {
                        return XDP_PASS;
                    }
                    dst_port = bpf_ntohs(inner_udp->dest);
                } else {
                    dst_port = 0;
                }
                key = flow_hash(inner_iph->saddr, inner_iph->daddr, proto, dst_port, tunnel_id);
                goto lookup;
            }
        }
    }

    key = flow_hash(iph->saddr, iph->daddr, proto, dst_port, tunnel_id);
lookup:
    control = bpf_map_lookup_elem(&control_map, &key);
    if (control) {
        action = control->action;
        queue = control->queue;
    }

    monitor = bpf_map_lookup_elem(&monitor_map, &key);
    if (!monitor) {
        bpf_map_update_elem(&monitor_map, &key, &zero, BPF_ANY);
        monitor = bpf_map_lookup_elem(&monitor_map, &key);
    }

    if (monitor) {
        monitor->packet_count += 1;
        monitor->total_bytes += pkt_len;
        monitor->last_action = action;
        monitor->last_queue = queue;
        if (action == ACTION_DROP) {
            monitor->dropped_packets += 1;
        } else if (action == ACTION_STEER) {
            monitor->steered_packets += 1;
        } else {
            monitor->passed_packets += 1;
        }
    }

    if (action == ACTION_DROP) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
