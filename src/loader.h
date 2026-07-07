#ifndef XDP_SHIELD_LOADER_H
#define XDP_SHIELD_LOADER_H

#include <stdbool.h>
#include <linux/if_link.h>

#include <bpf/libbpf.h>

#define XDP_SHIELD_PROG_NAME "xdp_shield_firewall"
#define XDP_SHIELD_ATTACH_FLAGS (XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST)
#define XDP_SHIELD_DETACH_FLAGS XDP_FLAGS_SKB_MODE
#define XDP_SHIELD_PIN_DIR "/sys/fs/bpf/xdp-shield"

/*
 * File descriptors for maps owned by the loaded BPF object.
 *
 * Keeping these FDs in the loader prepares later modules for runtime rule
 * updates, feed updates, temporary bans, flow inspection, and statistics.
 */
struct xdp_shield_map_fds {
	int rule_map;
	int config_map;
	int default_policy_map;
	int src_ipv4_rule_map;
	int dst_ipv4_rule_map;
	int src_port_rule_map;
	int dst_port_rule_map;
	int protocol_rule_map;
	int src_cidr_rule_map;
	int dst_cidr_rule_map;
	int threat_feed_map;
	int whitelist_map;
	int temp_ban_map;
	int flow_map;
	int stats_map;
	int percpu_stats_map;
	int events_map;
	int honeypot_config_map;
	int honeypot_devmap;
	int canary_port_map;
	int honeypot_source_map;
	int honeypot_flow_map;
};

/*
 * Loader state for one XDP firewall instance.
 */
struct xs_loader {
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct xdp_shield_map_fds maps;
	int prog_fd;
	int ifindex;
	int honeypot_ifindex;
	__u32 xdp_flags;
	bool loaded;
	bool attached;
	bool honeypot_attached;
};

/*
 * Open, load, and discover the firewall BPF object.
 */
int load_firewall(struct xs_loader *loader, const char *object_path);

/*
 * Locate the XDP program inside an opened object.
 */
int find_program(struct xs_loader *loader);

/*
 * Locate all maps required by the firewall.
 */
int find_maps(struct xs_loader *loader);

/*
 * Attach the loaded XDP program to an interface by name.
 */
int attach_firewall(struct xs_loader *loader, const char *ifname, __u32 xdp_flags);

/*
 * Attach the same loaded XDP program to the honeypot return interface.
 */
int attach_firewall_honeypot(struct xs_loader *loader, const char *ifname,
			     __u32 xdp_flags);

/*
 * Detach the XDP program from its interface.
 */
int detach_firewall(struct xs_loader *loader);

/*
 * Detach any XDP program from an interface by name. This is useful when the
 * original attach process is no longer running.
 */
int detach_firewall_from_interface(const char *ifname, __u32 xdp_flags);

/*
 * Detach if needed and release all libbpf resources.
 */
void destroy_firewall(struct xs_loader *loader);

/*
 * Compatibility wrappers used by the current skeleton main.c.
 */
int xs_loader_open(struct xs_loader *loader, const char *object_path);
int xs_loader_load(struct xs_loader *loader);
int xs_loader_attach(struct xs_loader *loader, const char *ifname);
int xs_loader_detach(struct xs_loader *loader);
void xs_loader_close(struct xs_loader *loader);
int xs_loader_map_fd(const struct xs_loader *loader, const char *map_name);

#endif
