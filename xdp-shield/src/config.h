#ifndef XDP_SHIELD_CONFIG_H
#define XDP_SHIELD_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../bpf/common.h"
#include "loader.h"

#define XS_CONFIG_PATH_LEN 256
#define XS_CONFIG_IFNAME_LEN 64
#define XS_CONFIG_CANARY_PORTS_MAX 64

struct xs_config {
	const char *object_path;
	const char *ifname;
	const char *rules_path;
	const char *honeypot_ifname;
	char object_path_buf[XS_CONFIG_PATH_LEN];
	char ifname_buf[XS_CONFIG_IFNAME_LEN];
	char rules_path_buf[XS_CONFIG_PATH_LEN];
	char honeypot_ifname_buf[XS_CONFIG_IFNAME_LEN];
	struct xdp_shield_runtime_config runtime;
	struct xdp_shield_honeypot_config honeypot;
	__u16 canary_ports[XS_CONFIG_CANARY_PORTS_MAX];
	size_t canary_port_count;
	__u32 xdp_flags;
	__u32 detach_flags;
	bool attach_skb_mode;
	uint32_t log_sample_rate;
	uint32_t default_ban_seconds;
};

int xs_config_defaults(struct xs_config *config);
int xs_config_load(struct xs_config *config, const char *path);
int xs_config_runtime_defaults(struct xdp_shield_runtime_config *runtime);
int xs_config_update_map(int config_map_fd,
			 const struct xdp_shield_runtime_config *runtime);
int xs_config_update_honeypot_maps(const struct xdp_shield_map_fds *maps,
				   struct xs_config *config);
int xs_config_set_pinned(const char *pin_dir, const char *name,
			 const char *value);
int xs_config_show_pinned(const char *pin_dir);

#endif
