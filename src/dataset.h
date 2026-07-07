#ifndef XDP_SHIELD_DATASET_H
#define XDP_SHIELD_DATASET_H

#include "../bpf/common.h"
#include "loader.h"

#define XDP_SHIELD_DEFAULT_DATASET_DIR "datasets"

struct xs_dataset_loader {
	const char *dataset_dir;
	int threat_map_fd;
	int whitelist_map_fd;
};

/*
 * Initialize the local dataset loader from loaded BPF map descriptors.
 */
int dataset_init(struct xs_dataset_loader *loader,
		 const struct xdp_shield_map_fds *maps,
		 const char *dataset_dir);

/*
 * Load blacklist and whitelist datasets into their BPF maps.
 */
int dataset_load(struct xs_dataset_loader *loader);

/*
 * Clear dataset maps and reload all local dataset files.
 */
int dataset_reload(struct xs_dataset_loader *loader);

/*
 * Load all files under datasets/blacklist into the threat map.
 */
int dataset_load_blacklist(struct xs_dataset_loader *loader);

/*
 * Load all files under datasets/whitelist into the whitelist map.
 */
int dataset_load_whitelist(struct xs_dataset_loader *loader);

/*
 * Release dataset loader state. BPF map FDs remain owned by libbpf.
 */
void dataset_destroy(struct xs_dataset_loader *loader);

#endif
