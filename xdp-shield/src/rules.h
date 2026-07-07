#ifndef XDP_SHIELD_RULES_H
#define XDP_SHIELD_RULES_H

#include <stddef.h>

#include "../bpf/common.h"
#include "loader.h"

struct xs_rule_manager {
	struct xdp_shield_map_fds maps;
	int initialized;
};

typedef int (*xs_rule_list_cb)(const struct xdp_shield_rule_key *key,
			       const struct xdp_shield_firewall_rule *rule,
			       void *ctx);

/*
 * Initialize a rule manager from map FDs discovered by the loader.
 */
int rules_init(struct xs_rule_manager *manager,
	       const struct xdp_shield_map_fds *maps);

/*
 * Initialize a rule manager by opening maps pinned under bpffs.
 */
int rules_init_pinned(struct xs_rule_manager *manager, const char *pin_dir);

/*
 * Add a new validated firewall rule and install all required kernel indexes.
 */
int rules_add(struct xs_rule_manager *manager,
	      const struct xdp_shield_firewall_rule *rule);

/*
 * Delete a rule from the canonical rule map and all indexes derived from it.
 */
int rules_delete(struct xs_rule_manager *manager, __u32 rule_id);

/*
 * Replace an existing rule atomically from the rule manager's perspective.
 */
int rules_update(struct xs_rule_manager *manager,
		 const struct xdp_shield_firewall_rule *rule);

/*
 * Enable an existing rule and rebuild its indexes.
 */
int rules_enable(struct xs_rule_manager *manager, __u32 rule_id);

/*
 * Disable an existing rule and remove its active indexes.
 */
int rules_disable(struct xs_rule_manager *manager, __u32 rule_id);

/*
 * Look up one rule by ID from the canonical rule map.
 */
int rules_lookup(struct xs_rule_manager *manager, __u32 rule_id,
		 struct xdp_shield_firewall_rule *rule);

/*
 * Iterate every installed canonical rule.
 */
int rules_list(struct xs_rule_manager *manager, xs_rule_list_cb cb, void *ctx);

/*
 * Remove every installed rule and clear all rule indexes.
 */
int rules_clear(struct xs_rule_manager *manager);

/*
 * Load key=value rules from a local text file.
 */
int rules_load_file(struct xs_rule_manager *manager, const char *path);

/*
 * Release manager-owned state. This does not close BPF map FDs owned by libbpf.
 */
void rules_destroy(struct xs_rule_manager *manager);

/*
 * Compatibility wrapper retained for the existing skeleton main.c.
 */
struct xs_rule_store {
	struct xs_rule_manager manager;
};

int xs_rules_init(struct xs_rule_store *store, int rule_map_fd);
int xs_rules_add(struct xs_rule_store *store, __u32 id,
		 const struct xdp_shield_firewall_rule *rule);
int xs_rules_delete(struct xs_rule_store *store, __u32 id);
int xs_rules_flush(struct xs_rule_store *store);

#endif
