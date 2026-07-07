#include <errno.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "rules.h"

#define RULE_LINE_MAX 512

static int map_fd_valid(int fd)
{
	return fd >= 0;
}

static struct xdp_shield_rule_key rule_key(__u32 rule_id)
{
	struct xdp_shield_rule_key key = {
		.rule_id = rule_id,
	};

	return key;
}

static int manager_ready(const struct xs_rule_manager *manager)
{
	return manager && manager->initialized && map_fd_valid(manager->maps.rule_map);
}

static int all_rule_maps_valid(const struct xdp_shield_map_fds *maps)
{
	return map_fd_valid(maps->rule_map) &&
	       map_fd_valid(maps->src_ipv4_rule_map) &&
	       map_fd_valid(maps->dst_ipv4_rule_map) &&
	       map_fd_valid(maps->src_port_rule_map) &&
	       map_fd_valid(maps->dst_port_rule_map) &&
	       map_fd_valid(maps->protocol_rule_map) &&
	       map_fd_valid(maps->src_cidr_rule_map) &&
	       map_fd_valid(maps->dst_cidr_rule_map);
}

static int valid_action(__u8 action)
{
	return action == XDP_SHIELD_RULE_ALLOW ||
	       action == XDP_SHIELD_RULE_DROP;
}

static int valid_protocol(__u8 protocol)
{
	switch (protocol) {
	case XDP_SHIELD_PROTOCOL_ANY:
	case XDP_SHIELD_PROTO_ICMP:
	case XDP_SHIELD_PROTO_TCP:
	case XDP_SHIELD_PROTO_UDP:
	case XDP_SHIELD_PROTO_ICMPV6:
		return 1;
	default:
		return 0;
	}
}

static int valid_rule_type(__u8 type)
{
	switch (type) {
	case XDP_SHIELD_RULE_TYPE_EXACT:
	case XDP_SHIELD_RULE_TYPE_CIDR:
	case XDP_SHIELD_RULE_TYPE_PORT:
	case XDP_SHIELD_RULE_TYPE_PROTOCOL:
	case XDP_SHIELD_RULE_TYPE_COMPOSITE:
		return 1;
	default:
		return 0;
	}
}

static int valid_ipv4_addr(const struct xdp_shield_ip_addr *addr)
{
	if (!addr)
		return 0;
	return !addr->is_ipv6;
}

static int valid_prefix_len(__u8 prefix_len)
{
	return prefix_len <= XDP_SHIELD_IPV4_LPM_PREFIX_BITS;
}

static int rule_has_src_ip(const struct xdp_shield_firewall_rule *rule)
{
	return rule->src_ip.ipv4 != 0 || rule->src_prefix_len != 0;
}

static int rule_has_dst_ip(const struct xdp_shield_firewall_rule *rule)
{
	return rule->dst_ip.ipv4 != 0 || rule->dst_prefix_len != 0;
}

static int rule_has_src_port(const struct xdp_shield_firewall_rule *rule)
{
	return rule->src_port != XDP_SHIELD_PORT_ANY;
}

static int rule_has_dst_port(const struct xdp_shield_firewall_rule *rule)
{
	return rule->dst_port != XDP_SHIELD_PORT_ANY;
}

static int rule_has_protocol(const struct xdp_shield_firewall_rule *rule)
{
	return rule->protocol != XDP_SHIELD_PROTOCOL_ANY;
}

static int validate_rule(const struct xdp_shield_firewall_rule *rule)
{
	if (!rule)
		return -EINVAL;
	if (rule->rule_id >= XDP_SHIELD_MAX_RULES)
		return -ERANGE;
	if (!valid_action(rule->action))
		return -EINVAL;
	if (!valid_rule_type(rule->type))
		return -EINVAL;
	if (!valid_protocol(rule->protocol))
		return -EINVAL;
	if (!valid_ipv4_addr(&rule->src_ip) || !valid_ipv4_addr(&rule->dst_ip))
		return -EAFNOSUPPORT;
	if (!valid_prefix_len(rule->src_prefix_len) ||
	    !valid_prefix_len(rule->dst_prefix_len))
		return -ERANGE;
	if (rule->src_prefix_len == 0 && rule->src_ip.ipv4 != 0 &&
	    rule->type == XDP_SHIELD_RULE_TYPE_CIDR)
		return -EINVAL;
	if (rule->dst_prefix_len == 0 && rule->dst_ip.ipv4 != 0 &&
	    rule->type == XDP_SHIELD_RULE_TYPE_CIDR)
		return -EINVAL;
	if (rule->priority == 0)
		return -EINVAL;

	return 0;
}

static __u8 effective_prefix_len(__be32 addr, __u8 prefix_len)
{
	if (prefix_len)
		return prefix_len;
	if (addr)
		return XDP_SHIELD_IPV4_LPM_PREFIX_BITS;
	return 0;
}

static struct xdp_shield_rule_decision
rule_decision(const struct xdp_shield_firewall_rule *rule)
{
	struct xdp_shield_rule_decision decision = {
		.rule_id = rule->rule_id,
		.priority = rule->priority,
		.action = rule->action,
		.type = rule->type,
		.enabled = rule->enabled,
	};

	return decision;
}

static void fill_ipv4_lpm_key(struct xdp_shield_lpm_key *key,
			      __be32 addr, __u8 prefix_len)
{
	__u8 *raw = (__u8 *)&addr;

	memset(key, 0, sizeof(*key));
	key->prefix_len = 8 + prefix_len;
	key->is_ipv6 = 0;
	key->addr[0] = raw[0];
	key->addr[1] = raw[1];
	key->addr[2] = raw[2];
	key->addr[3] = raw[3];
}

static int update_decision_map(int fd, const void *key,
			       const struct xdp_shield_rule_decision *decision)
{
	struct xdp_shield_rule_decision existing;
	int err;

	if (!map_fd_valid(fd))
		return -EINVAL;

	errno = 0;
	err = bpf_map_lookup_elem(fd, key, &existing);
	if (!err && existing.enabled &&
	    existing.priority <= decision->priority)
		return 0;
	if (err && errno != ENOENT)
		return errno ? -errno : err;

	errno = 0;
	err = bpf_map_update_elem(fd, key, decision, BPF_ANY);
	return err ? (errno ? -errno : err) : 0;
}

static int delete_map_elem(int fd, const void *key)
{
	int err;

	if (!map_fd_valid(fd))
		return 0;

	errno = 0;
	err = bpf_map_delete_elem(fd, key);
	if (!err || errno == ENOENT)
		return 0;
	return errno ? -errno : err;
}

static int install_rule_indexes(struct xs_rule_manager *manager,
				const struct xdp_shield_firewall_rule *rule)
{
	struct xdp_shield_rule_decision decision = rule_decision(rule);
	int err;

	if (!rule->enabled)
		return 0;

	if (rule_has_src_ip(rule)) {
		__u8 prefix_len = effective_prefix_len(rule->src_ip.ipv4,
						       rule->src_prefix_len);

		if (prefix_len == XDP_SHIELD_IPV4_LPM_PREFIX_BITS) {
			struct xdp_shield_ipv4_key key = {
				.addr = rule->src_ip.ipv4,
			};

			err = update_decision_map(manager->maps.src_ipv4_rule_map,
						  &key, &decision);
			if (err)
				return err;
		} else {
			struct xdp_shield_lpm_key key;

			fill_ipv4_lpm_key(&key, rule->src_ip.ipv4,
					  prefix_len);
			err = update_decision_map(manager->maps.src_cidr_rule_map,
						  &key, &decision);
			if (err)
				return err;
		}
	}

	if (rule_has_dst_ip(rule)) {
		__u8 prefix_len = effective_prefix_len(rule->dst_ip.ipv4,
						       rule->dst_prefix_len);

		if (prefix_len == XDP_SHIELD_IPV4_LPM_PREFIX_BITS) {
			struct xdp_shield_ipv4_key key = {
				.addr = rule->dst_ip.ipv4,
			};

			err = update_decision_map(manager->maps.dst_ipv4_rule_map,
						  &key, &decision);
			if (err)
				return err;
		} else {
			struct xdp_shield_lpm_key key;

			fill_ipv4_lpm_key(&key, rule->dst_ip.ipv4,
					  prefix_len);
			err = update_decision_map(manager->maps.dst_cidr_rule_map,
						  &key, &decision);
			if (err)
				return err;
		}
	}

	if (rule_has_src_port(rule)) {
		struct xdp_shield_port_key key = {
			.port = rule->src_port,
		};

		err = update_decision_map(manager->maps.src_port_rule_map,
					  &key, &decision);
		if (err)
			return err;
	}

	if (rule_has_dst_port(rule)) {
		struct xdp_shield_port_key key = {
			.port = rule->dst_port,
		};

		err = update_decision_map(manager->maps.dst_port_rule_map,
					  &key, &decision);
		if (err)
			return err;
	}

	if (rule_has_protocol(rule)) {
		struct xdp_shield_protocol_key key = {
			.protocol = rule->protocol,
		};

		err = update_decision_map(manager->maps.protocol_rule_map,
					  &key, &decision);
		if (err)
			return err;
	}

	return 0;
}

static int clear_map(int fd)
{
	for (;;) {
		unsigned char key[sizeof(struct xdp_shield_lpm_key)] = {};
		int err;

		if (!map_fd_valid(fd))
			return 0;

		errno = 0;
		err = bpf_map_get_next_key(fd, NULL, key);
		if (err)
			return errno == ENOENT ? 0 : (errno ? -errno : err);

		err = delete_map_elem(fd, key);
		if (err && err != -ENOENT)
			return err;
	}
}

static int clear_rule_indexes(struct xs_rule_manager *manager)
{
	int err;

	err = clear_map(manager->maps.src_ipv4_rule_map);
	if (err)
		return err;
	err = clear_map(manager->maps.dst_ipv4_rule_map);
	if (err)
		return err;
	err = clear_map(manager->maps.src_port_rule_map);
	if (err)
		return err;
	err = clear_map(manager->maps.dst_port_rule_map);
	if (err)
		return err;
	err = clear_map(manager->maps.protocol_rule_map);
	if (err)
		return err;
	err = clear_map(manager->maps.src_cidr_rule_map);
	if (err)
		return err;
	return clear_map(manager->maps.dst_cidr_rule_map);
}

static int rebuild_rule_indexes(struct xs_rule_manager *manager)
{
	struct xdp_shield_rule_key key;
	struct xdp_shield_rule_key next_key;
	void *key_ptr = NULL;
	int err;

	err = clear_rule_indexes(manager);
	if (err)
		return err;

	for (;;) {
		struct xdp_shield_firewall_rule rule;

		errno = 0;
		err = bpf_map_get_next_key(manager->maps.rule_map, key_ptr,
					   &next_key);
		if (err)
			return errno == ENOENT ? 0 : (errno ? -errno : err);

		errno = 0;
		err = bpf_map_lookup_elem(manager->maps.rule_map, &next_key,
					  &rule);
		if (!err) {
			err = install_rule_indexes(manager, &rule);
			if (err)
				return err;
		} else if (errno != ENOENT) {
			return errno ? -errno : err;
		}

		key = next_key;
		key_ptr = &key;
	}
}

int rules_init(struct xs_rule_manager *manager,
	       const struct xdp_shield_map_fds *maps)
{
	if (!manager || !maps)
		return -EINVAL;
	if (!all_rule_maps_valid(maps))
		return -EINVAL;

	memset(manager, 0, sizeof(*manager));
	manager->maps = *maps;
	manager->initialized = 1;
	return 0;
}

static int open_pinned_map(const char *pin_dir, const char *name)
{
	char path[256];

	if (snprintf(path, sizeof(path), "%s/%s", pin_dir, name) >=
	    (int)sizeof(path))
		return -ENAMETOOLONG;
	return bpf_obj_get(path);
}

int rules_init_pinned(struct xs_rule_manager *manager, const char *pin_dir)
{
	struct xdp_shield_map_fds maps;

	if (!manager)
		return -EINVAL;
	if (!pin_dir)
		pin_dir = XDP_SHIELD_PIN_DIR;

	memset(&maps, -1, sizeof(maps));
	maps.rule_map = open_pinned_map(pin_dir, "xdp_shield_rule_map");
	maps.src_ipv4_rule_map = open_pinned_map(pin_dir, "xdp_shield_src_ipv4_rule_map");
	maps.dst_ipv4_rule_map = open_pinned_map(pin_dir, "xdp_shield_dst_ipv4_rule_map");
	maps.src_port_rule_map = open_pinned_map(pin_dir, "xdp_shield_src_port_rule_map");
	maps.dst_port_rule_map = open_pinned_map(pin_dir, "xdp_shield_dst_port_rule_map");
	maps.protocol_rule_map = open_pinned_map(pin_dir, "xdp_shield_protocol_rule_map");
	maps.src_cidr_rule_map = open_pinned_map(pin_dir, "xdp_shield_src_cidr_rule_map");
	maps.dst_cidr_rule_map = open_pinned_map(pin_dir, "xdp_shield_dst_cidr_rule_map");
	if (!all_rule_maps_valid(&maps))
		return -ENOENT;

	return rules_init(manager, &maps);
}

int rules_add(struct xs_rule_manager *manager,
	      const struct xdp_shield_firewall_rule *rule)
{
	struct xdp_shield_firewall_rule existing;
	struct xdp_shield_rule_key key;
	int err;

	if (!manager_ready(manager))
		return -EINVAL;

	err = validate_rule(rule);
	if (err)
		return err;

	key = rule_key(rule->rule_id);
	errno = 0;
	err = bpf_map_lookup_elem(manager->maps.rule_map, &key, &existing);
	if (!err)
		return -EEXIST;
	if (errno != ENOENT)
		return -errno;

	err = bpf_map_update_elem(manager->maps.rule_map, &key, rule, BPF_NOEXIST);
	if (err)
		return errno ? -errno : err;

	err = rebuild_rule_indexes(manager);
	if (err) {
		delete_map_elem(manager->maps.rule_map, &key);
		rebuild_rule_indexes(manager);
		return err;
	}

	return 0;
}

int rules_delete(struct xs_rule_manager *manager, __u32 rule_id)
{
	struct xdp_shield_firewall_rule rule;
	struct xdp_shield_rule_key key;
	int err;

	if (!manager_ready(manager))
		return -EINVAL;
	if (rule_id >= XDP_SHIELD_MAX_RULES)
		return -ERANGE;

	key = rule_key(rule_id);
	errno = 0;
	err = bpf_map_lookup_elem(manager->maps.rule_map, &key, &rule);
	if (err)
		return errno ? -errno : err;

	err = delete_map_elem(manager->maps.rule_map, &key);
	if (err)
		return err;
	return rebuild_rule_indexes(manager);
}

int rules_update(struct xs_rule_manager *manager,
		 const struct xdp_shield_firewall_rule *rule)
{
	struct xdp_shield_firewall_rule old_rule;
	struct xdp_shield_rule_key key;
	int err;

	if (!manager_ready(manager))
		return -EINVAL;

	err = validate_rule(rule);
	if (err)
		return err;

	key = rule_key(rule->rule_id);
	errno = 0;
	err = bpf_map_lookup_elem(manager->maps.rule_map, &key, &old_rule);
	if (err)
		return errno ? -errno : err;

	errno = 0;
	err = bpf_map_update_elem(manager->maps.rule_map, &key, rule, BPF_EXIST);
	if (err) {
		return errno ? -errno : err;
	}

	err = rebuild_rule_indexes(manager);
	if (err) {
		bpf_map_update_elem(manager->maps.rule_map, &key, &old_rule,
				    BPF_EXIST);
		rebuild_rule_indexes(manager);
		return err;
	}

	return 0;
}

int rules_enable(struct xs_rule_manager *manager, __u32 rule_id)
{
	struct xdp_shield_firewall_rule rule;
	int err;

	err = rules_lookup(manager, rule_id, &rule);
	if (err)
		return err;

	rule.enabled = 1;
	return rules_update(manager, &rule);
}

int rules_disable(struct xs_rule_manager *manager, __u32 rule_id)
{
	struct xdp_shield_firewall_rule rule;
	struct xdp_shield_rule_key key;
	int err;

	if (!manager_ready(manager))
		return -EINVAL;

	err = rules_lookup(manager, rule_id, &rule);
	if (err)
		return err;

	rule.enabled = 0;
	key = rule_key(rule_id);
	errno = 0;
	err = bpf_map_update_elem(manager->maps.rule_map, &key, &rule,
				  BPF_EXIST);
	if (err)
		return errno ? -errno : err;
	return rebuild_rule_indexes(manager);
}

int rules_lookup(struct xs_rule_manager *manager, __u32 rule_id,
		 struct xdp_shield_firewall_rule *rule)
{
	struct xdp_shield_rule_key key;

	if (!manager_ready(manager) || !rule)
		return -EINVAL;
	if (rule_id >= XDP_SHIELD_MAX_RULES)
		return -ERANGE;

	key = rule_key(rule_id);
	errno = 0;
	if (bpf_map_lookup_elem(manager->maps.rule_map, &key, rule))
		return errno ? -errno : -ENOENT;
	return 0;
}

int rules_list(struct xs_rule_manager *manager, xs_rule_list_cb cb, void *ctx)
{
	struct xdp_shield_rule_key key;
	struct xdp_shield_rule_key next_key;
	void *key_ptr = NULL;
	int err;

	if (!manager_ready(manager) || !cb)
		return -EINVAL;

	for (;;) {
		struct xdp_shield_firewall_rule rule;

		errno = 0;
		err = bpf_map_get_next_key(manager->maps.rule_map, key_ptr,
					   &next_key);
		if (err)
			return errno == ENOENT ? 0 : (errno ? -errno : err);

		errno = 0;
		err = bpf_map_lookup_elem(manager->maps.rule_map, &next_key,
					  &rule);
		if (!err) {
			err = cb(&next_key, &rule, ctx);
			if (err)
				return err;
		} else if (errno != ENOENT) {
			return errno ? -errno : err;
		}

		key = next_key;
		key_ptr = &key;
	}

	return 0;
}

int rules_clear(struct xs_rule_manager *manager)
{
	struct xdp_shield_rule_key key;
	int err;

	if (!manager_ready(manager))
		return -EINVAL;

	err = clear_rule_indexes(manager);
	if (err)
		return err;

	for (;;) {
		errno = 0;
		err = bpf_map_get_next_key(manager->maps.rule_map, NULL, &key);
		if (err)
			return errno == ENOENT ? 0 : (errno ? -errno : err);

		err = rules_delete(manager, key.rule_id);
		if (err && err != -ENOENT)
			return err;
	}
}

void rules_destroy(struct xs_rule_manager *manager)
{
	if (!manager)
		return;

	memset(manager, 0, sizeof(*manager));
}

static char *trim(char *s)
{
	char *end;

	while (isspace((unsigned char)*s))
		s++;
	end = s + strlen(s);
	while (end > s && isspace((unsigned char)*(end - 1)))
		*--end = '\0';
	return s;
}

static int parse_u32_value(const char *value, __u32 *out)
{
	char *end = NULL;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(value, &end, 10);
	if (errno || !end || *end != '\0' || parsed > UINT32_MAX)
		return -EINVAL;
	*out = (__u32)parsed;
	return 0;
}

static int parse_u16_value(const char *value, __u16 *out)
{
	__u32 parsed;

	if (parse_u32_value(value, &parsed) || parsed > UINT16_MAX)
		return -EINVAL;
	*out = (__u16)parsed;
	return 0;
}

static int parse_action_value(const char *value, __u8 *action)
{
	if (!strcasecmp(value, "allow")) {
		*action = XDP_SHIELD_RULE_ALLOW;
		return 0;
	}
	if (!strcasecmp(value, "drop")) {
		*action = XDP_SHIELD_RULE_DROP;
		return 0;
	}
	return -EINVAL;
}

static int parse_proto_value(const char *value, __u8 *protocol)
{
	if (!strcasecmp(value, "any")) {
		*protocol = XDP_SHIELD_PROTOCOL_ANY;
		return 0;
	}
	if (!strcasecmp(value, "icmp")) {
		*protocol = XDP_SHIELD_PROTO_ICMP;
		return 0;
	}
	if (!strcasecmp(value, "tcp")) {
		*protocol = XDP_SHIELD_PROTO_TCP;
		return 0;
	}
	if (!strcasecmp(value, "udp")) {
		*protocol = XDP_SHIELD_PROTO_UDP;
		return 0;
	}
	if (!strcasecmp(value, "icmpv6")) {
		*protocol = XDP_SHIELD_PROTO_ICMPV6;
		return 0;
	}
	return -EINVAL;
}

static int parse_type_value(const char *value, __u8 *type)
{
	if (!strcasecmp(value, "exact")) {
		*type = XDP_SHIELD_RULE_TYPE_EXACT;
		return 0;
	}
	if (!strcasecmp(value, "cidr")) {
		*type = XDP_SHIELD_RULE_TYPE_CIDR;
		return 0;
	}
	if (!strcasecmp(value, "port")) {
		*type = XDP_SHIELD_RULE_TYPE_PORT;
		return 0;
	}
	if (!strcasecmp(value, "protocol")) {
		*type = XDP_SHIELD_RULE_TYPE_PROTOCOL;
		return 0;
	}
	if (!strcasecmp(value, "composite")) {
		*type = XDP_SHIELD_RULE_TYPE_COMPOSITE;
		return 0;
	}
	return -EINVAL;
}

static int parse_ipv4_value(const char *value, struct xdp_shield_ip_addr *addr,
			    __u8 *prefix_len)
{
	char buf[64];
	char *slash;
	__u32 prefix = 32;

	if (strlen(value) >= sizeof(buf))
		return -EINVAL;

	strcpy(buf, value);
	slash = strchr(buf, '/');
	if (slash) {
		*slash = '\0';
		if (parse_u32_value(slash + 1, &prefix) || prefix > 32)
			return -EINVAL;
	}

	memset(addr, 0, sizeof(*addr));
	if (inet_pton(AF_INET, buf, &addr->ipv4) != 1)
		return -EINVAL;
	addr->is_ipv6 = 0;
	*prefix_len = (__u8)prefix;
	return 0;
}

static void init_file_rule(struct xdp_shield_firewall_rule *rule)
{
	memset(rule, 0, sizeof(*rule));
	rule->action = XDP_SHIELD_RULE_DROP;
	rule->type = XDP_SHIELD_RULE_TYPE_COMPOSITE;
	rule->protocol = XDP_SHIELD_PROTOCOL_ANY;
	rule->priority = XDP_SHIELD_RULE_PRIORITY_DEFAULT;
	rule->enabled = 1;
}

static int parse_rule_line(char *line, struct xdp_shield_firewall_rule *rule)
{
	char *save = NULL;
	char *token;
	int id_seen = 0;

	init_file_rule(rule);
	for (token = strtok_r(line, " \t", &save); token;
	     token = strtok_r(NULL, " \t", &save)) {
		char *key = token;
		char *value = strchr(token, '=');

		if (!value)
			return -EINVAL;
		*value++ = '\0';

		if (!strcasecmp(key, "id")) {
			if (parse_u32_value(value, &rule->rule_id))
				return -EINVAL;
			id_seen = 1;
		} else if (!strcasecmp(key, "action")) {
			if (parse_action_value(value, &rule->action))
				return -EINVAL;
		} else if (!strcasecmp(key, "src")) {
			if (parse_ipv4_value(value, &rule->src_ip,
					     &rule->src_prefix_len))
				return -EINVAL;
		} else if (!strcasecmp(key, "dst")) {
			if (parse_ipv4_value(value, &rule->dst_ip,
					     &rule->dst_prefix_len))
				return -EINVAL;
		} else if (!strcasecmp(key, "sport")) {
			if (parse_u16_value(value, &rule->src_port))
				return -EINVAL;
		} else if (!strcasecmp(key, "dport")) {
			if (parse_u16_value(value, &rule->dst_port))
				return -EINVAL;
		} else if (!strcasecmp(key, "proto")) {
			if (parse_proto_value(value, &rule->protocol))
				return -EINVAL;
		} else if (!strcasecmp(key, "priority")) {
			if (parse_u32_value(value, &rule->priority))
				return -EINVAL;
		} else if (!strcasecmp(key, "type")) {
			if (parse_type_value(value, &rule->type))
				return -EINVAL;
		} else if (!strcasecmp(key, "enabled")) {
			__u32 enabled;

			if (parse_u32_value(value, &enabled) || enabled > 1)
				return -EINVAL;
			rule->enabled = (__u8)enabled;
		} else {
			return -EINVAL;
		}
	}

	return id_seen ? 0 : -EINVAL;
}

int rules_load_file(struct xs_rule_manager *manager, const char *path)
{
	char line[RULE_LINE_MAX];
	unsigned int line_no = 0;
	FILE *fp;
	int err = 0;

	if (!manager_ready(manager) || !path)
		return -EINVAL;

	fp = fopen(path, "r");
	if (!fp)
		return errno == ENOENT ? 0 : -errno;

	while (fgets(line, sizeof(line), fp)) {
		struct xdp_shield_firewall_rule rule;
		char *comment;
		char *text;

		line_no++;
		comment = strchr(line, '#');
		if (comment)
			*comment = '\0';
		text = trim(line);
		if (*text == '\0')
			continue;

		err = parse_rule_line(text, &rule);
		if (!err)
			err = rules_add(manager, &rule);
		if (err == -EEXIST)
			err = rules_update(manager, &rule);
		if (err) {
			fprintf(stderr, "rules: %s:%u invalid rule (%d)\n",
				path, line_no, err);
			break;
		}
	}

	fclose(fp);
	return err;
}

int xs_rules_init(struct xs_rule_store *store, int rule_map_fd)
{
	struct xdp_shield_map_fds maps;

	if (!store || rule_map_fd < 0)
		return -EINVAL;

	memset(store, 0, sizeof(*store));
	memset(&maps, -1, sizeof(maps));
	maps.rule_map = rule_map_fd;
	store->manager.maps = maps;
	store->manager.initialized = 1;
	return 0;
}

int xs_rules_add(struct xs_rule_store *store, __u32 id,
		 const struct xdp_shield_firewall_rule *rule)
{
	struct xdp_shield_firewall_rule copy;

	if (!store || !rule)
		return -EINVAL;

	copy = *rule;
	copy.rule_id = id;
	return rules_add(&store->manager, &copy);
}

int xs_rules_delete(struct xs_rule_store *store, __u32 id)
{
	if (!store)
		return -EINVAL;

	return rules_delete(&store->manager, id);
}

int xs_rules_flush(struct xs_rule_store *store)
{
	if (!store)
		return -EINVAL;

	return rules_clear(&store->manager);
}
