#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <arpa/inet.h>

#include "cli.h"

static int parse_u32(const char *value, __u32 *out)
{
	char *end = NULL;
	unsigned long parsed;

	if (!value || !out)
		return -EINVAL;

	errno = 0;
	parsed = strtoul(value, &end, 10);
	if (errno || !end || *end != '\0' || parsed > UINT32_MAX)
		return -EINVAL;

	*out = (__u32)parsed;
	return 0;
}

static int parse_u16(const char *value, __u16 *out)
{
	__u32 parsed;
	int err;

	err = parse_u32(value, &parsed);
	if (err || parsed > UINT16_MAX)
		return -EINVAL;

	*out = (__u16)parsed;
	return 0;
}

static int parse_action(const char *value, __u8 *action)
{
	if (!strcasecmp(value, "allow")) {
		*action = XDP_SHIELD_RULE_ALLOW;
		return 0;
	}
	if (!strcasecmp(value, "drop")) {
		*action = XDP_SHIELD_RULE_DROP;
		return 0;
	}

	fprintf(stderr, "invalid rule action '%s' expected allow or drop\n", value);
	return -EINVAL;
}

static int parse_protocol(const char *value, __u8 *protocol)
{
	__u32 parsed;

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

	if (parse_u32(value, &parsed) || parsed > UINT8_MAX) {
		fprintf(stderr, "invalid protocol '%s'\n", value);
		return -EINVAL;
	}

	*protocol = (__u8)parsed;
	return 0;
}

static int parse_rule_type(const char *value, __u8 *type)
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

	fprintf(stderr, "invalid rule type '%s'\n", value);
	return -EINVAL;
}

static int parse_ipv4_cidr(const char *value, struct xdp_shield_ip_addr *addr,
			   __u8 *prefix_len)
{
	char buf[64];
	char *slash;
	__u32 prefix = XDP_SHIELD_IPV4_LPM_PREFIX_BITS;

	if (!value || !addr || !prefix_len)
		return -EINVAL;
	if (strlen(value) >= sizeof(buf))
		return -EINVAL;

	memset(addr, 0, sizeof(*addr));
	strcpy(buf, value);
	slash = strchr(buf, '/');
	if (slash) {
		*slash = '\0';
		if (parse_u32(slash + 1, &prefix) || prefix > 32) {
			fprintf(stderr, "invalid CIDR prefix '%s'\n", slash + 1);
			return -EINVAL;
		}
	}

	if (inet_pton(AF_INET, buf, &addr->ipv4) != 1) {
		fprintf(stderr, "invalid IPv4 address '%s'\n", buf);
		return -EINVAL;
	}

	addr->is_ipv6 = 0;
	*prefix_len = (__u8)prefix;
	return 0;
}

static void init_cli_args(struct xs_cli_args *args)
{
	memset(args, 0, sizeof(*args));
	args->command = XS_CMD_NONE;
	args->object_path = XDP_SHIELD_DEFAULT_OBJECT;
	args->config_path = XDP_SHIELD_DEFAULT_CONFIG;
	args->xdp_flags = XDP_SHIELD_ATTACH_FLAGS;
	args->detach_flags = XDP_SHIELD_DETACH_FLAGS;
	args->rule.rule.action = XDP_SHIELD_RULE_ALLOW;
	args->rule.rule.type = XDP_SHIELD_RULE_TYPE_COMPOSITE;
	args->rule.rule.protocol = XDP_SHIELD_PROTOCOL_ANY;
	args->rule.rule.enabled = 1;
	args->rule.rule.priority = XDP_SHIELD_RULE_PRIORITY_DEFAULT;
}

static int require_arg(int argc, char **argv, int index, const char *name)
{
	if (index < argc)
		return 0;

	fprintf(stderr, "missing %s\n", name);
	(void)argv;
	return -EINVAL;
}

static int parse_xdp_mode(const char *mode, __u32 *attach_flags, __u32 *detach_flags)
{
	if (!strcmp(mode, "generic")) {
		*attach_flags = XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;
		*detach_flags = XDP_FLAGS_SKB_MODE;
		return 0;
	}
	if (!strcmp(mode, "native")) {
		*attach_flags = XDP_FLAGS_DRV_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;
		*detach_flags = XDP_FLAGS_DRV_MODE;
		return 0;
	}

	fprintf(stderr, "invalid XDP mode '%s' expected generic or native\n", mode);
	return -EINVAL;
}

static int handle_attach(int argc, char **argv, int index, struct xs_cli_args *args)
{
	if (require_arg(argc, argv, index, "interface"))
		return -EINVAL;

	args->command = XS_CMD_ATTACH;
	args->ifname = argv[index];
	index++;
	while (index < argc) {
		if (!strcmp(argv[index], "--mode")) {
			if (require_arg(argc, argv, index + 1, "XDP mode"))
				return -EINVAL;
			if (parse_xdp_mode(argv[index + 1], &args->xdp_flags,
					   &args->detach_flags))
				return -EINVAL;
			args->has_xdp_mode = 1;
			index += 2;
			continue;
		}
		fprintf(stderr, "unexpected attach argument '%s'\n", argv[index]);
		return -EINVAL;
	}
	return 0;
}

static int handle_detach(int argc, char **argv, int index, struct xs_cli_args *args)
{
	if (require_arg(argc, argv, index, "interface"))
		return -EINVAL;

	args->command = XS_CMD_DETACH;
	args->ifname = argv[index];
	index++;
	while (index < argc) {
		if (!strcmp(argv[index], "--mode")) {
			if (require_arg(argc, argv, index + 1, "XDP mode"))
				return -EINVAL;
			if (parse_xdp_mode(argv[index + 1], &args->xdp_flags,
					   &args->detach_flags))
				return -EINVAL;
			args->has_xdp_mode = 1;
			index += 2;
			continue;
		}
		fprintf(stderr, "unexpected detach argument '%s'\n", argv[index]);
		return -EINVAL;
	}
	return 0;
}

static int handle_firewall(int argc, char **argv, int index, struct xs_cli_args *args)
{
	if (require_arg(argc, argv, index, "firewall command"))
		return -EINVAL;

	if (!strcmp(argv[index], "attach"))
		return handle_attach(argc, argv, index + 1, args);
	if (!strcmp(argv[index], "detach"))
		return handle_detach(argc, argv, index + 1, args);

	fprintf(stderr, "unknown firewall command '%s'\n", argv[index]);
	return -EINVAL;
}

static int parse_rule_options(int argc, char **argv, int index,
			      struct xs_cli_args *args, int id_required)
{
	enum {
		OPT_ID = 1000,
		OPT_ACTION,
		OPT_SRC,
		OPT_DST,
		OPT_SPORT,
		OPT_DPORT,
		OPT_PROTO,
		OPT_PRIORITY,
		OPT_TYPE,
		OPT_ENABLE,
		OPT_DISABLE,
	};
	static const struct option opts[] = {
		{ "id", required_argument, NULL, OPT_ID },
		{ "action", required_argument, NULL, OPT_ACTION },
		{ "src", required_argument, NULL, OPT_SRC },
		{ "dst", required_argument, NULL, OPT_DST },
		{ "sport", required_argument, NULL, OPT_SPORT },
		{ "dport", required_argument, NULL, OPT_DPORT },
		{ "proto", required_argument, NULL, OPT_PROTO },
		{ "priority", required_argument, NULL, OPT_PRIORITY },
		{ "type", required_argument, NULL, OPT_TYPE },
		{ "enable", no_argument, NULL, OPT_ENABLE },
		{ "disable", no_argument, NULL, OPT_DISABLE },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};
	int id_seen = 0;
	int c;

	optind = index;
	opterr = 0;
	while ((c = getopt_long(argc, argv, "", opts, NULL)) != -1) {
		switch (c) {
		case OPT_ID:
			if (parse_u32(optarg, &args->rule.rule.rule_id))
				return -EINVAL;
			args->rule.rule_id = args->rule.rule.rule_id;
			id_seen = 1;
			break;
		case OPT_ACTION:
			if (parse_action(optarg, &args->rule.rule.action))
				return -EINVAL;
			break;
		case OPT_SRC:
			if (parse_ipv4_cidr(optarg, &args->rule.rule.src_ip,
					    &args->rule.rule.src_prefix_len))
				return -EINVAL;
			break;
		case OPT_DST:
			if (parse_ipv4_cidr(optarg, &args->rule.rule.dst_ip,
					    &args->rule.rule.dst_prefix_len))
				return -EINVAL;
			break;
		case OPT_SPORT:
			if (parse_u16(optarg, &args->rule.rule.src_port))
				return -EINVAL;
			break;
		case OPT_DPORT:
			if (parse_u16(optarg, &args->rule.rule.dst_port))
				return -EINVAL;
			break;
		case OPT_PROTO:
			if (parse_protocol(optarg, &args->rule.rule.protocol))
				return -EINVAL;
			break;
		case OPT_PRIORITY:
			if (parse_u32(optarg, &args->rule.rule.priority))
				return -EINVAL;
			break;
		case OPT_TYPE:
			if (parse_rule_type(optarg, &args->rule.rule.type))
				return -EINVAL;
			break;
		case OPT_ENABLE:
			args->rule.rule.enabled = 1;
			break;
		case OPT_DISABLE:
			args->rule.rule.enabled = 0;
			break;
		case 'h':
			args->command = XS_CMD_HELP;
			return 0;
		default:
			fprintf(stderr, "invalid rule option near '%s'\n",
				argv[optind - 1]);
			return -EINVAL;
		}
	}

	if (optind != argc) {
		fprintf(stderr, "unexpected rule argument '%s'\n", argv[optind]);
		return -EINVAL;
	}
	if (id_required && !id_seen) {
		fprintf(stderr, "rule id is required\n");
		return -EINVAL;
	}

	args->rule.has_rule = 1;
	return 0;
}

static int parse_rule_id_arg(int argc, char **argv, int index,
			     struct xs_cli_args *args)
{
	if (require_arg(argc, argv, index, "rule id"))
		return -EINVAL;
	if (parse_u32(argv[index], &args->rule.rule_id)) {
		fprintf(stderr, "invalid rule id '%s'\n", argv[index]);
		return -EINVAL;
	}
	return 0;
}

static int handle_rule(int argc, char **argv, int index, struct xs_cli_args *args)
{
	const char *cmd;

	if (require_arg(argc, argv, index, "rule command"))
		return -EINVAL;

	cmd = argv[index];
	if (!strcmp(cmd, "add")) {
		args->command = XS_CMD_RULE_ADD;
		return parse_rule_options(argc, argv, index + 1, args, 1);
	}
	if (!strcmp(cmd, "update")) {
		args->command = XS_CMD_RULE_UPDATE;
		return parse_rule_options(argc, argv, index + 1, args, 1);
	}
	if (!strcmp(cmd, "delete")) {
		args->command = XS_CMD_RULE_DELETE;
		return parse_rule_id_arg(argc, argv, index + 1, args);
	}
	if (!strcmp(cmd, "enable")) {
		args->command = XS_CMD_RULE_ENABLE;
		return parse_rule_id_arg(argc, argv, index + 1, args);
	}
	if (!strcmp(cmd, "disable")) {
		args->command = XS_CMD_RULE_DISABLE;
		return parse_rule_id_arg(argc, argv, index + 1, args);
	}
	if (!strcmp(cmd, "list")) {
		args->command = XS_CMD_RULE_LIST;
		return 0;
	}
	if (!strcmp(cmd, "clear")) {
		args->command = XS_CMD_RULE_CLEAR;
		return 0;
	}

	fprintf(stderr, "unknown rule command '%s'\n", cmd);
	return -EINVAL;
}

static int handle_config(int argc, char **argv, int index, struct xs_cli_args *args)
{
	if (require_arg(argc, argv, index, "config command"))
		return -EINVAL;

	if (!strcmp(argv[index], "load")) {
		if (require_arg(argc, argv, index + 1, "config file"))
			return -EINVAL;
		args->command = XS_CMD_CONFIG_LOAD;
		args->config_path = argv[index + 1];
		return 0;
	}
	if (!strcmp(argv[index], "show")) {
		args->command = XS_CMD_CONFIG_SHOW;
		return 0;
	}
	if (!strcmp(argv[index], "set")) {
		if (require_arg(argc, argv, index + 1, "config name") ||
		    require_arg(argc, argv, index + 2, "config value"))
			return -EINVAL;
		args->command = XS_CMD_CONFIG_SET;
		args->config_name = argv[index + 1];
		args->config_value = argv[index + 2];
		return 0;
	}

	fprintf(stderr, "unknown config command '%s'\n", argv[index]);
	return -EINVAL;
}

static int handle_version(struct xs_cli_args *args)
{
	args->command = XS_CMD_VERSION;
	return 0;
}

static int handle_help(struct xs_cli_args *args)
{
	args->command = XS_CMD_HELP;
	return 0;
}

int xs_cli_parse(int argc, char **argv, struct xs_cli_args *args)
{
	int index = 1;

	if (!args)
		return -EINVAL;

	init_cli_args(args);

	if (argc <= 1) {
		args->command = XS_CMD_HELP;
		return 0;
	}

	while (index < argc) {
		if (!strcmp(argv[index], "--config") || !strcmp(argv[index], "-c")) {
			if (require_arg(argc, argv, index + 1, "config file"))
				return -EINVAL;
			args->config_path = argv[index + 1];
			index += 2;
			continue;
		}
		break;
	}

	if (index >= argc) {
		args->command = XS_CMD_HELP;
		return 0;
	}

	if (!strcmp(argv[index], "--help") || !strcmp(argv[index], "-h"))
		return handle_help(args);
	if (!strcmp(argv[index], "version") || !strcmp(argv[index], "--version"))
		return handle_version(args);

	if (!strcmp(argv[index], "attach"))
		return handle_attach(argc, argv, index + 1, args);
	if (!strcmp(argv[index], "detach"))
		return handle_detach(argc, argv, index + 1, args);
	if (!strcmp(argv[index], "firewall"))
		return handle_firewall(argc, argv, index + 1, args);
	if (!strcmp(argv[index], "rule"))
		return handle_rule(argc, argv, index + 1, args);
	if (!strcmp(argv[index], "config"))
		return handle_config(argc, argv, index + 1, args);
	if (!strcmp(argv[index], "help"))
		return handle_help(args);

	/* Backward-compatible bootstrap for the current skeleton main.c. */
	args->command = XS_CMD_RUN;
	args->ifname = argv[index];
	return 0;
}

static int print_rule_cb(const struct xdp_shield_rule_key *key,
			 const struct xdp_shield_firewall_rule *rule,
			 void *ctx)
{
	(void)ctx;
	printf("id=%u action=%s enabled=%u proto=%u sport=%u dport=%u priority=%u\n",
	       key->rule_id,
	       rule->action == XDP_SHIELD_RULE_DROP ? "drop" : "allow",
	       rule->enabled, rule->protocol, rule->src_port,
	       rule->dst_port, rule->priority);
	return 0;
}

static int handle_attach_exec(const struct xs_cli_args *args,
			      struct xs_loader *loader,
			      struct xs_config *config)
{
	int err;

	if (!loader || !config)
		return -EINVAL;

	err = load_firewall(loader, args->object_path);
	if (err)
		return err;

	config->ifname = args->ifname;
	return attach_firewall(loader, args->ifname, args->xdp_flags);
}

static int handle_detach_exec(const struct xs_cli_args *args,
			      struct xs_loader *loader)
{
	if (!loader)
		return -EINVAL;

	if (!loader->attached) {
		fprintf(stderr, "detach requires an attached loader context for %s\n",
			args->ifname);
		return -EINVAL;
	}

	return detach_firewall(loader);
}

static int handle_rule_exec(const struct xs_cli_args *args,
			    struct xs_rule_manager *rules)
{
	if (!rules)
		return -EINVAL;

	switch (args->command) {
	case XS_CMD_RULE_ADD:
		return rules_add(rules, &args->rule.rule);
	case XS_CMD_RULE_DELETE:
		return rules_delete(rules, args->rule.rule_id);
	case XS_CMD_RULE_UPDATE:
		return rules_update(rules, &args->rule.rule);
	case XS_CMD_RULE_ENABLE:
		return rules_enable(rules, args->rule.rule_id);
	case XS_CMD_RULE_DISABLE:
		return rules_disable(rules, args->rule.rule_id);
	case XS_CMD_RULE_LIST:
		return rules_list(rules, print_rule_cb, NULL);
	case XS_CMD_RULE_CLEAR:
		return rules_clear(rules);
	default:
		return -EINVAL;
	}
}

static int handle_config_exec(const struct xs_cli_args *args,
			      struct xs_config *config)
{
	if (!config)
		return -EINVAL;

	switch (args->command) {
	case XS_CMD_CONFIG_LOAD:
		return xs_config_load(config, args->config_path);
	case XS_CMD_CONFIG_SHOW:
		printf("object_path=%s\n", config->object_path);
		printf("ifname=%s\n", config->ifname ? config->ifname : "");
		printf("attach_skb_mode=%s\n", config->attach_skb_mode ? "true" : "false");
		printf("log_sample_rate=%u\n", config->log_sample_rate);
		printf("default_ban_seconds=%u\n", config->default_ban_seconds);
		return 0;
	case XS_CMD_CONFIG_SET:
		return xs_config_set_pinned(XDP_SHIELD_PIN_DIR,
					    args->config_name,
					    args->config_value);
	default:
		return -EINVAL;
	}
}

int xs_cli_execute(const struct xs_cli_args *args, struct xs_loader *loader,
		   struct xs_rule_manager *rules, struct xs_config *config)
{
	if (!args)
		return -EINVAL;

	switch (args->command) {
	case XS_CMD_ATTACH:
		return handle_attach_exec(args, loader, config);
	case XS_CMD_DETACH:
		return handle_detach_exec(args, loader);
	case XS_CMD_RULE_ADD:
	case XS_CMD_RULE_DELETE:
	case XS_CMD_RULE_UPDATE:
	case XS_CMD_RULE_ENABLE:
	case XS_CMD_RULE_DISABLE:
	case XS_CMD_RULE_LIST:
	case XS_CMD_RULE_CLEAR:
		return handle_rule_exec(args, rules);
	case XS_CMD_CONFIG_LOAD:
	case XS_CMD_CONFIG_SHOW:
	case XS_CMD_CONFIG_SET:
		return handle_config_exec(args, config);
	case XS_CMD_VERSION:
		printf("xdp-shield %s\n", XDP_SHIELD_VERSION);
		return 0;
	case XS_CMD_HELP:
		xs_cli_usage("xdp-shield");
		return 0;
	case XS_CMD_RUN:
	case XS_CMD_NONE:
	default:
		return 0;
	}
}

void xs_cli_usage(const char *prog)
{
	fprintf(stderr, "usage:\n");
	fprintf(stderr, "  %s [--config <file>] <command> [args]\n", prog);
	fprintf(stderr, "  %s attach <interface> [--mode generic|native]\n", prog);
	fprintf(stderr, "  %s detach <interface> [--mode generic|native]\n", prog);
	fprintf(stderr, "  %s firewall attach <interface> [--mode generic|native]\n", prog);
	fprintf(stderr, "  %s firewall detach <interface> [--mode generic|native]\n", prog);
	fprintf(stderr, "  %s rule add --id <id> [--action allow|drop] [--src ip[/cidr]] [--dst ip[/cidr]] [--sport port] [--dport port] [--proto any|tcp|udp|icmp|icmpv6] [--priority n] [--type exact|cidr|port|protocol|composite] [--disable]\n", prog);
	fprintf(stderr, "  %s rule update --id <id> [rule options]\n", prog);
	fprintf(stderr, "  %s rule delete <id>\n", prog);
	fprintf(stderr, "  %s rule enable <id>\n", prog);
	fprintf(stderr, "  %s rule disable <id>\n", prog);
	fprintf(stderr, "  %s rule list\n", prog);
	fprintf(stderr, "  %s rule clear\n", prog);
	fprintf(stderr, "  %s config load <file>\n", prog);
	fprintf(stderr, "  %s config show\n", prog);
	fprintf(stderr, "  %s config set <name> <value>\n", prog);
	fprintf(stderr, "  %s version\n", prog);
	fprintf(stderr, "  %s help\n", prog);
}
