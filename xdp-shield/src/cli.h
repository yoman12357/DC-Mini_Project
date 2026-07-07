#ifndef XDP_SHIELD_CLI_H
#define XDP_SHIELD_CLI_H

#include "../bpf/common.h"
#include "config.h"
#include "loader.h"
#include "rules.h"

#define XDP_SHIELD_VERSION "0.1.0"
#define XDP_SHIELD_DEFAULT_OBJECT "bpf/firewall.bpf.o"
#define XDP_SHIELD_DEFAULT_CONFIG "/etc/xdp-shield/xdp-shield.conf"

enum xs_command {
	XS_CMD_NONE = 0,
	XS_CMD_RUN,
	XS_CMD_ATTACH,
	XS_CMD_DETACH,
	XS_CMD_RULE_ADD,
	XS_CMD_RULE_DELETE,
	XS_CMD_RULE_UPDATE,
	XS_CMD_RULE_ENABLE,
	XS_CMD_RULE_DISABLE,
	XS_CMD_RULE_LIST,
	XS_CMD_RULE_CLEAR,
	XS_CMD_CONFIG_LOAD,
	XS_CMD_CONFIG_SHOW,
	XS_CMD_CONFIG_SET,
	XS_CMD_VERSION,
	XS_CMD_HELP,
};

struct xs_cli_rule {
	struct xdp_shield_firewall_rule rule;
	__u32 rule_id;
	int has_rule;
};

struct xs_cli_args {
	enum xs_command command;
	const char *object_path;
	const char *config_path;
	const char *ifname;
	const char *config_name;
	const char *config_value;
	__u32 xdp_flags;
	__u32 detach_flags;
	int has_xdp_mode;
	struct xs_cli_rule rule;
};

/*
 * Parse command-line arguments into a structured request.
 */
int xs_cli_parse(int argc, char **argv, struct xs_cli_args *args);

/*
 * Execute a parsed request by delegating to loader, rules, and config modules.
 */
int xs_cli_execute(const struct xs_cli_args *args, struct xs_loader *loader,
		   struct xs_rule_manager *rules, struct xs_config *config);

/*
 * Print full usage information.
 */
void xs_cli_usage(const char *prog);

#endif
