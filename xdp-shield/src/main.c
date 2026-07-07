#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>

#include "cli.h"
#include "config.h"
#include "dataset.h"
#include "loader.h"
#include "logger.h"
#include "rules.h"

static volatile sig_atomic_t exiting;

static void signal_handler(int signo)
{
	(void)signo;
	exiting = 1;
}

static void reset_stats(const struct xs_loader *loader)
{
	struct xdp_shield_stats_entry zero = {};
	__u32 key = 0;

	if (!loader || loader->maps.stats_map < 0)
		return;

	bpf_map_update_elem(loader->maps.stats_map, &key, &zero, BPF_ANY);
}

static void init_runtime_config(const struct xs_loader *loader,
				const struct xs_config *config)
{
	if (!loader || !config || loader->maps.config_map < 0)
		return;
	xs_config_update_map(loader->maps.config_map, &config->runtime);
}

static void print_stats(const struct xs_loader *loader)
{
	struct xdp_shield_stats_entry stats;
	__u32 key = 0;

	if (!loader || loader->maps.stats_map < 0)
		return;
	if (bpf_map_lookup_elem(loader->maps.stats_map, &key, &stats))
		return;

	printf("stats packets=%llu pass=%llu drop=%llu threat=%llu tempban=%llu rule=%llu honeypot=%llu canary=%llu\n",
	       (unsigned long long)stats.packets_processed,
	       (unsigned long long)stats.packets_accepted,
	       (unsigned long long)stats.packets_dropped,
	       (unsigned long long)stats.threat_feed_hits,
	       (unsigned long long)stats.temporary_ban_hits,
	       (unsigned long long)stats.rule_hits,
	       (unsigned long long)stats.honeypot_redirects,
	       (unsigned long long)stats.canary_hits);
	fflush(stdout);
}

static int run_attached(const struct xs_cli_args *args)
{
	struct xs_dataset_loader datasets = {};
	struct xs_logger logger = {};
	struct xs_rule_manager rules = {};
	struct xs_config config = {};
	struct xs_loader loader = {};
	__u32 attach_flags;
	int err;

	err = xs_config_defaults(&config);
	if (err)
		return err;
	err = xs_config_load(&config, args->config_path);
	if (err)
		return err;
	if (args->ifname)
		config.ifname = args->ifname;
	if (!config.ifname)
		return -EINVAL;
	attach_flags = args->has_xdp_mode ? args->xdp_flags : config.xdp_flags;

	err = load_firewall(&loader, config.object_path);
	if (err)
		return err;

	err = rules_init(&rules, &loader.maps);
	if (err)
		goto out_loader;
	init_runtime_config(&loader, &config);
	err = xs_config_update_honeypot_maps(&loader.maps, &config);
	if (err) {
		fprintf(stderr, "honeypot configuration failed: %d\n", err);
		goto out_loader;
	}
	rules_load_file(&rules, config.rules_path);

	err = dataset_init(&datasets, &loader.maps, NULL);
	if (!err)
		dataset_load(&datasets);
	reset_stats(&loader);

	err = xs_logger_open(&logger, loader.maps.events_map);
	if (err)
		memset(&logger, 0, sizeof(logger));

	err = attach_firewall(&loader, config.ifname, attach_flags);
	if (err)
		goto out_logger;
	if (config.honeypot.enabled) {
		err = attach_firewall_honeypot(&loader, config.honeypot_ifname,
					       attach_flags);
		if (err)
			goto out_logger;
	}

	printf("xdp-shield attached to %s. Press Ctrl+C to detach.\n",
	       config.ifname);
	if (config.honeypot.enabled)
		printf("honeypot redirect active on %s -> 10.200.0.2:%u\n",
		       config.honeypot_ifname, config.honeypot.honeypot_port);

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	while (!exiting) {
		if (logger.ring_buffer)
			xs_logger_poll(&logger, 1000);
		else
			sleep(1);
		print_stats(&loader);
	}

	err = detach_firewall(&loader);

out_logger:
	xs_logger_close(&logger);
	dataset_destroy(&datasets);
	rules_destroy(&rules);
out_loader:
	destroy_firewall(&loader);
	return err;
}

int main(int argc, char **argv)
{
	struct xs_cli_args args;
	int err;

	err = xs_cli_parse(argc, argv, &args);
	if (err) {
		xs_cli_usage(argv[0]);
		return 1;
	}

	if (args.command == XS_CMD_HELP || args.command == XS_CMD_VERSION) {
		return xs_cli_execute(&args, NULL, NULL, NULL) ? 1 : 0;
	}

	if (args.command == XS_CMD_RUN) {
		if (!args.ifname) {
			xs_cli_usage(argv[0]);
			return 1;
		}
		return run_attached(&args) ? 1 : 0;
	}

	if (args.command == XS_CMD_ATTACH) {
		return run_attached(&args) ? 1 : 0;
	}

	if (args.command == XS_CMD_DETACH) {
		return detach_firewall_from_interface(args.ifname,
						      args.detach_flags) ? 1 : 0;
	}

	switch (args.command) {
	case XS_CMD_RULE_ADD:
	case XS_CMD_RULE_DELETE:
	case XS_CMD_RULE_UPDATE:
	case XS_CMD_RULE_ENABLE:
	case XS_CMD_RULE_DISABLE:
	case XS_CMD_RULE_LIST:
	case XS_CMD_RULE_CLEAR: {
		struct xs_rule_manager rules;

		err = rules_init_pinned(&rules, XDP_SHIELD_PIN_DIR);
		if (err) {
			fprintf(stderr, "could not open pinned rule maps: %d\n", err);
			return 1;
		}
		return xs_cli_execute(&args, NULL, &rules, NULL) ? 1 : 0;
	}
	case XS_CMD_CONFIG_SET:
		return xs_config_set_pinned(XDP_SHIELD_PIN_DIR, args.config_name,
					    args.config_value) ? 1 : 0;
	case XS_CMD_CONFIG_SHOW:
		return xs_config_show_pinned(XDP_SHIELD_PIN_DIR) ? 1 : 0;
	default:
		break;
	}

	fprintf(stderr, "command requires a running control plane in a later phase\n");
	return 1;
}
