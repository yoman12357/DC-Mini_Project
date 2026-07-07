#ifndef XDP_SHIELD_HONEYPOT_H
#define XDP_SHIELD_HONEYPOT_H

#include <stdbool.h>
#include <stdio.h>

#include "../bpf/common.h"

struct xs_honeypot_monitor {
	const char *log_path;
	FILE *fp;
	int temp_ban_map_fd;
	__u64 ban_duration_ns;
	bool enabled;
};

int xs_honeypot_monitor_open(struct xs_honeypot_monitor *monitor,
			     int temp_ban_map_fd, const char *log_path,
			     __u64 ban_duration_ns, bool enabled);
int xs_honeypot_monitor_poll(struct xs_honeypot_monitor *monitor);
void xs_honeypot_monitor_close(struct xs_honeypot_monitor *monitor);

#endif
