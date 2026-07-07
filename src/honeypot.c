#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>
#include <bpf/bpf.h>

#include "honeypot.h"
#include "logger.h"

#define HONEYPOT_LINE_MAX (64 * 1024)

static __u64 monotonic_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return 0;
	return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

static int json_get_string(const char *line, const char *field,
			   char *out, size_t out_len)
{
	const char *pos;
	const char *start;
	const char *end;
	char pattern[64];
	size_t len;

	if (!line || !field || !out || !out_len)
		return -EINVAL;
	if (snprintf(pattern, sizeof(pattern), "\"%s\":\"", field) >=
	    (int)sizeof(pattern))
		return -EINVAL;

	pos = strstr(line, pattern);
	if (!pos)
		return -ENOENT;
	start = pos + strlen(pattern);
	end = strchr(start, '"');
	if (!end)
		return -EINVAL;
	len = (size_t)(end - start);
	if (len >= out_len)
		return -ENAMETOOLONG;
	memcpy(out, start, len);
	out[len] = '\0';
	return 0;
}

static int is_promotable_event(const char *eventid)
{
	if (!eventid)
		return 0;
	if (!strcmp(eventid, "cowrie.login.failed"))
		return 1;
	if (!strcmp(eventid, "cowrie.login.success"))
		return 1;
	if (!strcmp(eventid, "cowrie.command.input"))
		return 1;
	if (!strcmp(eventid, "cowrie.session.file_download"))
		return 1;
	if (!strcmp(eventid, "cowrie.session.file_upload"))
		return 1;
	return 0;
}

static int promote_source(struct xs_honeypot_monitor *monitor,
			  const char *src_ip, const char *eventid)
{
	struct xdp_shield_temp_ban_entry ban = {};
	struct xdp_shield_ip_addr key = {};
	__u64 now_ns;

	if (!monitor || monitor->temp_ban_map_fd < 0 || !src_ip)
		return -EINVAL;
	if (inet_pton(AF_INET, src_ip, &key.ipv4) != 1)
		return -EINVAL;

	now_ns = monotonic_ns();
	if (!now_ns)
		return -errno;

	key.is_ipv6 = 0;
	ban.ip = key;
	ban.ban_timestamp_ns = now_ns;
	ban.expiration_timestamp_ns = now_ns + monitor->ban_duration_ns;
	ban.reason = XDP_SHIELD_BAN_REASON_HONEYPOT;

	if (bpf_map_update_elem(monitor->temp_ban_map_fd, &key, &ban, BPF_ANY))
		return errno ? -errno : -EINVAL;

	xs_log_info("honeypot promoted %s to temp-ban after %s", src_ip,
		    eventid ? eventid : "interaction");
	return 0;
}

static int handle_line(struct xs_honeypot_monitor *monitor, const char *line)
{
	char eventid[128];
	char src_ip[64];

	if (json_get_string(line, "eventid", eventid, sizeof(eventid)))
		return 0;
	if (!is_promotable_event(eventid))
		return 0;
	if (json_get_string(line, "src_ip", src_ip, sizeof(src_ip)))
		return 0;
	return promote_source(monitor, src_ip, eventid);
}

static int open_log_at_end(struct xs_honeypot_monitor *monitor)
{
	if (!monitor || !monitor->log_path)
		return -EINVAL;

	monitor->fp = fopen(monitor->log_path, "r");
	if (!monitor->fp)
		return -errno;
	if (fseek(monitor->fp, 0, SEEK_END)) {
		int err = -errno;

		fclose(monitor->fp);
		monitor->fp = NULL;
		return err;
	}
	return 0;
}

int xs_honeypot_monitor_open(struct xs_honeypot_monitor *monitor,
			     int temp_ban_map_fd, const char *log_path,
			     __u64 ban_duration_ns, bool enabled)
{
	int err;

	if (!monitor)
		return -EINVAL;

	memset(monitor, 0, sizeof(*monitor));
	monitor->temp_ban_map_fd = temp_ban_map_fd;
	monitor->log_path = log_path;
	monitor->ban_duration_ns = ban_duration_ns ?
		ban_duration_ns : XDP_SHIELD_TEMP_BAN_DURATION_NS;
	monitor->enabled = enabled;

	if (!enabled)
		return 0;

	err = open_log_at_end(monitor);
	if (err) {
		xs_log_error("honeypot monitor disabled: could not open %s: %s",
			     log_path ? log_path : "(null)", strerror(-err));
		monitor->enabled = false;
		return err;
	}

	xs_log_info("honeypot monitor watching %s", log_path);
	return 0;
}

int xs_honeypot_monitor_poll(struct xs_honeypot_monitor *monitor)
{
	char line[HONEYPOT_LINE_MAX];
	int err = 0;

	if (!monitor || !monitor->enabled)
		return 0;
	if (!monitor->fp) {
		err = open_log_at_end(monitor);
		if (err)
			return err;
	}

	while (fgets(line, sizeof(line), monitor->fp)) {
		err = handle_line(monitor, line);
		if (err)
			return err;
	}

	if (ferror(monitor->fp)) {
		err = -errno;
		clearerr(monitor->fp);
		return err;
	}

	clearerr(monitor->fp);
	return 0;
}

void xs_honeypot_monitor_close(struct xs_honeypot_monitor *monitor)
{
	if (!monitor)
		return;
	if (monitor->fp)
		fclose(monitor->fp);
	memset(monitor, 0, sizeof(*monitor));
}
