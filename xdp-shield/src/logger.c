#include <errno.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include <bpf/libbpf.h>

#include "logger.h"

static void xs_vlog(FILE *stream, const char *level, const char *fmt, va_list ap)
{
	fprintf(stream, "%s: ", level);
	vfprintf(stream, fmt, ap);
	fprintf(stream, "\n");
}

void xs_log_info(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	xs_vlog(stdout, "info", fmt, ap);
	va_end(ap);
}

void xs_log_error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	xs_vlog(stderr, "error", fmt, ap);
	va_end(ap);
}

static const char *event_type_name(__u8 type)
{
	switch (type) {
	case XDP_SHIELD_EVENT_DROP:
		return "drop";
	case XDP_SHIELD_EVENT_TEMP_BAN:
		return "temp-ban";
	case XDP_SHIELD_EVENT_THREAT_HIT:
		return "threat";
	case XDP_SHIELD_EVENT_RULE_HIT:
		return "rule";
	case XDP_SHIELD_EVENT_HONEYPOT_REDIRECT:
		return "honeypot-redirect";
	case XDP_SHIELD_EVENT_CANARY_HIT:
		return "canary-hit";
	default:
		return "unknown";
	}
}

static const char *reason_name(__u32 reason)
{
	switch (reason) {
	case XDP_SHIELD_BAN_REASON_THREAT_FEED:
		return "threat-feed";
	case XDP_SHIELD_BAN_REASON_SYN_FLOOD:
		return "syn-flood";
	case XDP_SHIELD_BAN_REASON_UDP_FLOOD:
		return "udp-flood";
	case XDP_SHIELD_BAN_REASON_ICMP_FLOOD:
		return "icmp-flood";
	case XDP_SHIELD_BAN_REASON_PORT_SCAN:
		return "port-scan";
	case XDP_SHIELD_BAN_REASON_CONNECTION_RATE:
		return "connection-rate";
	case XDP_SHIELD_BAN_REASON_HONEYPOT:
		return "honeypot";
	case XDP_SHIELD_BAN_REASON_CANARY_PORT:
		return "canary-port";
	case XDP_SHIELD_BAN_REASON_MANUAL:
		return "manual-rule";
	default:
		return "unknown";
	}
}

static int handle_event(void *ctx, void *data, size_t len)
{
	const struct xdp_shield_event *event = data;
	char src[INET_ADDRSTRLEN] = "0.0.0.0";
	char dst[INET_ADDRSTRLEN] = "0.0.0.0";

	(void)ctx;
	if (len < sizeof(*event))
		return 0;

	inet_ntop(AF_INET, &event->src_ipv4, src, sizeof(src));
	inet_ntop(AF_INET, &event->dst_ipv4, dst, sizeof(dst));
	printf("event type=%s src=%s:%u dst=%s:%u proto=%u reason=%s\n",
	       event_type_name(event->event_type),
	       src, event->src_port, dst, event->dst_port,
	       event->protocol, reason_name(event->reason));
	fflush(stdout);
	return 0;
}

int xs_logger_open(struct xs_logger *logger, int events_map_fd)
{
	if (!logger)
		return -EINVAL;

	memset(logger, 0, sizeof(*logger));
	logger->events_map_fd = events_map_fd;
	if (events_map_fd < 0)
		return -EINVAL;

	logger->ring_buffer = ring_buffer__new(events_map_fd, handle_event,
					       logger, NULL);
	if (!logger->ring_buffer)
		return -ENOMEM;

	return libbpf_get_error(logger->ring_buffer);
}

int xs_logger_poll(struct xs_logger *logger, int timeout_ms)
{
	if (!logger || !logger->ring_buffer)
		return -EINVAL;

	return ring_buffer__poll(logger->ring_buffer, timeout_ms);
}

void xs_logger_close(struct xs_logger *logger)
{
	if (!logger)
		return;

	if (logger->ring_buffer)
		ring_buffer__free(logger->ring_buffer);
	memset(logger, 0, sizeof(*logger));
}
