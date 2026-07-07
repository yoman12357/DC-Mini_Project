#ifndef XDP_SHIELD_LOGGER_H
#define XDP_SHIELD_LOGGER_H

#include <stdarg.h>

#include "../bpf/common.h"

struct xs_logger {
	int events_map_fd;
	void *ring_buffer;
};

void xs_log_info(const char *fmt, ...);
void xs_log_error(const char *fmt, ...);

int xs_logger_open(struct xs_logger *logger, int events_map_fd);
int xs_logger_poll(struct xs_logger *logger, int timeout_ms);
void xs_logger_close(struct xs_logger *logger);

#endif
