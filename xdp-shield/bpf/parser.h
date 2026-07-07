#ifndef XDP_SHIELD_BPF_PARSER_H
#define XDP_SHIELD_BPF_PARSER_H

#include <linux/bpf.h>

#include "common.h"

static __always_inline int parse_packet(struct xdp_md *ctx,
					struct xdp_shield_packet_info *pkt);

#endif
