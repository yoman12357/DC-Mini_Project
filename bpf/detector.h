#ifndef XDP_SHIELD_BPF_DETECTOR_H
#define XDP_SHIELD_BPF_DETECTOR_H

#include "common.h"

struct xdp_shield_detection_result {
	__u8 action;
	__u32 reason;
};

int xs_run_detectors(const struct xdp_shield_packet *pkt,
		     struct xdp_shield_detection_result *result);

#endif
