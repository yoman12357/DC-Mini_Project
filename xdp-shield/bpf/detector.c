#include <bpf/bpf_helpers.h>

#include "detector.h"
#include "maps.h"

static __always_inline int xs_detect_syn_flood(const struct xdp_shield_packet *pkt)
{
	/* TODO: Track SYN rates per source and destination. */
	return 0;
}

static __always_inline int xs_detect_udp_flood(const struct xdp_shield_packet *pkt)
{
	/* TODO: Track UDP packet and byte rates. */
	return 0;
}

static __always_inline int xs_detect_icmp_flood(const struct xdp_shield_packet *pkt)
{
	/* TODO: Track ICMP and ICMPv6 packet rates. */
	return 0;
}

static __always_inline int xs_detect_port_scan(const struct xdp_shield_packet *pkt)
{
	/* TODO: Track distinct destination ports per source. */
	return 0;
}

int xs_run_detectors(const struct xdp_shield_packet *pkt,
		     struct xdp_shield_detection_result *result)
{
	result->action = XDP_SHIELD_ACTION_PASS;
	result->reason = XDP_SHIELD_DROP_NONE;

	if (xs_detect_syn_flood(pkt) ||
	    xs_detect_udp_flood(pkt) ||
	    xs_detect_icmp_flood(pkt) ||
	    xs_detect_port_scan(pkt)) {
		result->action = XDP_SHIELD_ACTION_DROP;
		result->reason = XDP_SHIELD_DROP_DETECTOR;
	}

	return 0;
}
