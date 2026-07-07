#ifndef XDP_SHIELD_FEED_H
#define XDP_SHIELD_FEED_H

#include "../bpf/common.h"

struct xs_feed {
	int feed_map_fd;
	const char *url;
	const char *cache_path;
};

int xs_feed_init(struct xs_feed *feed, int feed_map_fd);
int xs_feed_set_source(struct xs_feed *feed, const char *url,
		       const char *cache_path);
int xs_feed_update(struct xs_feed *feed);
int xs_feed_insert_entry(struct xs_feed *feed,
			 const struct xdp_shield_threat_feed_entry *entry,
			 __u32 reputation_score);

#endif
