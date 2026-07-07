#include <errno.h>
#include <string.h>

#include <bpf/bpf.h>

#include "feed.h"

int xs_feed_init(struct xs_feed *feed, int feed_map_fd)
{
	if (!feed || feed_map_fd < 0)
		return -EINVAL;

	memset(feed, 0, sizeof(*feed));
	feed->feed_map_fd = feed_map_fd;
	return 0;
}

int xs_feed_set_source(struct xs_feed *feed, const char *url,
		       const char *cache_path)
{
	if (!feed)
		return -EINVAL;

	feed->url = url;
	feed->cache_path = cache_path;
	return 0;
}

int xs_feed_update(struct xs_feed *feed)
{
	if (!feed)
		return -EINVAL;

	/* TODO: Download threat feed, parse entries, deduplicate, then update map. */
	return -ENOSYS;
}

int xs_feed_insert_entry(struct xs_feed *feed,
			 const struct xdp_shield_threat_feed_entry *entry,
			 __u32 reputation_score)
{
	struct xdp_shield_threat_feed_entry value;
	struct xdp_shield_lpm_key key;
	unsigned char *raw;

	if (!feed || !entry)
		return -EINVAL;

	memset(&key, 0, sizeof(key));
	memset(&value, 0, sizeof(value));
	raw = (unsigned char *)&entry->ip.ipv4;
	key.prefix_len = XDP_SHIELD_IPV4_LPM_PREFIX_BITS + 8;
	key.is_ipv6 = entry->ip.is_ipv6;
	key.addr[0] = raw[0];
	key.addr[1] = raw[1];
	key.addr[2] = raw[2];
	key.addr[3] = raw[3];
	value = *entry;
	value.reputation_score = reputation_score;

	return bpf_map_update_elem(feed->feed_map_fd, &key, &value, BPF_ANY);
}
