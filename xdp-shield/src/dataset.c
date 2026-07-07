#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <sys/stat.h>

#include "dataset.h"

#define DATASET_LINE_MAX 256

struct dataset_entry {
	struct xdp_shield_lpm_key key;
	struct xdp_shield_threat_feed_entry value;
};

struct dataset_entries {
	struct dataset_entry *items;
	size_t count;
	size_t capacity;
};

static int map_fd_valid(int fd)
{
	return fd >= 0;
}

static char *trim_line(char *line)
{
	char *end;

	while (isspace((unsigned char)*line))
		line++;

	end = line + strlen(line);
	while (end > line && isspace((unsigned char)*(end - 1)))
		*--end = '\0';

	return line;
}

static int key_equal(const struct xdp_shield_lpm_key *a,
		     const struct xdp_shield_lpm_key *b)
{
	return a->prefix_len == b->prefix_len &&
	       a->is_ipv6 == b->is_ipv6 &&
	       memcmp(a->addr, b->addr, sizeof(a->addr)) == 0;
}

static int entry_seen(const struct dataset_entries *entries,
		      const struct xdp_shield_lpm_key *key)
{
	size_t i;

	for (i = 0; i < entries->count; i++) {
		if (key_equal(&entries->items[i].key, key))
			return 1;
	}

	return 0;
}

static int entries_push(struct dataset_entries *entries,
			const struct dataset_entry *entry)
{
	struct dataset_entry *next;
	size_t capacity;

	if (entry_seen(entries, &entry->key))
		return 0;

	if (entries->count == entries->capacity) {
		capacity = entries->capacity ? entries->capacity * 2 : 256;
		next = realloc(entries->items, capacity * sizeof(*next));
		if (!next)
			return -ENOMEM;
		entries->items = next;
		entries->capacity = capacity;
	}

	entries->items[entries->count++] = *entry;
	return 0;
}

static void entries_destroy(struct dataset_entries *entries)
{
	if (!entries)
		return;

	free(entries->items);
	memset(entries, 0, sizeof(*entries));
}

static int ipv4_host_bits_zero(__be32 addr, __u32 prefix_len)
{
	__u32 host = ntohl(addr);
	__u32 mask;

	if (prefix_len == 0)
		return host == 0;
	if (prefix_len == 32)
		return 1;

	mask = ~((1U << (32 - prefix_len)) - 1);
	return (host & ~mask) == 0;
}

static int ipv4_prefix_overlaps(__be32 addr, __u32 prefix_len,
				__u32 network, __u32 network_prefix_len)
{
	__u32 host = ntohl(addr);
	__u32 compare_len;
	__u32 mask;

	compare_len = prefix_len < network_prefix_len ?
		prefix_len : network_prefix_len;
	if (compare_len == 0)
		return 1;

	mask = ~((1U << (32 - compare_len)) - 1);
	return (host & mask) == (network & mask);
}

static int ipv4_prefix_is_public(__be32 addr, __u32 prefix_len)
{
	static const struct {
		__u32 network;
		__u32 prefix_len;
	} non_public[] = {
		{ 0x00000000U, 8 },   /* "This network" */
		{ 0x0a000000U, 8 },   /* RFC1918 10.0.0.0/8 */
		{ 0x64400000U, 10 },  /* Carrier-grade NAT */
		{ 0x7f000000U, 8 },   /* Loopback */
		{ 0xa9fe0000U, 16 },  /* Link-local */
		{ 0xac100000U, 12 },  /* RFC1918 172.16.0.0/12 */
		{ 0xc0000000U, 24 },  /* IETF protocol assignments */
		{ 0xc0000200U, 24 },  /* TEST-NET-1 */
		{ 0xc0586300U, 24 },  /* IPv6 to IPv4 relay anycast */
		{ 0xc0a80000U, 16 },  /* RFC1918 192.168.0.0/16 */
		{ 0xc6120000U, 15 },  /* Benchmarking */
		{ 0xc6336400U, 24 },  /* TEST-NET-2 */
		{ 0xcb007100U, 24 },  /* TEST-NET-3 */
		{ 0xe0000000U, 4 },   /* Multicast */
		{ 0xf0000000U, 4 },   /* Reserved */
	};
	size_t i;

	for (i = 0; i < sizeof(non_public) / sizeof(non_public[0]); i++) {
		if (ipv4_prefix_overlaps(addr, prefix_len,
					 non_public[i].network,
					 non_public[i].prefix_len))
			return 0;
	}

	return 1;
}

static void fill_lpm_key(struct xdp_shield_lpm_key *key, __be32 addr,
			 __u32 prefix_len)
{
	unsigned char *raw = (unsigned char *)&addr;

	memset(key, 0, sizeof(*key));
	key->prefix_len = 8 + prefix_len;
	key->is_ipv6 = 0;
	key->addr[0] = raw[0];
	key->addr[1] = raw[1];
	key->addr[2] = raw[2];
	key->addr[3] = raw[3];
}

static int parse_dataset_entry(const char *text, __u32 source_id,
			       __u32 category, __u32 reputation_score,
			       int require_public, struct dataset_entry *entry)
{
	char buf[DATASET_LINE_MAX];
	char *slash;
	__u32 prefix_len = 32;
	__be32 addr;

	if (!text || !entry || strlen(text) >= sizeof(buf))
		return -EINVAL;

	strcpy(buf, text);
	slash = strchr(buf, '/');
	if (slash) {
		char *end = NULL;
		unsigned long parsed;

		*slash = '\0';
		errno = 0;
		parsed = strtoul(slash + 1, &end, 10);
		if (errno || !end || *end != '\0' || parsed > 32)
			return -EINVAL;
		prefix_len = (__u32)parsed;
	}

	if (inet_pton(AF_INET, buf, &addr) != 1)
		return -EINVAL;
	if (!ipv4_host_bits_zero(addr, prefix_len))
		return -EINVAL;
	if (require_public && !ipv4_prefix_is_public(addr, prefix_len))
		return -EINVAL;

	memset(entry, 0, sizeof(*entry));
	fill_lpm_key(&entry->key, addr, prefix_len);
	entry->value.ip.is_ipv6 = 0;
	entry->value.ip.ipv4 = addr;
	entry->value.reputation_score = reputation_score;
	entry->value.feed_source_id = source_id;
	entry->value.category = category;
	return 0;
}

static __u32 category_from_filename(const char *name)
{
	if (strstr(name, "tor"))
		return XDP_SHIELD_THREAT_TOR_EXIT;
	if (strstr(name, "malware"))
		return XDP_SHIELD_THREAT_MALWARE;
	if (strstr(name, "spam"))
		return XDP_SHIELD_THREAT_SPAM;
	if (strstr(name, "firehol"))
		return XDP_SHIELD_THREAT_ABUSE;
	return XDP_SHIELD_THREAT_UNKNOWN;
}

static __u32 source_id_from_name(const char *name)
{
	__u32 hash = 2166136261u;

	while (*name) {
		hash ^= (unsigned char)*name++;
		hash *= 16777619u;
	}

	return hash;
}

static int read_dataset_file(const char *path, const char *name,
			     __u32 reputation_score, __u32 category,
			     int require_public,
			     struct dataset_entries *entries)
{
	char line[DATASET_LINE_MAX];
	__u32 source_id = source_id_from_name(name);
	FILE *fp;
	int err = 0;

	fp = fopen(path, "r");
	if (!fp)
		return -errno;

	while (fgets(line, sizeof(line), fp)) {
		struct dataset_entry entry;
		char *comment;
		char *text;

		text = trim_line(line);
		if (*text == '\0' || *text == '#')
			continue;

		comment = strchr(text, '#');
		if (comment) {
			*comment = '\0';
			text = trim_line(text);
			if (*text == '\0')
				continue;
		}

		if (parse_dataset_entry(text, source_id, category,
					reputation_score, require_public,
					&entry))
			continue;

		err = entries_push(entries, &entry);
		if (err)
			break;
	}

	fclose(fp);
	return err;
}

static int read_dataset_dir(const char *path, int whitelist,
			    struct dataset_entries *entries)
{
	struct dirent *de;
	DIR *dir;

	dir = opendir(path);
	if (!dir)
		return errno == ENOENT ? 0 : -errno;

	while ((de = readdir(dir))) {
		struct stat st;
		char full_path[PATH_MAX];
		__u32 category;
		__u32 score;

		if (de->d_name[0] == '.')
			continue;

		if (snprintf(full_path, sizeof(full_path), "%s/%s", path,
			     de->d_name) >= (int)sizeof(full_path))
			continue;

		if (stat(full_path, &st) || !S_ISREG(st.st_mode))
			continue;

		category = whitelist ? XDP_SHIELD_THREAT_UNKNOWN :
			category_from_filename(de->d_name);
		score = whitelist ? 0 : XDP_SHIELD_MAX_REPUTATION_SCORE;

		if (read_dataset_file(full_path, de->d_name, score, category,
				      !whitelist, entries) == -ENOMEM) {
			closedir(dir);
			return -ENOMEM;
		}
	}

	closedir(dir);
	return 0;
}

static int clear_map(int fd)
{
	if (!map_fd_valid(fd))
		return -EINVAL;

	for (;;) {
		struct xdp_shield_lpm_key key;
		int err;

		errno = 0;
		err = bpf_map_get_next_key(fd, NULL, &key);
		if (err)
			return errno == ENOENT ? 0 : (errno ? -errno : err);

		errno = 0;
		err = bpf_map_delete_elem(fd, &key);
		if (err && errno != ENOENT)
			return errno ? -errno : err;
	}
}

static int load_entries_to_map(int map_fd, const struct dataset_entries *entries)
{
	size_t i;

	if (!map_fd_valid(map_fd))
		return -EINVAL;

	for (i = 0; i < entries->count; i++) {
		int err;

		errno = 0;
		err = bpf_map_update_elem(map_fd, &entries->items[i].key,
					  &entries->items[i].value, BPF_ANY);
		if (err)
			return errno ? -errno : err;
	}

	return 0;
}

static int dataset_subdir(char *buf, size_t len, const char *base,
			  const char *name)
{
	if (snprintf(buf, len, "%s/%s", base, name) >= (int)len)
		return -ENAMETOOLONG;
	return 0;
}

int dataset_init(struct xs_dataset_loader *loader,
		 const struct xdp_shield_map_fds *maps,
		 const char *dataset_dir)
{
	if (!loader || !maps)
		return -EINVAL;
	if (!map_fd_valid(maps->threat_feed_map) ||
	    !map_fd_valid(maps->whitelist_map))
		return -EINVAL;

	memset(loader, 0, sizeof(*loader));
	loader->dataset_dir = dataset_dir ? dataset_dir :
		XDP_SHIELD_DEFAULT_DATASET_DIR;
	loader->threat_map_fd = maps->threat_feed_map;
	loader->whitelist_map_fd = maps->whitelist_map;
	return 0;
}

int dataset_load_blacklist(struct xs_dataset_loader *loader)
{
	struct dataset_entries entries = {};
	char path[PATH_MAX];
	int err;

	if (!loader)
		return -EINVAL;

	err = dataset_subdir(path, sizeof(path), loader->dataset_dir,
			     "blacklist");
	if (err)
		return err;

	err = read_dataset_dir(path, 0, &entries);
	if (!err)
		err = load_entries_to_map(loader->threat_map_fd, &entries);

	entries_destroy(&entries);
	return err;
}

int dataset_load_whitelist(struct xs_dataset_loader *loader)
{
	struct dataset_entries entries = {};
	char path[PATH_MAX];
	int err;

	if (!loader)
		return -EINVAL;

	err = dataset_subdir(path, sizeof(path), loader->dataset_dir,
			     "whitelist");
	if (err)
		return err;

	err = read_dataset_dir(path, 1, &entries);
	if (!err)
		err = load_entries_to_map(loader->whitelist_map_fd, &entries);

	entries_destroy(&entries);
	return err;
}

int dataset_load(struct xs_dataset_loader *loader)
{
	return dataset_load_blacklist(loader);
}

int dataset_reload(struct xs_dataset_loader *loader)
{
	int err;

	if (!loader)
		return -EINVAL;

	err = clear_map(loader->threat_map_fd);
	if (err)
		return err;
	err = clear_map(loader->whitelist_map_fd);
	if (err)
		return err;

	return dataset_load(loader);
}

void dataset_destroy(struct xs_dataset_loader *loader)
{
	if (!loader)
		return;

	memset(loader, 0, sizeof(*loader));
}
