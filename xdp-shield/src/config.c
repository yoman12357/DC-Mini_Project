#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>

#include "config.h"

#define CONFIG_LINE_MAX 512

static int parse_u64(const char *value, __u64 *out);
static int parse_canary_ports(struct xs_config *config, const char *value);
static int parse_mac_value(const char *value, struct xdp_shield_mac_addr *mac);

static char *trim(char *s)
{
	char *end;

	while (isspace((unsigned char)*s))
		s++;
	end = s + strlen(s);
	while (end > s && isspace((unsigned char)*(end - 1)))
		*--end = '\0';
	return s;
}

static int copy_config_string(char *dst, size_t dst_len, const char *value)
{
	if (!dst || !value || strlen(value) >= dst_len)
		return -EINVAL;
	strcpy(dst, value);
	return 0;
}

static int parse_bool_value(const char *value, bool *out)
{
	if (!strcasecmp(value, "true") || !strcasecmp(value, "yes") ||
	    !strcmp(value, "1")) {
		*out = true;
		return 0;
	}
	if (!strcasecmp(value, "false") || !strcasecmp(value, "no") ||
	    !strcmp(value, "0")) {
		*out = false;
		return 0;
	}
	return -EINVAL;
}

static int parse_u32_value(const char *value, __u32 *out)
{
	__u64 parsed;
	int err;

	err = parse_u64(value, &parsed);
	if (err || parsed > UINT32_MAX)
		return -EINVAL;
	*out = (__u32)parsed;
	return 0;
}

static int parse_xdp_mode_value(const char *value, __u32 *attach_flags,
				__u32 *detach_flags)
{
	if (!strcasecmp(value, "generic")) {
		*attach_flags = XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;
		*detach_flags = XDP_FLAGS_SKB_MODE;
		return 0;
	}
	if (!strcasecmp(value, "native")) {
		*attach_flags = XDP_FLAGS_DRV_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;
		*detach_flags = XDP_FLAGS_DRV_MODE;
		return 0;
	}
	return -EINVAL;
}

int xs_config_defaults(struct xs_config *config)
{
	if (!config)
		return -EINVAL;

	memset(config, 0, sizeof(*config));
	copy_config_string(config->object_path_buf, sizeof(config->object_path_buf),
			   "bpf/firewall.bpf.o");
	copy_config_string(config->rules_path_buf, sizeof(config->rules_path_buf),
			   "rules.conf");
	config->object_path = config->object_path_buf;
	config->rules_path = config->rules_path_buf;
	xs_config_runtime_defaults(&config->runtime);
	config->xdp_flags = XDP_SHIELD_ATTACH_FLAGS;
	config->detach_flags = XDP_SHIELD_DETACH_FLAGS;
	config->attach_skb_mode = false;
	config->log_sample_rate = 1;
	config->default_ban_seconds = 300;
	config->honeypot.redirect_tcp = 1;
	config->honeypot.honeypot_port = 22;
	config->honeypot.honeypot_mac.bytes[0] = 0x02;
	config->honeypot.honeypot_mac.bytes[5] = 0x02;
	config->honeypot.honeypot_mac.bytes[4] = 0x20;
	config->honeypot.redirect_duration_ns =
		(__u64)XDP_SHIELD_HONEYPOT_DEFAULT_SECONDS * 1000000000ULL;
	return 0;
}

int xs_config_load(struct xs_config *config, const char *path)
{
	char line[CONFIG_LINE_MAX];
	unsigned int line_no = 0;
	FILE *fp;

	if (!config)
		return -EINVAL;
	if (!path)
		return 0;

	fp = fopen(path, "r");
	if (!fp)
		return errno == ENOENT ? 0 : -errno;

	while (fgets(line, sizeof(line), fp)) {
		char *comment;
		char *key;
		char *value;
		int err = 0;

		line_no++;
		comment = strchr(line, '#');
		if (comment)
			*comment = '\0';
		key = trim(line);
		if (*key == '\0')
			continue;

		value = strchr(key, '=');
		if (!value) {
			fprintf(stderr, "config: %s:%u missing '='\n", path, line_no);
			fclose(fp);
			return -EINVAL;
		}
		*value++ = '\0';
		key = trim(key);
		value = trim(value);

		if (!strcmp(key, "interface") || !strcmp(key, "ifname")) {
			err = copy_config_string(config->ifname_buf,
						 sizeof(config->ifname_buf), value);
			config->ifname = config->ifname_buf;
		} else if (!strcmp(key, "object_path")) {
			err = copy_config_string(config->object_path_buf,
						 sizeof(config->object_path_buf), value);
			config->object_path = config->object_path_buf;
		} else if (!strcmp(key, "rules_path")) {
			err = copy_config_string(config->rules_path_buf,
						 sizeof(config->rules_path_buf), value);
			config->rules_path = config->rules_path_buf;
		} else if (!strcmp(key, "honeypot_enabled")) {
			bool enabled;

			err = parse_bool_value(value, &enabled);
			config->honeypot.enabled = enabled ? 1 : 0;
		} else if (!strcmp(key, "honeypot_ifname")) {
			err = copy_config_string(config->honeypot_ifname_buf,
						 sizeof(config->honeypot_ifname_buf), value);
			config->honeypot_ifname = config->honeypot_ifname_buf;
		} else if (!strcmp(key, "honeypot_ip")) {
			if (inet_pton(AF_INET, value,
				      &config->honeypot.honeypot_ipv4) != 1)
				err = -EINVAL;
		} else if (!strcmp(key, "honeypot_mac")) {
			err = parse_mac_value(value, &config->honeypot.honeypot_mac);
		} else if (!strcmp(key, "honeypot_port")) {
			__u32 parsed;

			err = parse_u32_value(value, &parsed);
			if (!err && (parsed == 0 || parsed > UINT16_MAX))
				err = -EINVAL;
			if (!err)
				config->honeypot.honeypot_port = (__u16)parsed;
		} else if (!strcmp(key, "honeypot_redirect_seconds")) {
			__u64 parsed;

			err = parse_u64(value, &parsed);
			if (!err)
				config->honeypot.redirect_duration_ns =
					parsed * 1000000000ULL;
		} else if (!strcmp(key, "canary_ports")) {
			err = parse_canary_ports(config, value);
		} else if (!strcmp(key, "xdp_mode")) {
			err = parse_xdp_mode_value(value, &config->xdp_flags,
						   &config->detach_flags);
		} else if (!strcmp(key, "attach_skb_mode")) {
			err = parse_bool_value(value, &config->attach_skb_mode);
			if (!err && config->attach_skb_mode)
				parse_xdp_mode_value("generic", &config->xdp_flags,
						     &config->detach_flags);
		} else if (!strcmp(key, "log_sample_rate")) {
			err = parse_u32_value(value, &config->log_sample_rate);
		} else if (!strcmp(key, "default_ban_seconds")) {
			err = parse_u32_value(value, &config->default_ban_seconds);
			if (!err)
				config->runtime.temp_ban_duration_ns =
					(__u64)config->default_ban_seconds * 1000000000ULL;
		} else if (!strcmp(key, "syn_threshold")) {
			err = parse_u32_value(value, &config->runtime.syn_flood_threshold);
		} else if (!strcmp(key, "udp_threshold")) {
			err = parse_u32_value(value, &config->runtime.udp_flood_threshold);
		} else if (!strcmp(key, "icmp_threshold")) {
			err = parse_u32_value(value, &config->runtime.icmp_flood_threshold);
		} else if (!strcmp(key, "port_scan_threshold")) {
			err = parse_u32_value(value, &config->runtime.port_scan_threshold);
		} else if (!strcmp(key, "connection_threshold")) {
			err = parse_u32_value(value, &config->runtime.connection_rate_threshold);
		} else if (!strcmp(key, "window_ms")) {
			__u64 parsed;

			err = parse_u64(value, &parsed);
			if (!err)
				config->runtime.detection_window_ns = parsed * 1000000ULL;
		} else if (!strcmp(key, "ban_seconds")) {
			__u64 parsed;

			err = parse_u64(value, &parsed);
			if (!err)
				config->runtime.temp_ban_duration_ns =
					parsed * 1000000000ULL;
		} else {
			fprintf(stderr, "config: %s:%u unknown key '%s'\n",
				path, line_no, key);
			fclose(fp);
			return -EINVAL;
		}

		if (err) {
			fprintf(stderr, "config: %s:%u invalid value for '%s'\n",
				path, line_no, key);
			fclose(fp);
			return err;
		}
	}

	fclose(fp);
	return 0;
}

static int parse_mac_value(const char *value, struct xdp_shield_mac_addr *mac)
{
	unsigned int bytes[6];
	int parsed;
	int i;

	if (!value || !mac)
		return -EINVAL;

	parsed = sscanf(value, "%x:%x:%x:%x:%x:%x",
			&bytes[0], &bytes[1], &bytes[2],
			&bytes[3], &bytes[4], &bytes[5]);
	if (parsed != 6)
		return -EINVAL;

	memset(mac, 0, sizeof(*mac));
	for (i = 0; i < 6; i++) {
		if (bytes[i] > 0xff)
			return -EINVAL;
		mac->bytes[i] = (unsigned char)bytes[i];
	}
	return 0;
}

static int get_interface_mac(const char *ifname, struct xdp_shield_mac_addr *mac)
{
	struct ifreq ifr;
	int fd;
	int err = 0;

	if (!ifname || !mac)
		return -EINVAL;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -errno;

	memset(&ifr, 0, sizeof(ifr));
	if (strlen(ifname) >= sizeof(ifr.ifr_name)) {
		close(fd);
		return -ENAMETOOLONG;
	}
	strcpy(ifr.ifr_name, ifname);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr)) {
		err = -errno;
		close(fd);
		return err;
	}

	memset(mac, 0, sizeof(*mac));
	memcpy(mac->bytes, ifr.ifr_hwaddr.sa_data, sizeof(mac->bytes));
	close(fd);
	return 0;
}

static int parse_canary_ports(struct xs_config *config, const char *value)
{
	char buf[512];
	char *save = NULL;
	char *token;

	if (!config || !value || strlen(value) >= sizeof(buf))
		return -EINVAL;

	strcpy(buf, value);
	config->canary_port_count = 0;
	for (token = strtok_r(buf, ",", &save); token;
	     token = strtok_r(NULL, ",", &save)) {
		__u32 parsed;
		char *port = trim(token);

		if (*port == '\0')
			continue;
		if (config->canary_port_count >= XS_CONFIG_CANARY_PORTS_MAX)
			return -E2BIG;
		if (parse_u32_value(port, &parsed) || parsed == 0 ||
		    parsed > UINT16_MAX)
			return -EINVAL;
		config->canary_ports[config->canary_port_count++] =
			(__u16)parsed;
	}

	return 0;
}

int xs_config_runtime_defaults(struct xdp_shield_runtime_config *runtime)
{
	if (!runtime)
		return -EINVAL;

	memset(runtime, 0, sizeof(*runtime));
	runtime->syn_flood_threshold = XDP_SHIELD_SYN_FLOOD_THRESHOLD;
	runtime->udp_flood_threshold = XDP_SHIELD_UDP_FLOOD_THRESHOLD;
	runtime->icmp_flood_threshold = XDP_SHIELD_ICMP_FLOOD_THRESHOLD;
	runtime->port_scan_threshold = XDP_SHIELD_PORT_SCAN_THRESHOLD;
	runtime->connection_rate_threshold = XDP_SHIELD_CONNECTION_RATE_THRESHOLD;
	runtime->detection_window_ns = XDP_SHIELD_DETECTION_WINDOW_NS;
	runtime->temp_ban_duration_ns = XDP_SHIELD_TEMP_BAN_DURATION_NS;
	return 0;
}

int xs_config_update_map(int config_map_fd,
			 const struct xdp_shield_runtime_config *runtime)
{
	__u32 key = XDP_SHIELD_CONFIG_KEY;

	if (config_map_fd < 0 || !runtime)
		return -EINVAL;
	if (bpf_map_update_elem(config_map_fd, &key, runtime, BPF_ANY))
		return errno ? -errno : -EINVAL;
	return 0;
}

static int clear_canary_ports(int fd)
{
	for (;;) {
		struct xdp_shield_port_key key;
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

int xs_config_update_honeypot_maps(const struct xdp_shield_map_fds *maps,
				   struct xs_config *config)
{
	__u32 key = 0;
	size_t i;
	int err;

	if (!maps || !config)
		return -EINVAL;
	if (maps->honeypot_config_map < 0 || maps->honeypot_devmap < 0 ||
	    maps->canary_port_map < 0)
		return -EINVAL;

	if (!config->honeypot.enabled) {
		if (bpf_map_update_elem(maps->honeypot_config_map, &key,
					&config->honeypot, BPF_ANY))
			return errno ? -errno : -EINVAL;
		return 0;
	}

	if (!config->ifname || !config->honeypot_ifname ||
	    !config->honeypot.honeypot_ipv4)
		return -EINVAL;

	config->honeypot.external_ifindex = if_nametoindex(config->ifname);
	config->honeypot.honeypot_ifindex =
		if_nametoindex(config->honeypot_ifname);
	if (!config->honeypot.external_ifindex ||
	    !config->honeypot.honeypot_ifindex)
		return -ENODEV;

	err = get_interface_mac(config->ifname, &config->honeypot.external_mac);
	if (err)
		return err;
	if (bpf_map_update_elem(maps->honeypot_config_map, &key,
				&config->honeypot, BPF_ANY))
		return errno ? -errno : -EINVAL;

	key = XDP_SHIELD_DEVMAP_HONEYPOT_KEY;
	if (bpf_map_update_elem(maps->honeypot_devmap, &key,
				&config->honeypot.honeypot_ifindex, BPF_ANY))
		return errno ? -errno : -EINVAL;

	key = XDP_SHIELD_DEVMAP_EXTERNAL_KEY;
	if (bpf_map_update_elem(maps->honeypot_devmap, &key,
				&config->honeypot.external_ifindex, BPF_ANY))
		return errno ? -errno : -EINVAL;

	err = clear_canary_ports(maps->canary_port_map);
	if (err)
		return err;
	for (i = 0; i < config->canary_port_count; i++) {
		struct xdp_shield_port_key port_key = {
			.port = config->canary_ports[i],
		};
		__u8 enabled = 1;

		if (bpf_map_update_elem(maps->canary_port_map, &port_key,
					&enabled, BPF_ANY))
			return errno ? -errno : -EINVAL;
	}

	return 0;
}

static int open_config_map(const char *pin_dir)
{
	char path[256];

	if (!pin_dir)
		pin_dir = XDP_SHIELD_PIN_DIR;
	if (snprintf(path, sizeof(path), "%s/%s", pin_dir,
		     "xdp_shield_config_map") >= (int)sizeof(path))
		return -ENAMETOOLONG;
	return bpf_obj_get(path);
}

static int parse_u64(const char *value, __u64 *out)
{
	char *end = NULL;
	unsigned long long parsed;

	errno = 0;
	parsed = strtoull(value, &end, 10);
	if (errno || !end || *end != '\0')
		return -EINVAL;
	*out = (__u64)parsed;
	return 0;
}

int xs_config_set_pinned(const char *pin_dir, const char *name,
			 const char *value)
{
	struct xdp_shield_runtime_config runtime;
	__u32 key = XDP_SHIELD_CONFIG_KEY;
	__u64 parsed;
	int fd;
	int err;

	if (!name || !value)
		return -EINVAL;

	fd = open_config_map(pin_dir);
	if (fd < 0)
		return fd;

	err = bpf_map_lookup_elem(fd, &key, &runtime);
	if (err)
		xs_config_runtime_defaults(&runtime);

	err = parse_u64(value, &parsed);
	if (err) {
		close(fd);
		return err;
	}

	if (!strcmp(name, "syn_threshold"))
		runtime.syn_flood_threshold = (__u32)parsed;
	else if (!strcmp(name, "udp_threshold"))
		runtime.udp_flood_threshold = (__u32)parsed;
	else if (!strcmp(name, "icmp_threshold"))
		runtime.icmp_flood_threshold = (__u32)parsed;
	else if (!strcmp(name, "port_scan_threshold"))
		runtime.port_scan_threshold = (__u32)parsed;
	else if (!strcmp(name, "connection_threshold"))
		runtime.connection_rate_threshold = (__u32)parsed;
	else if (!strcmp(name, "window_ms"))
		runtime.detection_window_ns = parsed * 1000000ULL;
	else if (!strcmp(name, "ban_seconds"))
		runtime.temp_ban_duration_ns = parsed * 1000000000ULL;
	else {
		close(fd);
		return -EINVAL;
	}

	err = xs_config_update_map(fd, &runtime);
	close(fd);
	return err;
}

int xs_config_show_pinned(const char *pin_dir)
{
	struct xdp_shield_runtime_config runtime;
	__u32 key = XDP_SHIELD_CONFIG_KEY;
	int fd;

	fd = open_config_map(pin_dir);
	if (fd < 0)
		return fd;
	if (bpf_map_lookup_elem(fd, &key, &runtime))
		return errno ? -errno : -ENOENT;

	printf("syn_threshold=%u\n", runtime.syn_flood_threshold);
	printf("udp_threshold=%u\n", runtime.udp_flood_threshold);
	printf("icmp_threshold=%u\n", runtime.icmp_flood_threshold);
	printf("port_scan_threshold=%u\n", runtime.port_scan_threshold);
	printf("connection_threshold=%u\n", runtime.connection_rate_threshold);
	printf("window_ms=%llu\n",
	       (unsigned long long)(runtime.detection_window_ns / 1000000ULL));
	printf("ban_seconds=%llu\n",
	       (unsigned long long)(runtime.temp_ban_duration_ns / 1000000000ULL));
	close(fd);
	return 0;
}
