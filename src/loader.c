#include <errno.h>
#include <net/if.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bpf/bpf.h>

#include "loader.h"
#include "logger.h"

struct required_map {
	const char *name;
	int *fd;
};

static void init_loader(struct xs_loader *loader)
{
	memset(loader, 0, sizeof(*loader));
	memset(&loader->maps, -1, sizeof(loader->maps));
	loader->prog_fd = -1;
	loader->ifindex = 0;
	loader->xdp_flags = XDP_SHIELD_ATTACH_FLAGS;
}

static int libbpf_ptr_err(const void *ptr)
{
	long err = libbpf_get_error(ptr);

	if (!ptr)
		return -ENOMEM;
	if (err)
		return (int)err;
	return 0;
}

static int map_fd_by_name(const struct xs_loader *loader, const char *map_name)
{
	struct bpf_map *map;
	int fd;

	if (!loader || !loader->obj || !map_name)
		return -EINVAL;

	map = bpf_object__find_map_by_name(loader->obj, map_name);
	if (!map) {
		xs_log_error("map lookup failure: missing map '%s'", map_name);
		return -ENOENT;
	}

	fd = bpf_map__fd(map);
	if (fd < 0) {
		xs_log_error("map lookup failure: map '%s' has invalid fd %d",
			     map_name, fd);
		return -EINVAL;
	}

	return fd;
}

static int pin_loaded_maps(struct xs_loader *loader)
{
	struct bpf_map *map;
	int err;

	err = mkdir(XDP_SHIELD_PIN_DIR, 0700);
	if (err && errno != EEXIST) {
		xs_log_error("map pin failure: could not create %s: %s",
			     XDP_SHIELD_PIN_DIR, strerror(errno));
		return -errno;
	}

	bpf_object__for_each_map(map, loader->obj) {
		char path[256];
		const char *name = bpf_map__name(map);

		if (snprintf(path, sizeof(path), "%s/%s", XDP_SHIELD_PIN_DIR,
			     name) >= (int)sizeof(path))
			return -ENAMETOOLONG;

		unlink(path);
		err = bpf_map__pin(map, path);
		if (err) {
			xs_log_error("map pin failure: could not pin %s: %s",
				     path, strerror(-err));
			return err;
		}
	}

	return 0;
}

/*
 * Locate all maps required by the kernel firewall and save their FDs for later
 * rule, feed, ban, flow, and statistics modules.
 */
int find_maps(struct xs_loader *loader)
{
	struct required_map maps[22];
	size_t i;

	if (!loader || !loader->obj)
		return -EINVAL;

	maps[0] = (struct required_map){ "xdp_shield_rule_map", &loader->maps.rule_map };
	maps[1] = (struct required_map){ "xdp_shield_config_map", &loader->maps.config_map };
	maps[2] = (struct required_map){ "xdp_shield_default_policy_map", &loader->maps.default_policy_map };
	maps[3] = (struct required_map){ "xdp_shield_src_ipv4_rule_map", &loader->maps.src_ipv4_rule_map };
	maps[4] = (struct required_map){ "xdp_shield_dst_ipv4_rule_map", &loader->maps.dst_ipv4_rule_map };
	maps[5] = (struct required_map){ "xdp_shield_src_port_rule_map", &loader->maps.src_port_rule_map };
	maps[6] = (struct required_map){ "xdp_shield_dst_port_rule_map", &loader->maps.dst_port_rule_map };
	maps[7] = (struct required_map){ "xdp_shield_protocol_rule_map", &loader->maps.protocol_rule_map };
	maps[8] = (struct required_map){ "xdp_shield_src_cidr_rule_map", &loader->maps.src_cidr_rule_map };
	maps[9] = (struct required_map){ "xdp_shield_dst_cidr_rule_map", &loader->maps.dst_cidr_rule_map };
	maps[10] = (struct required_map){ "xdp_shield_threat_feed_map", &loader->maps.threat_feed_map };
	maps[11] = (struct required_map){ "xdp_shield_whitelist_map", &loader->maps.whitelist_map };
	maps[12] = (struct required_map){ "xdp_shield_temp_ban_map", &loader->maps.temp_ban_map };
	maps[13] = (struct required_map){ "xdp_shield_flow_map", &loader->maps.flow_map };
	maps[14] = (struct required_map){ "xdp_shield_stats_map", &loader->maps.stats_map };
	maps[15] = (struct required_map){ "xdp_shield_percpu_stats_map", &loader->maps.percpu_stats_map };
	maps[16] = (struct required_map){ "xdp_shield_events", &loader->maps.events_map };
	maps[17] = (struct required_map){ "xdp_shield_honeypot_config_map", &loader->maps.honeypot_config_map };
	maps[18] = (struct required_map){ "xdp_shield_honeypot_devmap", &loader->maps.honeypot_devmap };
	maps[19] = (struct required_map){ "xdp_shield_canary_port_map", &loader->maps.canary_port_map };
	maps[20] = (struct required_map){ "xdp_shield_honeypot_source_map", &loader->maps.honeypot_source_map };
	maps[21] = (struct required_map){ "xdp_shield_honeypot_flow_map", &loader->maps.honeypot_flow_map };

	for (i = 0; i < sizeof(maps) / sizeof(maps[0]); i++) {
		int fd = map_fd_by_name(loader, maps[i].name);

		if (fd < 0)
			return fd;
		*maps[i].fd = fd;
	}

	return 0;
}

/*
 * Locate the firewall XDP program and mark it as an XDP program before load.
 */
int find_program(struct xs_loader *loader)
{
	if (!loader || !loader->obj)
		return -EINVAL;

	loader->prog = bpf_object__find_program_by_name(loader->obj,
							XDP_SHIELD_PROG_NAME);
	if (!loader->prog) {
		xs_log_error("program lookup failure: missing XDP program '%s'",
			     XDP_SHIELD_PROG_NAME);
		return -ENOENT;
	}

	bpf_program__set_type(loader->prog, BPF_PROG_TYPE_XDP);
	return 0;
}

/*
 * Open the compiled BPF object, find the firewall program, load it into the
 * kernel, and discover map file descriptors.
 */
int load_firewall(struct xs_loader *loader, const char *object_path)
{
	int err;

	if (!loader || !object_path)
		return -EINVAL;

	init_loader(loader);

	loader->obj = bpf_object__open_file(object_path, NULL);
	err = libbpf_ptr_err(loader->obj);
	if (err) {
		xs_log_error("object open failure: failed to open '%s': %s",
			     object_path, strerror(-err));
		loader->obj = NULL;
		return err;
	}

	err = find_program(loader);
	if (err)
		goto fail;

	err = bpf_object__load(loader->obj);
	if (err) {
		xs_log_error("program load failure: verifier rejected or failed to load '%s': %s",
			     object_path, strerror(-err));
		goto fail;
	}

	loader->loaded = true;
	loader->prog_fd = bpf_program__fd(loader->prog);
	if (loader->prog_fd < 0) {
		xs_log_error("program load failure: '%s' has invalid program fd %d",
			     XDP_SHIELD_PROG_NAME, loader->prog_fd);
		err = -EINVAL;
		goto fail;
	}

	err = find_maps(loader);
	if (err)
		goto fail;

	err = pin_loaded_maps(loader);
	if (err)
		goto fail;

	return 0;

fail:
	destroy_firewall(loader);
	return err;
}

/*
 * Attach the already-loaded XDP firewall to the selected interface.
 */
int attach_firewall(struct xs_loader *loader, const char *ifname, __u32 xdp_flags)
{
	int err;

	if (!loader || !ifname)
		return -EINVAL;
	if (!loader->loaded || loader->prog_fd < 0) {
		xs_log_error("attach failure: firewall object is not loaded");
		return -EINVAL;
	}
	if (loader->attached) {
		xs_log_error("attach failure: firewall is already attached");
		return -EBUSY;
	}

	loader->ifindex = if_nametoindex(ifname);
	if (!loader->ifindex) {
		err = errno ? -errno : -ENODEV;
		xs_log_error("interface lookup failure: unknown interface '%s': %s",
			     ifname, strerror(-err));
		return err;
	}

	loader->xdp_flags = xdp_flags;
	err = bpf_xdp_attach(loader->ifindex, loader->prog_fd, xdp_flags, NULL);
	if (err) {
		xs_log_error("attach failure: could not attach '%s' to %s: %s",
			     XDP_SHIELD_PROG_NAME, ifname, strerror(-err));
		return err;
	}

	loader->attached = true;
	return 0;
}

int attach_firewall_honeypot(struct xs_loader *loader, const char *ifname,
			     __u32 xdp_flags)
{
	int err;

	if (!loader || !ifname)
		return -EINVAL;
	if (!loader->loaded || loader->prog_fd < 0) {
		xs_log_error("attach failure: firewall object is not loaded");
		return -EINVAL;
	}
	if (loader->honeypot_attached) {
		xs_log_error("attach failure: honeypot interface is already attached");
		return -EBUSY;
	}

	loader->honeypot_ifindex = if_nametoindex(ifname);
	if (!loader->honeypot_ifindex) {
		err = errno ? -errno : -ENODEV;
		xs_log_error("interface lookup failure: unknown honeypot interface '%s': %s",
			     ifname, strerror(-err));
		return err;
	}

	err = bpf_xdp_attach(loader->honeypot_ifindex, loader->prog_fd,
			     xdp_flags, NULL);
	if (err) {
		xs_log_error("attach failure: could not attach '%s' to honeypot interface %s: %s",
			     XDP_SHIELD_PROG_NAME, ifname, strerror(-err));
		return err;
	}

	loader->honeypot_attached = true;
	return 0;
}

/*
 * Detach the firewall from the interface used during attach.
 */
int detach_firewall(struct xs_loader *loader)
{
	int err;

	if (!loader)
		return -EINVAL;
	if (loader->honeypot_attached) {
		err = bpf_xdp_detach(loader->honeypot_ifindex,
				     loader->xdp_flags, NULL);
		if (err) {
			xs_log_error("detach failure: could not detach XDP program from honeypot ifindex %d: %s",
				     loader->honeypot_ifindex, strerror(-err));
			return err;
		}
		loader->honeypot_attached = false;
		loader->honeypot_ifindex = 0;
	}
	if (!loader->attached)
		return 0;

	err = bpf_xdp_detach(loader->ifindex, loader->xdp_flags, NULL);
	if (err) {
		xs_log_error("detach failure: could not detach XDP program from ifindex %d: %s",
			     loader->ifindex, strerror(-err));
		return err;
	}

	loader->attached = false;
	loader->ifindex = 0;
	return 0;
}

/*
 * Detach an XDP program from an interface without requiring the original
 * loader context. This is the path used by a standalone detach command.
 */
int detach_firewall_from_interface(const char *ifname, __u32 xdp_flags)
{
	unsigned int ifindex;
	int err;

	if (!ifname)
		return -EINVAL;

	ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		err = errno ? -errno : -ENODEV;
		xs_log_error("interface lookup failure: unknown interface '%s': %s",
			     ifname, strerror(-err));
		return err;
	}

	err = bpf_xdp_detach(ifindex, xdp_flags, NULL);
	if (err) {
		xs_log_error("detach failure: could not detach XDP program from %s: %s",
			     ifname, strerror(-err));
		return err;
	}

	return 0;
}

/*
 * Release all resources. This function is idempotent and safe on partially
 * initialized loaders.
 */
void destroy_firewall(struct xs_loader *loader)
{
	if (!loader)
		return;

	detach_firewall(loader);
	bpf_object__close(loader->obj);
	init_loader(loader);
}

int xs_loader_open(struct xs_loader *loader, const char *object_path)
{
	int err;

	if (!loader || !object_path)
		return -EINVAL;

	init_loader(loader);
	loader->obj = bpf_object__open_file(object_path, NULL);
	err = libbpf_ptr_err(loader->obj);
	if (err) {
		xs_log_error("object open failure: failed to open '%s': %s",
			     object_path, strerror(-err));
		loader->obj = NULL;
		return err;
	}

	return find_program(loader);
}

int xs_loader_load(struct xs_loader *loader)
{
	int err;

	if (!loader || !loader->obj)
		return -EINVAL;

	err = bpf_object__load(loader->obj);
	if (err) {
		xs_log_error("program load failure: verifier rejected or load failed: %s",
			     strerror(-err));
		return err;
	}

	loader->loaded = true;
	loader->prog_fd = bpf_program__fd(loader->prog);
	if (loader->prog_fd < 0) {
		xs_log_error("program load failure: invalid program fd %d",
			     loader->prog_fd);
		return -EINVAL;
	}

	return find_maps(loader);
}

int xs_loader_attach(struct xs_loader *loader, const char *ifname)
{
	return attach_firewall(loader, ifname, XDP_SHIELD_ATTACH_FLAGS);
}

int xs_loader_detach(struct xs_loader *loader)
{
	return detach_firewall(loader);
}

void xs_loader_close(struct xs_loader *loader)
{
	destroy_firewall(loader);
}

int xs_loader_map_fd(const struct xs_loader *loader, const char *map_name)
{
	return map_fd_by_name(loader, map_name);
}
