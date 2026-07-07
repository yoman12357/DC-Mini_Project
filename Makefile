CLANG ?= clang
CC ?= cc

BPF_CFLAGS ?= -O2 -g -target bpf -Wall -Wextra
USER_CFLAGS ?= -O2 -g -Wall -Wextra
ARCH_INCLUDE ?= /usr/include/$(shell uname -m)-linux-gnu
CPPFLAGS ?= -I./bpf -I./src -I$(ARCH_INCLUDE)
LDLIBS ?= -lbpf -lelf -lz

BPF_OBJ := bpf/firewall.bpf.o
USER_BIN := xdp-shield
USER_SRCS := $(wildcard src/*.c)
PREFIX ?= /usr/local
SYSCONFDIR ?= /etc
SYSTEMD_DIR ?= /etc/systemd/system

.PHONY: all clean attach detach datasets lab install install-systemd

all: $(BPF_OBJ) $(USER_BIN)

lab: BPF_CFLAGS += -DXDP_SHIELD_LAB_THRESHOLDS
lab: clean all

$(BPF_OBJ): bpf/firewall.bpf.c bpf/*.h bpf/parser.c bpf/rules.c bpf/engine.c
	$(CLANG) $(BPF_CFLAGS) $(CPPFLAGS) -c $< -o $@

$(USER_BIN): $(USER_SRCS) bpf/common.h
	$(CC) $(USER_CFLAGS) $(CPPFLAGS) $(USER_SRCS) $(LDLIBS) -o $@

attach: all
	@if [ -z "$(IFACE)" ]; then echo "usage: make attach IFACE=<interface>"; exit 1; fi
	sudo ./$(USER_BIN) firewall attach $(IFACE)

detach:
	@if [ -z "$(IFACE)" ]; then echo "usage: make detach IFACE=<interface>"; exit 1; fi
	sudo ip link set dev $(IFACE) xdp off

datasets:
	sh scripts/update-datasets.sh

install: all
	install -d $(DESTDIR)$(PREFIX)/sbin
	install -d $(DESTDIR)$(PREFIX)/lib/xdp-shield/bpf
	install -d $(DESTDIR)$(PREFIX)/lib/xdp-shield/datasets
	install -m 0755 $(USER_BIN) $(DESTDIR)$(PREFIX)/sbin/xdp-shield
	install -m 0644 $(BPF_OBJ) $(DESTDIR)$(PREFIX)/lib/xdp-shield/bpf/firewall.bpf.o
	install -m 0644 rules.conf $(DESTDIR)$(PREFIX)/lib/xdp-shield/rules.conf
	cp -R datasets/. $(DESTDIR)$(PREFIX)/lib/xdp-shield/datasets/

install-systemd: install
	install -d $(DESTDIR)$(SYSCONFDIR)/xdp-shield
	install -d $(DESTDIR)$(SYSTEMD_DIR)
	install -m 0644 xdp-shield.conf $(DESTDIR)$(SYSCONFDIR)/xdp-shield/xdp-shield.conf
	install -m 0644 packaging/systemd/xdp-shield.env $(DESTDIR)$(SYSCONFDIR)/xdp-shield/xdp-shield.env
	install -m 0644 packaging/systemd/xdp-shield.service $(DESTDIR)$(SYSTEMD_DIR)/xdp-shield.service

clean:
	rm -f $(BPF_OBJ) $(USER_BIN)
