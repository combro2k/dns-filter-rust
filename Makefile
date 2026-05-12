BINARY_NAME := dns-filter
CARGO ?= cargo
DESTDIR ?=
PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
ETCDIR ?= /etc/dns-filter
DATADIR ?= /var/lib/dns-filter
SYSTEMD_UNIT_DIR ?= /usr/lib/systemd/system
OPENRC_INIT_DIR ?= /etc/init.d
BUILD_PROFILE ?= release

ifeq ($(BUILD_PROFILE),release)
CARGO_BUILD_FLAGS := --release
else ifeq ($(BUILD_PROFILE),debug)
CARGO_BUILD_FLAGS :=
else
CARGO_BUILD_FLAGS := --profile $(BUILD_PROFILE)
endif

SYSTEMD_UNIT_SRC := package/systemd/dns-filter.service
OPENRC_INIT_SRC := package/openrc/dns-filter.openrc
CONFIG_SRC := package/config/config.example.yaml

# Auto-detect init system: systemd > openrc > none.
# Override with: make install INIT_SYSTEM=openrc
INIT_SYSTEM ?= $(shell \
	if command -v systemctl >/dev/null 2>&1; then echo systemd; \
	elif command -v openrc-run >/dev/null 2>&1; then echo openrc; \
	else echo none; fi)

.PHONY: all build install install-binary install-config install-data install-service install-systemd-service install-openrc-service clean

all: build

build:
	$(CARGO) build $(CARGO_BUILD_FLAGS)

install: install-binary install-config install-data install-service

install-binary: build
	install -D -m 0755 target/$(BUILD_PROFILE)/$(BINARY_NAME) $(DESTDIR)$(BINDIR)/$(BINARY_NAME)

install-config:
	install -d -m 0755 $(DESTDIR)$(ETCDIR)
	@if [ -f "$(DESTDIR)$(ETCDIR)/config.yaml" ]; then \
		install -m 0644 $(CONFIG_SRC) $(DESTDIR)$(ETCDIR)/config.yaml.dist; \
		echo "config.yaml already exists, installed new config as config.yaml.dist"; \
		echo "Differences:"; \
		diff -u $(DESTDIR)$(ETCDIR)/config.yaml $(DESTDIR)$(ETCDIR)/config.yaml.dist || true; \
		echo ""; \
		echo "To merge new defaults into your existing config, run:"; \
		echo "  dns-filter merge-config --overwrite --config $(ETCDIR)/config.yaml"; \
	else \
		install -m 0644 $(CONFIG_SRC) $(DESTDIR)$(ETCDIR)/config.yaml; \
	fi

install-data:
	install -d -m 0755 $(DESTDIR)$(DATADIR)

install-service:
ifeq ($(INIT_SYSTEM),systemd)
	@$(MAKE) install-systemd-service
else ifeq ($(INIT_SYSTEM),openrc)
	@$(MAKE) install-openrc-service
else
	@echo "No supported init system detected (INIT_SYSTEM=$(INIT_SYSTEM)), skipping service install."
	@echo "Install manually with: make install-systemd-service  or  make install-openrc-service"
endif

install-systemd-service:
	install -D -m 0644 $(SYSTEMD_UNIT_SRC) $(DESTDIR)$(SYSTEMD_UNIT_DIR)/$(BINARY_NAME).service

install-openrc-service:
	install -D -m 0755 $(OPENRC_INIT_SRC) $(DESTDIR)$(OPENRC_INIT_DIR)/$(BINARY_NAME)

clean:
	$(CARGO) clean
