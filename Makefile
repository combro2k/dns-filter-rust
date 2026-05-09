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

.PHONY: all build install install-binary install-config install-data install-systemd-service install-openrc-service clean

all: build

build:
	$(CARGO) build $(CARGO_BUILD_FLAGS)

install: install-binary install-config install-data

install-binary: build
	install -D -m 0755 target/$(BUILD_PROFILE)/$(BINARY_NAME) $(DESTDIR)$(BINDIR)/$(BINARY_NAME)

install-config:
	install -D -m 0644 $(CONFIG_SRC) $(DESTDIR)$(ETCDIR)/config.yaml

install-data:
	install -d -m 0755 $(DESTDIR)$(DATADIR)

install-systemd-service:
	install -D -m 0644 $(SYSTEMD_UNIT_SRC) $(DESTDIR)$(SYSTEMD_UNIT_DIR)/$(BINARY_NAME).service

install-openrc-service:
	install -D -m 0755 $(OPENRC_INIT_SRC) $(DESTDIR)$(OPENRC_INIT_DIR)/$(BINARY_NAME)

clean:
	$(CARGO) clean
