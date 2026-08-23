# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright (C) Landstrip Contributors

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man
CARGO ?= cargo
CARGO_ZIGBUILD ?= cargo-zigbuild
INSTALL ?= install
NODE ?= node
RM ?= rm -f

.PHONY: all check test clippy package install uninstall clean

all:
	$(CARGO) build

check:
	$(CARGO) test
	$(CARGO) clippy --all-targets

test:
	$(CARGO) test

clippy:
	$(CARGO) clippy --all-targets

package:
	CARGO_ZIGBUILD="$(CARGO_ZIGBUILD)" NODE="$(NODE)" ./scripts/package.sh $(PLATFORMS)

install:
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 755 target/release/landstrip $(DESTDIR)$(BINDIR)/landstrip

uninstall:
	$(RM) $(DESTDIR)$(BINDIR)/landstrip

clean:
	$(CARGO) clean
	$(RM) -r ../../artifacts
	$(RM) -r ../../npm/*/bin
