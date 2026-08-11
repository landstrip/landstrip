# SPDX-License-Identifier: Apache-2.0
# Copyright (C) Landstrip Contributors

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man
CARGO ?= cargo
CROSS ?= cross
GH ?= gh
NODE ?= node
NPM ?= npm
INSTALL ?= install
RM ?= rm -f

.PHONY: all check ci test clippy package publish install uninstall clean

all:
	$(CARGO) build

check:
	$(CARGO) test
	$(CARGO) clippy --all-targets

ci:
	CARGO="$(CARGO)" NODE="$(NODE)" NPM="$(NPM)" ./scripts/ci.sh

test:
	$(CARGO) test

clippy:
	$(CARGO) clippy --all-targets

package:
	CROSS="$(CROSS)" NODE="$(NODE)" ./scripts/package.sh $(PLATFORMS)

publish:
	CARGO="$(CARGO)" GH="$(GH)" NODE="$(NODE)" NPM="$(NPM)" \
		./scripts/publish.sh "$(VERSION)"

install:
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 755 target/release/landstrip $(DESTDIR)$(BINDIR)/landstrip

uninstall:
	$(RM) $(DESTDIR)$(BINDIR)/landstrip

clean:
	$(CARGO) clean
	$(RM) -r artifacts
	$(RM) -r npm/*/bin
