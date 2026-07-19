# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright (c) 2026 Jarkko Sakkinen

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man
CARGO ?= cargo
GH ?= gh
NODE ?= node
NPM ?= npm
INSTALL ?= install
RM ?= rm -f

.PHONY: all check test clippy publish install uninstall clean

all:
	$(CARGO) build

check:
	$(CARGO) build
	$(CARGO) test
	$(CARGO) clippy --all-targets

test:
	$(CARGO) test

clippy:
	$(CARGO) clippy --all-targets

publish:
	CARGO="$(CARGO)" GH="$(GH)" NODE="$(NODE)" NPM="$(NPM)" \
		./scripts/publish.sh "$(VERSION)"

install:
	$(CARGO) build --release
	$(INSTALL) -d "$(DESTDIR)$(BINDIR)" "$(DESTDIR)$(MANDIR)/man1"
	$(INSTALL) -m 755 target/release/landstrip "$(DESTDIR)$(BINDIR)/landstrip"
	$(INSTALL) -m 644 man/man1/landstrip.1 "$(DESTDIR)$(MANDIR)/man1/landstrip.1"

uninstall:
	$(RM) "$(DESTDIR)$(BINDIR)/landstrip" "$(DESTDIR)$(MANDIR)/man1/landstrip.1"

clean:
	$(CARGO) clean
