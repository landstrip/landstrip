# SPDX-License-Identifier: Apache-2.0
# Copyright (C) Landstrip Contributors

CARGO ?= cargo
CARGO_ZIGBUILD ?= cargo-zigbuild
GH ?= gh
NODE ?= node
NPM ?= npm
VERSION ?=

.PHONY: all check ci test clippy package publish install uninstall clean

all check test clippy package install uninstall clean:
	$(MAKE) -C packages/landstrip $@ CARGO="$(CARGO)" \
		CARGO_ZIGBUILD="$(CARGO_ZIGBUILD)" NODE="$(NODE)"

ci:
	CARGO="$(CARGO)" NODE="$(NODE)" NPM="$(NPM)" ./scripts/ci.sh

publish:
	CARGO="$(CARGO)" GH="$(GH)" NODE="$(NODE)" NPM="$(NPM)" \
		./scripts/publish.sh "$(VERSION)"
