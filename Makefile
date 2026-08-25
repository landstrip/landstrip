# SPDX-License-Identifier: Apache-2.0
# Copyright (C) Landstrip Contributors

CARGO ?= cargo
CARGO_ZIGBUILD ?= cargo-zigbuild
GH ?= gh
NODE ?= node
NPM ?= npm
VERSION ?=

.PHONY: default help all check ci test clippy package publish install uninstall clean

help: ## Show this help
	@awk -F ':[^#]*## ?' '/^[a-z_-]+:[^#]*##/{printf "  make %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

default: help

all: ## Build landstrip
	$(MAKE) -C packages/landstrip $@ CARGO="$(CARGO)" \
		CARGO_ZIGBUILD="$(CARGO_ZIGBUILD)" NODE="$(NODE)"

check: ## Run tests and lint with clippy
	$(MAKE) -C packages/landstrip $@ CARGO="$(CARGO)" \
		CARGO_ZIGBUILD="$(CARGO_ZIGBUILD)" NODE="$(NODE)"

test: ## Run tests
	$(MAKE) -C packages/landstrip $@ CARGO="$(CARGO)" \
		CARGO_ZIGBUILD="$(CARGO_ZIGBUILD)" NODE="$(NODE)"

clippy: ## Lint with clippy
	$(MAKE) -C packages/landstrip $@ CARGO="$(CARGO)" \
		CARGO_ZIGBUILD="$(CARGO_ZIGBUILD)" NODE="$(NODE)"

package: ## Package release binaries
	$(MAKE) -C packages/landstrip $@ CARGO="$(CARGO)" \
		CARGO_ZIGBUILD="$(CARGO_ZIGBUILD)" NODE="$(NODE)"

install: ## Install landstrip
	$(MAKE) -C packages/landstrip $@ CARGO="$(CARGO)" \
		CARGO_ZIGBUILD="$(CARGO_ZIGBUILD)" NODE="$(NODE)"

uninstall: ## Uninstall landstrip
	$(MAKE) -C packages/landstrip $@ CARGO="$(CARGO)" \
		CARGO_ZIGBUILD="$(CARGO_ZIGBUILD)" NODE="$(NODE)"

clean: ## Remove build artifacts
	$(MAKE) -C packages/landstrip $@ CARGO="$(CARGO)" \
		CARGO_ZIGBUILD="$(CARGO_ZIGBUILD)" NODE="$(NODE)"

ci: ## Run the local CI script
	CARGO="$(CARGO)" NODE="$(NODE)" NPM="$(NPM)" ./scripts/ci.sh

publish: ## Publish a release
	CARGO="$(CARGO)" GH="$(GH)" NODE="$(NODE)" NPM="$(NPM)" \
		./scripts/publish.sh "$(VERSION)"
