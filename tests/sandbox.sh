#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright (c) 2026 Jarkko Sakkinen

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
bin=${LANDSTRIP_BIN:-$repo_root/target/debug/landstrip}
nc_cmd=${NC:-nc}

test -x "$bin" || {
    echo "missing landstrip binary: $bin" >&2
    exit 1
}
command -v "$nc_cmd" >/dev/null 2>&1 || {
    echo "missing nc command" >&2
    exit 1
}
nc_path=$(command -v "$nc_cmd")
case $(uname -s) in
    Darwin) sandbox_shell=/bin/bash ;;
    *) sandbox_shell=/bin/sh ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir -p "$tmp/allowed" "$tmp/denied"

pass=0
fail=0
port_base=$((49152 + ($$ % 10000)))

pass() {
    pass=$((pass + 1))
    printf 'PASS %s\n' "$1"
}

fail() {
    fail=$((fail + 1))
    printf 'FAIL %s -- %s\n' "$1" "$2"
}

expect_success() {
    name=$1
    shift
    set +e
    output=$({ "$@"; } 2>&1)
    status=$?
    set -e
    if [ "$status" -eq 0 ]; then
        pass "$name"
    else
        fail "$name" "status=$status output=$output"
    fi
}

expect_failure() {
    name=$1
    shift
    set +e
    output=$({ "$@"; } 2>&1)
    status=$?
    set -e
    if [ "$status" -ne 0 ]; then
        pass "$name"
    else
        fail "$name" "unexpected success output=$output"
    fi
}

next_port() {
    port_base=$((port_base + 1))
    if [ "$port_base" -gt 60999 ]; then
        port_base=49152
    fi
    printf '%s\n' "$port_base"
}

expect_listener_denied() {
    name=$1
    policy=$2
    port=$(next_port)
    out=$tmp/listener-denied-$port.out

    set +e
    "$bin" -p "$policy" "$nc_path" -l 127.0.0.1 "$port" >"$out" 2>&1 &
    pid=$!
    sleep 1
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null
        status=0
        running=1
    else
        wait "$pid"
        status=$?
        running=0
    fi
    set -e

    if [ "$running" -eq 0 ] && [ "$status" -ne 0 ]; then
        pass "$name"
    else
        output=$(while IFS= read -r line; do printf '%s ' "$line"; done < "$out")
        fail "$name" "listener still running or exited successfully on port=$port output=$output"
    fi
}

expect_listener_allowed() {
    name=$1
    policy=$2
    port=$(next_port)
    out=$tmp/listener-allowed-$port.out

    "$bin" -p "$policy" "$nc_path" -l 127.0.0.1 "$port" >"$out" 2>&1 &
    pid=$!
    sleep 1

    if ! kill -0 "$pid" 2>/dev/null; then
        set +e
        wait "$pid"
        status=$?
        set -e
        output=$(while IFS= read -r line; do printf '%s ' "$line"; done < "$out")
        fail "$name" "listener exited status=$status output=$output"
        return
    fi

    set +e
    "$nc_cmd" -z 127.0.0.1 "$port" >/dev/null 2>&1
    connect_status=$?
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null
    set -e

    if [ "$connect_status" -eq 0 ]; then
        pass "$name"
    else
        output=$(while IFS= read -r line; do printf '%s ' "$line"; done < "$out")
        fail "$name" "connect failed status=$connect_status output=$output"
    fi
}

policy_read=$tmp/policy-read.json
printf '{"network":{"allowNetwork":true},"filesystem":{"allowWrite":["%s/allowed"]}}' "$tmp" >"$policy_read"
expect_success "unrestricted read policy runs command" \
    "$bin" -p "$policy_read" "$sandbox_shell" -c 'printf ok\\n'

policy_fs=$tmp/policy-fs.json
printf '{"network":{"allowNetwork":true},"filesystem":{"allowWrite":["%s/allowed"],"denyRead":["/"],"allowRead":["/"]}}' "$tmp" >"$policy_fs"
expect_success "allowWrite permits configured root" \
    "$bin" -p "$policy_fs" "$sandbox_shell" -c ': > "$1/ok.txt"; test -f "$1/ok.txt"' _ "$tmp/allowed"
expect_failure "allowWrite denies other root" \
    "$bin" -p "$policy_fs" "$sandbox_shell" -c ': > "$1/nope.txt"' _ "$tmp/denied"

policy_netdeny=$tmp/policy-netdeny.json
printf '{"filesystem":{"denyRead":["/"],"allowRead":["/"]}}' >"$policy_netdeny"
expect_listener_denied "default network denies TCP listener" "$policy_netdeny"

policy_localbind=$tmp/policy-localbind.json
printf '{"network":{"allowLocalBinding":true},"filesystem":{"denyRead":["/"],"allowRead":["/"]}}' >"$policy_localbind"
expect_listener_allowed "allowLocalBinding permits localhost listener" "$policy_localbind"

policy_allownet=$tmp/policy-allownet.json
printf '{"network":{"allowNetwork":true},"filesystem":{"denyRead":["/"],"allowRead":["/"]}}' >"$policy_allownet"
expect_listener_allowed "allowNetwork permits localhost listener" "$policy_allownet"

printf 'SUMMARY pass=%s fail=%s tmp=%s\n' "$pass" "$fail" "$tmp"
[ "$fail" -eq 0 ]
