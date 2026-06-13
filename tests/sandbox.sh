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
os_name=$(uname -s)
case $os_name in
    Darwin) sandbox_shell=/bin/bash ;;
    *) sandbox_shell=/bin/sh ;;
esac

tmp=$(mktemp -d)
cleanup_dirs="$tmp"
cleanup() {
    for dir in $cleanup_dirs; do
        rm -rf "$dir"
    done
}
trap cleanup EXIT HUP INT TERM
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

expect_success_no_access_denied() {
    name=$1
    shift
    set +e
    output=$({ "$@"; } 2>&1)
    status=$?
    set -e
    if [ "$status" -eq 0 ] && ! printf '%s\n' "$output" | grep -q 'reason: AccessDenied'; then
        pass "$name"
    else
        fail "$name" "status=$status output=$output"
    fi
}

expect_success_access_denied() {
    name=$1
    expected_file=$2
    expected_operation=$3
    shift 3
    expected_real=$(CDPATH= cd -- "$(dirname -- "$expected_file")" && pwd -P)/$(basename -- "$expected_file")
    set +e
    output=$({ "$@"; } 2>&1)
    status=$?
    set -e
    has_expected_structured_file=0
    if printf '%s\n' "$output" | grep -F -q \
        -e "file: $expected_file" \
        -e "file: $expected_real"; then
        has_expected_structured_file=1
    fi
    has_expected_native_file=0
    if printf '%s\n' "$output" | grep -F -q \
        -e "$expected_file" \
        -e "$expected_real"; then
        has_expected_native_file=1
    fi
    has_structured_denial=0
    if [ "$has_expected_structured_file" -eq 1 ] && \
        printf '%s\n' "$output" | grep -F -q 'reason: AccessDenied' && \
        printf '%s\n' "$output" | grep -F -q "operation: $expected_operation"; then
        has_structured_denial=1
    fi
    has_native_denial=0
    if [ "$os_name" = Darwin ] && [ "$has_expected_native_file" -eq 1 ] && \
        printf '%s\n' "$output" | grep -F -q 'Operation not permitted'; then
        has_native_denial=1
    fi
    if [ "$status" -eq 0 ] && \
        { [ "$has_structured_denial" -eq 1 ] || [ "$has_native_denial" -eq 1 ]; }; then
        pass "$name"
    else
        fail "$name" "status=$status output=$output"
    fi
}

expect_error_fd_write_denied() {
    name=$1
    policy=$2
    denied_file=$3
    expected_real=$(CDPATH= cd -- "$(dirname -- "$denied_file")" && pwd -P)/$(basename -- "$denied_file")
    diag=$tmp/error-fd-write-denied.txt
    rm -f "$diag"
    set +e
    output=$("$bin" --error-fd 3 -p "$policy" "$sandbox_shell" -c \
        'if test -e /proc/self/fd/3; then echo fd3-inherited >&2; fi; : > "$1"; exit 1' \
        _ "$denied_file" 3>"$diag" 2>&1)
    status=$?
    set -e

    has_expected_file=0
    if grep -F -q \
        -e "file: $denied_file" \
        -e "file: $expected_real" \
        "$diag"; then
        has_expected_file=1
    fi

    if [ "$status" -ne 0 ] && [ "$has_expected_file" -eq 1 ] && \
        grep -F -q 'reason: AccessDenied' "$diag" && \
        grep -F -q 'type: filesystem' "$diag" && \
        grep -F -q 'operation: write' "$diag" && \
        grep -F -q 'mechanism: seccomp' "$diag" && \
        ! printf '%s\n' "$output" | grep -F -q 'fd3-inherited'; then
        pass "$name"
    else
        diag_output=$(cat "$diag" 2>/dev/null || true)
        fail "$name" "status=$status output=$output error_fd=$diag_output"
    fi
}

expect_failure_access_denied() {
    name=$1
    expected_file=$2
    shift 2
    expected_real=$(CDPATH= cd -- "$(dirname -- "$expected_file")" && pwd -P)/$(basename -- "$expected_file")
    set +e
    output=$({ "$@"; } 2>&1)
    status=$?
    set -e
    has_expected_file=0
    if printf '%s\n' "$output" | grep -F -q \
        -e "file: $expected_file" \
        -e "file: $expected_real" \
        -e "$expected_file" \
        -e "$expected_real"; then
        has_expected_file=1
    fi
    if [ "$status" -ne 0 ] && [ "$has_expected_file" -eq 1 ] && \
        printf '%s\n' "$output" | grep -F -q \
        -e 'reason: AccessDenied' \
        -e 'Operation not permitted'; then
        pass "$name"
    else
        fail "$name" "status=$status output=$output"
    fi
}

write_policy() {
    fmt=$1; shift
    file="$tmp/policy-next.json"
    printf "$fmt" "$@" >"$file"
    printf '%s\n' "$file"
}

test_ok() {
    name=$1
    policy=$2
    shift 2
    expect_success "$name" "$bin" -p "$policy" "$@"
}

test_fail() {
    name=$1
    policy=$2
    shift 2
    expect_failure "$name" "$bin" -p "$policy" "$@"
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

policy=$(write_policy '{"network":{"allowNetwork":true},"filesystem":{"allowWrite":["%s/allowed"]}}' "$tmp")
test_ok "unrestricted read policy runs tool" "$policy" "$sandbox_shell" -c 'printf ok\\n'

test_ok "sysctl read permits uname" "$policy" "$sandbox_shell" -c 'uname -s'

policy=$(write_policy '{"network":{"allowNetwork":true},"filesystem":{"allowWrite":["%s/allowed"],"denyRead":["/"],"allowRead":["/"]}}' "$tmp")
test_ok "allowWrite permits configured root" "$policy" "$sandbox_shell" -c ': > "$1/ok.txt"; test -f "$1/ok.txt"' _ "$tmp/allowed"
test_fail "allowWrite denies other root" "$policy" "$sandbox_shell" -c ': > "$1/nope.txt"' _ "$tmp/denied"

policy=$(write_policy '{"network":{"allowNetwork":true},"filesystem":{"allowWrite":["/dev/null"],"denyRead":["/"],"allowRead":["/"]}}')
test_ok "dev null read and write are permitted" "$policy" "$sandbox_shell" -c 'cat /dev/null >/dev/null'

policy=$(write_policy '{"network":{"allowNetwork":true},"filesystem":{"allowWrite":["%s/allowed"],"denyRead":["/"],"allowRead":["/"]}}' "$tmp")
expect_success_access_denied "successful write denial is reported" "/dev/null" write \
    "$bin" -p "$policy" "$sandbox_shell" -c 'cat /dev/null >/dev/null; true'
if [ "$os_name" = Linux ]; then
    expect_error_fd_write_denied "error fd reports write denial" \
        "$policy" "$tmp/denied/error-fd.txt"
fi

policy_yaml=$tmp/policy-fs.yaml
printf '%s\n' \
    'network:' \
    '  allowNetwork: true' \
    'filesystem:' \
    '  allowWrite: |' \
    "    $tmp/allowed" \
    '  denyRead: |' \
    '    /' \
    '  allowRead: |' \
    '    /' \
    >"$policy_yaml"
expect_success "yaml line policy permits configured root" \
    "$bin" --format yaml -p "$policy_yaml" "$sandbox_shell" -c ': > "$1/yaml-ok.txt"; test -f "$1/yaml-ok.txt"' _ "$tmp/allowed"
expect_failure "yaml line policy denies other root" \
    "$bin" --format yaml -p "$policy_yaml" "$sandbox_shell" -c ': > "$1/yaml-nope.txt"' _ "$tmp/denied"

expect_success "stdin yaml policy runs tool" \
    "$sandbox_shell" -c 'printf "%s\n" "network:" "  allowNetwork: true" "filesystem:" "  denyRead: |" "    /" "  allowRead: |" "    /" | "$1" --format yaml "$2" -c "printf ok\\n"' _ "$bin" "$sandbox_shell"

policy=$(write_policy '{"filesystem":{"denyRead":["/"],"allowRead":["/"]}}')
expect_listener_denied "default network denies TCP listener" "$policy"

policy=$(write_policy '{"network":{"allowLocalBinding":true},"filesystem":{"denyRead":["/"],"allowRead":["/"]}}')
expect_listener_allowed "allowLocalBinding permits localhost listener" "$policy"

policy=$(write_policy '{"network":{"allowNetwork":true},"filesystem":{"denyRead":["/"],"allowRead":["/"]}}')
expect_listener_allowed "allowNetwork permits localhost listener" "$policy"

policy=$(write_policy '{"network":{"allowNetwork":true},"filesystem":{"allowWrite":[""]}}')
test_fail "empty path is rejected" "$policy" "$sandbox_shell" -c 'printf ok\\n'

mkdir -p "$tmp/allowed/keep" "$tmp/allowed/sub"
policy=$(write_policy '{"network":{"allowNetwork":true},"filesystem":{"allowWrite":["%s/allowed"],"denyWrite":["%s/allowed/sub"],"denyRead":["/"],"allowRead":["/"]}}' "$tmp" "$tmp")
test_ok "denyWrite permits sibling write" "$policy" "$sandbox_shell" -c ': > "$1/ok.txt"; test -f "$1/ok.txt"' _ "$tmp/allowed/keep"
test_fail "denyWrite denies subtree write" "$policy" "$sandbox_shell" -c ': > "$1/nope.txt"' _ "$tmp/allowed/sub"

policy=$(write_policy '{"network":{"httpProxyPort":0},"filesystem":{"denyRead":["/"],"allowRead":["/"]}}')
test_fail "httpProxyPort zero is rejected" "$policy" "$sandbox_shell" -c 'printf ok\\n'

policy=$(write_policy '{"network":{"allowNetwork":true},"filesystem":{"allowWrite":["%s/allowed"]}}' "$tmp")
printf '{bad' >"$policy"
test_fail "malformed JSON policy is rejected" "$policy" "$sandbox_shell" -c 'printf ok\\n'

policy=$(write_policy '{"network":{"socksProxyPort":0},"filesystem":{"denyRead":["/"],"allowRead":["/"]}}')
test_fail "socksProxyPort zero is rejected" "$policy" "$sandbox_shell" -c 'printf ok\\n'

mkdir -p "$tmp/globdir/match1" "$tmp/globdir/match2"
policy=$(write_policy '{"network":{"allowNetwork":true},"filesystem":{"allowWrite":["%s/globdir/*"],"denyRead":["/"],"allowRead":["/"]}}' "$tmp")
test_ok "glob permits write in matched dir" "$policy" "$sandbox_shell" -c ': > "$1/ok.txt"; test -f "$1/ok.txt"' _ "$tmp/globdir/match1"
test_fail "glob denies write in unmatched dir" "$policy" "$sandbox_shell" -c ': > "$1/nope.txt"' _ "$tmp/globdir"

home_testdir="$HOME/landstrip-test-$$"
mkdir -p "$home_testdir"
cleanup_dirs="$cleanup_dirs $home_testdir"
policy=$(write_policy '{"network":{"allowNetwork":true},"filesystem":{"allowWrite":["~/landstrip-test-%s"]}}' "$$")
test_ok "home tilde permits configured root" "$policy" "$sandbox_shell" -c ': > "$1/ok.txt"; test -f "$1/ok.txt"' _ "$home_testdir"

mkdir -p "$tmp/read-ok" "$tmp/read-no"
printf 'ok\n' >"$tmp/read-ok/data.txt"
printf 'no\n' >"$tmp/read-no/data.txt"
policy=$(write_policy '{"network":{"allowNetwork":true},"filesystem":{"denyRead":["/"],"allowRead":["%s/read-ok","/usr","/lib","/lib64","/bin","/sbin","/etc"]}}' "$tmp")
cwd=$(pwd)
cd "$tmp/read-ok"
test_ok "allowRead permits read in allowed path" "$policy" "$sandbox_shell" -c 'cat "$1/data.txt"' _ "$tmp/read-ok"
expect_failure_access_denied "allowRead denies other root" "$tmp/read-no/data.txt" "$bin" -p "$policy" "$sandbox_shell" -c 'cat "$1/data.txt"' _ "$tmp/read-no"
cd "$cwd"

mkdir -p "$tmp/probe-denied/bin"
policy=$(write_policy '{"network":{"allowNetwork":true},"filesystem":{"denyRead":["%s/probe-denied"]}}' "$tmp")
expect_success_no_access_denied "successful PATH probe hides nonfatal denials" \
    "$bin" -p "$policy" "$sandbox_shell" -c 'PATH="$1/probe-denied/bin:/bin:/usr/bin" ls /bin/sh' _ "$tmp"

policy_fs=$(write_policy '{"filesystem":{"allowWrite":["%s/allowed"],"denyRead":["/"],"allowRead":["/"]}}' "$tmp")
policy_net="$tmp/policy-net.json"
printf '{"network":{"allowNetwork":true}}' >"$policy_net"
expect_success "multiple policy files merge" \
    "$bin" -p "$policy_fs" -p "$policy_net" "$sandbox_shell" -c ': > "$1/ok.txt"; test -f "$1/ok.txt"' _ "$tmp/allowed"

policy=$(write_policy '{"network":{"allowNetwork":true},"filesystem":{"denyRead":["/"],"allowRead":["/"]}}')
expect_failure "tool not found is rejected" \
    "$bin" -p "$policy" "$tmp/no-such-tool-$$"

expect_failure "empty stdin policy is rejected" \
    "$sandbox_shell" -c ': | "$1" "$2" -c "exit 0"' _ "$bin" "$sandbox_shell"

printf 'SUMMARY pass=%s fail=%s tmp=%s\n' "$pass" "$fail" "$tmp"
[ "$fail" -eq 0 ]
