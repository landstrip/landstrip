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
    if [ "$status" -eq 0 ] && ! printf '%s\n' "$output" | grep -F -q '"kind":"filesystem"'; then
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
        -e "\"$expected_file\"" \
        -e "\"$expected_real\""; then
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
        printf '%s\n' "$output" | grep -F -q '"kind":"filesystem"' && \
        printf '%s\n' "$output" | grep -F -q "\"$expected_operation\""; then
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

expect_trap_fd_write_denied() {
    name=$1
    policy=$2
    denied_file=$3
    expected_real=$(CDPATH= cd -- "$(dirname -- "$denied_file")" && pwd -P)/$(basename -- "$denied_file")
    diag=$tmp/trap-fd-write-denied.txt
    rm -f "$diag"
    set +e
    output=$("$bin" --trap-fd 3 -p "$policy" "$sandbox_shell" -c \
        'if test -e /proc/self/fd/3; then echo fd3-inherited >&2; fi; : > "$1"; exit 1' \
        _ "$denied_file" 3>"$diag" 2>&1)
    status=$?
    set -e

    has_expected_file=0
    if grep -F -q \
        -e "\"$denied_file\"" \
        -e "\"$expected_real\"" \
        "$diag"; then
        has_expected_file=1
    fi

    if [ "$status" -ne 0 ] && [ "$has_expected_file" -eq 1 ] && \
        grep -F -q '"kind":"filesystem"' "$diag" && \
        grep -F -q '"write"' "$diag" && \
        grep -F -q '"seccomp"' "$diag" && \
        grep -F -q '"code":"FS_WRITE_DENIED"' "$diag" && \
        grep -F -q '"syscall":"openat"' "$diag" && \
        grep -F -q '"errno":"EACCES"' "$diag" && \
        grep -F -q '"O_CREAT"' "$diag" && \
        grep -F -q '"requested_path"' "$diag" && \
        grep -F -q '"reason":"allow_miss"' "$diag" && \
        grep -F -q '"suggested_grant":{"allowWrite"' "$diag" && \
        grep -F -q '"process":{"pid"' "$diag" && \
        ! printf '%s\n' "$output" | grep -F -q 'fd3-inherited'; then
        pass "$name"
    else
        diag_output=$(cat "$diag" 2>/dev/null || true)
        fail "$name" "status=$status output=$output trap_fd=$diag_output"
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
        -e "\"file\":\"$expected_file\"" \
        -e "\"file\":\"$expected_real\"" \
        -e "$expected_file" \
        -e "$expected_real"; then
        has_expected_file=1
    fi
    if [ "$status" -ne 0 ] && [ "$has_expected_file" -eq 1 ] && \
        printf '%s\n' "$output" | grep -F -q \
        -e '"kind":"filesystem"' \
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

expect_connect_denied() {
    name=$1
    policy=$2
    port=$(next_port)
    out=$tmp/connect-denied-$port.out
    set +e
    "$bin" -p "$policy" "$nc_path" -z -w1 127.0.0.1 "$port" >"$out" 2>&1
    status=$?
    set -e
    if [ "$status" -ne 0 ] && \
        grep -F -q '"kind":"network","code":"NET_CONNECT_DENIED"' "$out" && \
        grep -F -q "\"127.0.0.1:$port\"" "$out" && \
        grep -F -q '"seccomp"' "$out"; then
        pass "$name"
    else
        output=$(while IFS= read -r line; do printf '%s ' "$line"; done < "$out")
        fail "$name" "status=$status output=$output"
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
if [ "$os_name" = Darwin ]; then
    policy=$(write_policy '{"network":{"allowNetwork":true},"filesystem":{"allowWrite":["/dev/null"],"denyRead":["/"]}}')
    test_fail "denyRead root blocks directory listing" "$policy" /bin/ls /
fi

policy=$(write_policy '{"network":{"allowNetwork":true},"filesystem":{"allowWrite":["%s/allowed"],"denyRead":["/"],"allowRead":["/"]}}' "$tmp")
expect_success_access_denied "successful write denial is reported" "/dev/null" write \
    "$bin" -p "$policy" "$sandbox_shell" -c 'cat /dev/null >/dev/null; true'
if [ "$os_name" = Linux ]; then
    expect_trap_fd_write_denied "trap fd reports write denial" \
        "$policy" "$tmp/denied/trap-fd.txt"
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

if [ "$os_name" = Linux ]; then
    policy=$(write_policy '{"network":{"httpProxyPort":1},"filesystem":{"denyRead":["/home"],"allowRead":["/usr","/lib","/lib64","/bin","/sbin","/etc"]}}')
    expect_connect_denied "denied TCP connect is reported" "$policy"
fi

policy=$(write_policy '{"network":{"allowNetwork":true},"filesystem":{"allowWrite":[""]}}')
test_fail "empty path is rejected" "$policy" "$sandbox_shell" -c 'printf ok\\n'

mkdir -p "$tmp/allowed/keep" "$tmp/allowed/sub"
: > "$tmp/allowed/sub/keep-me"
policy=$(write_policy '{"network":{"allowNetwork":true},"filesystem":{"allowWrite":["%s/allowed"],"denyWrite":["%s/allowed/sub"],"denyRead":["/"],"allowRead":["/"]}}' "$tmp" "$tmp")
test_ok "denyWrite permits sibling write" "$policy" "$sandbox_shell" -c ': > "$1/ok.txt"; test -f "$1/ok.txt"' _ "$tmp/allowed/keep"
test_fail "denyWrite denies subtree write" "$policy" "$sandbox_shell" -c ': > "$1/nope.txt"' _ "$tmp/allowed/sub"
test_ok "denyWrite permits new entry beside denied path" "$policy" "$sandbox_shell" -c ': > "$1/fresh.txt"; test -f "$1/fresh.txt"' _ "$tmp/allowed"
if [ "$os_name" = Linux ]; then
    test_fail "denyWrite denies rename into denied subtree" "$policy" "$sandbox_shell" -c ': > "$1/mv-src.txt"; mv "$1/mv-src.txt" "$2/moved.txt"' _ "$tmp/allowed" "$tmp/allowed/sub"
    test_fail "denyWrite denies symlink into denied subtree" "$policy" "$sandbox_shell" -c 'ln -s /etc/hostname "$1/link"' _ "$tmp/allowed/sub"
    test_fail "denyWrite denies unlink in denied subtree" "$policy" "$sandbox_shell" -c 'rm -f "$1/keep-me"' _ "$tmp/allowed/sub"
fi

if [ "$os_name" = Linux ]; then
    mkdir -p "$tmp/unreadable/sub"
    : > "$tmp/unreadable/sub/secret"
    chmod 000 "$tmp/unreadable/sub"
    policy=$(write_policy '{"filesystem":{"allowWrite":["/dev/null"],"denyRead":["%s/unreadable/sub/secret"]}}' "$tmp")
    test_ok "denyRead spine through unreadable dir does not abort setup" "$policy" "$sandbox_shell" -c 'printf ok\\n'
    chmod 755 "$tmp/unreadable/sub"
fi

# A denyWrite glob expands by walking its base subtree. A directory in that
# subtree the broker cannot read must be skipped, not abort the policy.
if [ "$os_name" = Linux ]; then
    mkdir -p "$tmp/globwalk/locked"
    : > "$tmp/globwalk/locked/data"
    chmod 000 "$tmp/globwalk/locked"
    policy=$(write_policy '{"filesystem":{"allowWrite":["%s/globwalk","/dev/null"],"denyWrite":["%s/globwalk/**/.env"]}}' "$tmp" "$tmp")
    test_ok "denyWrite glob over unreadable subtree does not abort setup" "$policy" "$sandbox_shell" -c 'printf ok\\n'
    chmod 755 "$tmp/globwalk/locked"
fi

# stat/metadata of a denyRead path is permitted (tools must stat ancestor
# directories to canonicalise paths); only reading contents stays blocked.
# Linux-only: the macOS seatbelt profile governs stat separately.
if [ "$os_name" = Linux ]; then
    mkdir -p "$tmp/secret"
    printf 'topsecret\n' > "$tmp/secret/file"
    policy=$(write_policy '{"filesystem":{"denyRead":["%s/secret"],"allowWrite":["/dev/null"]}}' "$tmp")
    test_ok "stat of a denyRead path is permitted" "$policy" "$sandbox_shell" -c 'test -e "$1"' _ "$tmp/secret/file"
    test_fail "reading a denyRead file is still blocked" "$policy" "$sandbox_shell" -c 'cat "$1"' _ "$tmp/secret/file"
fi

# Where an allowRead and a denyRead overlap, the most specific rule wins: an
# allowRead path carves back out of a broader denyRead, and a denyRead nested
# inside an allowRead root still wins.
if [ "$os_name" = Linux ]; then
    mkdir -p "$tmp/vault"
    printf 'public\n' > "$tmp/vault/ok"
    printf 'private\n' > "$tmp/vault/hidden"
    policy=$(write_policy '{"filesystem":{"denyRead":["%s/vault"],"allowRead":["%s/vault/ok"],"allowWrite":["/dev/null"]}}' "$tmp" "$tmp")
    test_ok "allowRead carves a file back out of denyRead" "$policy" "$sandbox_shell" -c 'cat "$1"' _ "$tmp/vault/ok"
    test_fail "denyRead blocks the rest of the carved directory" "$policy" "$sandbox_shell" -c 'cat "$1"' _ "$tmp/vault/hidden"

    mkdir -p "$tmp/proj/sub"
    printf 'code\n' > "$tmp/proj/sub/main"
    printf 'token\n' > "$tmp/proj/sub/.env"
    policy=$(write_policy '{"filesystem":{"denyRead":["%s/proj/sub/.env"],"allowRead":["%s/proj"],"allowWrite":["/dev/null"]}}' "$tmp" "$tmp")
    test_ok "broad allowRead permits a file beside a nested denyRead" "$policy" "$sandbox_shell" -c 'cat "$1"' _ "$tmp/proj/sub/main"
    test_fail "nested denyRead wins over a broader allowRead" "$policy" "$sandbox_shell" -c 'cat "$1"' _ "$tmp/proj/sub/.env"
fi

# A denyWrite path that traverses a symlink must not be bypassable by swapping
# the symlink for a real directory, nor may the symlink itself be removed.
if [ "$os_name" = Linux ]; then
    link_root="$tmp/symlink-root"
    mkdir -p "$link_root/decoy"
    : > "$link_root/decoy/secret"
    ln -s decoy "$link_root/link"
    policy=$(write_policy '{"network":{"allowNetwork":true},"filesystem":{"allowWrite":["%s"],"denyWrite":["%s/link/secret"],"denyRead":["/"],"allowRead":["/"]}}' "$link_root" "$link_root")
    test_fail "denyWrite blocks symlink-swap replacement attack" "$policy" "$sandbox_shell" -c 'rm "$1/link" && mkdir "$1/link" && echo evil > "$1/link/secret"' _ "$link_root"
    test_fail "denyWrite blocks removing a symlink ancestor" "$policy" "$sandbox_shell" -c 'rm "$1/link"' _ "$link_root"
    test_ok "denyWrite permits unrelated write under symlink root" "$policy" "$sandbox_shell" -c ': > "$1/ok.txt"; test -f "$1/ok.txt"' _ "$link_root"
fi

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
if [ "$os_name" = Darwin ]; then
    test_fail "partial allowRead policy is rejected" "$policy" /bin/cat "$tmp/read-ok/data.txt"
else
    cwd=$(pwd)
    cd "$tmp/read-ok"
    test_ok "allowRead permits read in allowed path" "$policy" "$sandbox_shell" -c 'cat "$1/data.txt"' _ "$tmp/read-ok"
    expect_failure_access_denied "allowRead denies other root" "$tmp/read-no/data.txt" "$bin" -p "$policy" "$sandbox_shell" -c 'cat "$1/data.txt"' _ "$tmp/read-no"
    cd "$cwd"
fi

if [ "$os_name" = Darwin ]; then
    policy=$(write_policy '{"network":{"allowNetwork":true},"filesystem":{"denyRead":["%s/probe-denied"]}}' "$tmp")
    test_fail "denyRead without root allow is rejected" "$policy" "$sandbox_shell" -c 'printf ok\n'
else
    mkdir -p "$tmp/probe-denied/bin"
    policy=$(write_policy '{"network":{"allowNetwork":true},"filesystem":{"denyRead":["%s/probe-denied"]}}' "$tmp")
    expect_success_no_access_denied "successful PATH probe hides nonfatal denials" \
        "$bin" -p "$policy" "$sandbox_shell" -c 'PATH="$1/probe-denied/bin:/bin:/usr/bin" ls /bin/sh' _ "$tmp"

    policy=$(write_policy '{"network":{"allowNetwork":true},"filesystem":{"denyRead":["/home"],"allowRead":["/usr","/lib","/lib64","/bin","/sbin","/etc"]}}')
    expect_success_no_access_denied "missing denied read returns absent" \
        "$bin" -p "$policy" "$sandbox_shell" -c 'test ! -e "/home/landstrip-missing-$$"'
fi

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
