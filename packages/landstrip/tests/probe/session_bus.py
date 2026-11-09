#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright (c) 2026 Jarkko Sakkinen

"""Verify user D-Bus session socket mediation and xdg-dbus-proxy filtering."""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def run(binary, directory, env, policy, command, action="deny"):
    policy_path = directory / "policy.json"
    policy_path.write_text(json.dumps(policy))
    socket_path = directory / "trap.sock"
    socket_path.unlink(missing_ok=True)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(socket_path))
        listener.listen(1)
        listener.settimeout(10)
        args = [binary, "run", "--trap", str(socket_path), "-p", str(policy_path), "--"]
        with subprocess.Popen(
            args + command,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as process:
            try:
                records = []
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(10)
                    with connection.makefile("rb") as stream:
                        for line in stream:
                            trap = json.loads(line)
                            records.append(trap)
                            if trap.get("state") == "query":
                                response = {"query_id": trap["query_id"], "action": action}
                                connection.sendall((json.dumps(response) + "\n").encode())
                stdout, stderr = process.communicate(timeout=10)
                return process.returncode, stdout.decode(), stderr.decode(), records
            except BaseException:
                process.kill()
                process.communicate()
                raise


def write_dbus_fixture(runtime_dir, marker_path):
    services = runtime_dir / "services"
    services.mkdir()
    (services / "org.freedesktop.secrets.service").write_text(
        "[D-BUS Service]\nName=org.freedesktop.secrets\nExec=/bin/true\n"
    )
    touch = shutil.which("touch") or "/usr/bin/touch"
    (services / "org.freedesktop.systemd1.service").write_text(
        f"[D-BUS Service]\nName=org.freedesktop.systemd1\nExec={touch} {marker_path}\n"
    )
    bus_path = runtime_dir / "bus"
    conf_path = runtime_dir / "dbus.conf"
    conf_path.write_text(
        '<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"\n'
        ' "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">\n'
        "<busconfig>\n"
        "  <type>session</type>\n"
        f"  <listen>unix:path={bus_path}</listen>\n"
        f"  <servicedir>{services}</servicedir>\n"
        '  <policy context="default">\n'
        '    <allow send_destination="*" eavesdrop="true"/>\n'
        '    <allow eavesdrop="true"/>\n'
        '    <allow own="*"/>\n'
        "  </policy>\n"
        "</busconfig>\n"
    )
    return bus_path, conf_path


def list_activatable_cmd(address=None):
    cmd = ["gdbus", "call"]
    if address is None:
        cmd.append("--session")
    else:
        cmd.extend(["--address", address])
    cmd.extend(
        [
            "--dest",
            "org.freedesktop.DBus",
            "--object-path",
            "/org/freedesktop/DBus",
            "--method",
            "org.freedesktop.DBus.ListActivatableNames",
        ]
    )
    return cmd


def main(binary):
    for required in ("dbus-daemon", "gdbus", "xdg-dbus-proxy"):
        if shutil.which(required) is None:
            print("session bus verified")
            return

    with tempfile.TemporaryDirectory(prefix="ls-dbus-", dir="/tmp") as temporary:
        root = Path(temporary).resolve()
        runtime_dir = root / "rt"
        runtime_dir.mkdir()
        marker_path = root / "systemd-activated"
        bus_path, conf_path = write_dbus_fixture(runtime_dir, marker_path)
        ready_path = root / "ready"

        with ready_path.open("wb") as ready_out:
            daemon = subprocess.Popen(
                [
                    "dbus-daemon",
                    f"--config-file={conf_path}",
                    "--nofork",
                    "--nopidfile",
                    "--print-address=1",
                ],
                stdout=ready_out,
                stderr=subprocess.DEVNULL,
            )
        try:
            deadline = time.monotonic() + 5.0
            while ready_path.stat().st_size == 0:
                if daemon.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("dbus-daemon failed to start")
                time.sleep(0.02)

            raw = subprocess.run(
                list_activatable_cmd(f"unix:path={bus_path}"),
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            )
            assert "org.freedesktop.secrets" in raw.stdout, raw.stdout
            assert "org.freedesktop.systemd1" in raw.stdout, raw.stdout

            # Confirm unproxied systemd1 activation creates marker_path, then remove it.
            subprocess.run(
                [
                    "gdbus",
                    "call",
                    "--timeout",
                    "1",
                    "--address",
                    f"unix:path={bus_path}",
                    "--dest",
                    "org.freedesktop.systemd1",
                    "--object-path",
                    "/org/freedesktop/systemd1",
                    "--method",
                    "org.freedesktop.DBus.Peer.Ping",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            assert marker_path.exists(), "raw dbus-daemon did not activate systemd1 fixture"
            marker_path.unlink()

            env = os.environ.copy()
            env["XDG_RUNTIME_DIR"] = str(runtime_dir)
            env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus_path}"

            base_fs = {"allowRead": ["/"], "allowWrite": ["/dev/null"]}

            # 1. Interactive query denied -> blocked without starting or exposing bus.
            policy = {"network": {"allowUnixSockets": []}, "filesystem": base_fs}
            code, stdout, _, records = run(
                binary, root, env, policy, list_activatable_cmd(), action="deny"
            )
            assert code != 0 and "org.freedesktop.secrets" not in stdout, stdout
            assert any(
                r.get("state") == "query" and r.get("target") == str(bus_path)
                for r in records
            ), records

            # 2. Interactive query allowed -> secrets reachable, systemd1 stripped.
            code, stdout, stderr, records = run(
                binary, root, env, policy, list_activatable_cmd(), action="allow"
            )
            assert code == 0, (code, stdout, stderr)
            assert "org.freedesktop.secrets" in stdout, stdout
            assert "org.freedesktop.systemd1" not in stdout, stdout
            assert any(
                r.get("state") == "query" and r.get("target") == str(bus_path)
                for r in records
            ), records

            # 3. Explicit allowUnixSockets -> no prompt, still filtered via xdg-dbus-proxy.
            for allow_all in (False, True):
                allowed_policy = {
                    "network": {
                        "allowAllUnixSockets": allow_all,
                        "allowUnixSockets": [str(bus_path)],
                    },
                    "filesystem": base_fs,
                }
                code, stdout, stderr, records = run(
                    binary, root, env, allowed_policy, list_activatable_cmd(), action="deny"
                )
                assert code == 0, (allow_all, code, stdout, stderr)
                assert not records, records
                assert "org.freedesktop.secrets" in stdout, stdout
                assert "org.freedesktop.systemd1" not in stdout, stdout

                call_systemd = [
                    "gdbus",
                    "call",
                    "--session",
                    "--dest",
                    "org.freedesktop.systemd1",
                    "--object-path",
                    "/org/freedesktop/systemd1",
                    "--method",
                    "org.freedesktop.DBus.Peer.Ping",
                ]
                code, stdout, _, records = run(
                    binary, root, env, allowed_policy, call_systemd, action="allow"
                )
                assert code != 0, stdout
                assert not records, records
                assert not marker_path.exists(), "systemd1 service must never activate via proxy"

            # 4. Hard link inside an allowed sibling directory cannot bypass consent.
            sibling = runtime_dir / "app"
            sibling.mkdir()
            alias = sibling / "sneaky"
            os.link(bus_path, alias)
            sibling_policy = {
                "network": {"allowUnixSockets": [str(sibling)]},
                "filesystem": base_fs,
            }
            code, stdout, _, records = run(
                binary,
                root,
                env,
                sibling_policy,
                list_activatable_cmd(f"unix:path={alias}"),
                action="deny",
            )
            assert code != 0 and "org.freedesktop.secrets" not in stdout, stdout
            assert any(
                r.get("state") == "query" and r.get("target") == str(bus_path)
                for r in records
            ), records

            spaced_bus = root / "custom bus"
            os.link(bus_path, spaced_bus)
            encoded_env = env.copy()
            encoded_env["XDG_RUNTIME_DIR"] = "."
            encoded_env["DBUS_SESSION_BUS_ADDRESS"] = (
                f"unix:path=;unix:path=/..;unix:path=/bad%00nul;unix:path={root}/custom%20bus"
            )
            spaced_policy = {
                "network": {"allowUnixSockets": [str(spaced_bus)]},
                "filesystem": base_fs,
            }
            code, stdout, stderr, records = run(
                binary,
                root,
                encoded_env,
                spaced_policy,
                list_activatable_cmd(f"unix:path={root}/custom%20bus"),
                action="deny",
            )
            assert code == 0, (code, stdout, stderr)
            assert not records, records
            assert "org.freedesktop.secrets" in stdout and "org.freedesktop.systemd1" not in stdout, stdout

            # 5. Systemd private socket (directly or via hardlink in allowed dir) stays terminal.
            systemd_dir = runtime_dir / "systemd"
            systemd_dir.mkdir()
            units_dir = systemd_dir / "units"
            units_dir.mkdir()
            for idx in range(300):
                (units_dir / f"invocation:unit-{idx}.service").symlink_to("/dev/null")
                (units_dir / f"entry-{idx}").write_text("")
            systemd_sock = systemd_dir / "private"
            systemd_hardlink = sibling / "sneaky_systemd"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as srv:
                srv.bind(str(systemd_sock))
                srv.listen(1)
                os.link(systemd_sock, systemd_hardlink)
                for target_sock, allowed_entry in (
                    (systemd_sock, systemd_sock),
                    (systemd_hardlink, sibling),
                ):
                    systemd_policy = {
                        "network": {"allowUnixSockets": [str(allowed_entry)]},
                        "filesystem": base_fs,
                    }
                    probe = [
                        sys.executable,
                        "-c",
                        "import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])",
                        str(target_sock),
                    ]
                    code, _, _, records = run(
                        binary, root, env, systemd_policy, probe, action="allow"
                    )
                    assert code != 0
                    assert not records, records
        finally:
            daemon.terminate()
            try:
                daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait()

    print("session bus verified")


if __name__ == "__main__":
    main(sys.argv[1])
