// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

#[cfg(target_os = "linux")]
use super::context::{PolicyDelivery, SandboxContext};
use super::context::{ResponderMode, RunSpec};
use super::machine::{Require, Step};
use super::probe::{NetProbe, Probe, ProbeOutcome};
use super::state::{NetworkMode, SandboxState};
use proptest::prelude::*;
use proptest::strategy::Union;
use proptest::test_runner::TestCaseResult;
use serde_json::{Value, json};
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
#[cfg(target_os = "linux")]
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ConfigureNetworkModeCmd {
    pub mode_idx: usize,
}

impl Arbitrary for ConfigureNetworkModeCmd {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        (0..4usize).prop_map(|mode_idx| Self { mode_idx }).boxed()
    }
}

impl Step for ConfigureNetworkModeCmd {
    fn apply(&self, state: &mut SandboxState) -> TestCaseResult {
        state.policy.network = match self.mode_idx % 4 {
            0 => NetworkMode::DenyAll,
            1 => NetworkMode::LocalBindingOnly,
            2 => NetworkMode::ProxyPort(8080),
            _ => NetworkMode::AllowAll,
        };
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct TcpMediationCmd;

impl Arbitrary for TcpMediationCmd {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        Just(Self).boxed()
    }
}

impl Step for TcpMediationCmd {
    #[allow(clippy::too_many_lines)]
    fn apply(&self, state: &mut SandboxState) -> TestCaseResult {
        let proxy_listener = TcpListener::bind("127.0.0.1:0").require("bind proxy listener")?;
        let other_listener = TcpListener::bind("127.0.0.1:0").require("bind other listener")?;
        let proxy_addr = proxy_listener.local_addr().require("proxy addr")?;
        let other_addr = other_listener.local_addr().require("other addr")?;

        let deny_pol = vec![json!({
            "filesystem": { "allowRead": ["/"] },
            "network": {}
        })];
        prop_assert_eq!(
            state.probe(&deny_pol, NetProbe::TcpBind)?,
            ProbeOutcome::Denied,
            "TCP bind should fail under default network policy"
        );

        let conn_other = Probe::from(NetProbe::TcpConnect { addr: other_addr });
        let mut deny_conn_spec = RunSpec::worker(&state.root, &deny_pol, &conn_other, &state.ctx)?;
        deny_conn_spec.responder = ResponderMode::ObserveFd;
        let deny_conn_res = state.ctx.execute(&deny_conn_spec);
        prop_assert_eq!(
            ProbeOutcome::try_from(&deny_conn_res)?,
            ProbeOutcome::Denied,
            "TCP connect must fail under DenyAll"
        );
        if cfg!(target_os = "linux") {
            prop_assert!(
                deny_conn_res.has_trap(|t| {
                    t.get("kind").and_then(Value::as_str) == Some("network")
                        && t.get("code").and_then(Value::as_str) == Some("NETWORK_DENIED")
                }),
                "expected NETWORK_DENIED trap on Linux TCP denial: stderr={}",
                deny_conn_res.stderr
            );
        }
        #[cfg(target_os = "linux")]
        {
            let fastopen = Probe::from(NetProbe::TcpFastOpen { addr: other_addr });
            let mut spec = RunSpec::worker(&state.root, &deny_pol, &fastopen, &state.ctx)?;
            spec.responder = ResponderMode::ObserveFd;
            let res = state.ctx.execute(&spec);
            prop_assert_eq!(
                ProbeOutcome::try_from(&res)?,
                ProbeOutcome::Denied,
                "TCP Fast Open send must fail under DenyAll"
            );
            prop_assert!(
                res.has_trap(|t| {
                    t.get("code").and_then(Value::as_str) == Some("NETWORK_DENIED")
                }),
                "expected NETWORK_DENIED trap on TCP Fast Open denial: stderr={}",
                res.stderr
            );
            other_listener
                .set_nonblocking(true)
                .require("nonblocking listener")?;
            prop_assert!(
                other_listener.accept().is_err(),
                "refused TCP Fast Open must not reach the host listener"
            );
        }

        let proxy_pol = vec![json!({
            "filesystem": { "allowRead": ["/"] },
            "network": { "httpProxyPort": proxy_addr.port() }
        })];
        let accept_thread = std::thread::spawn(move || {
            let mut buf = [0_u8; 4];
            if let Ok((mut s, _)) = proxy_listener.accept() {
                let _ = s.read(&mut buf);
            }
            buf
        });
        prop_assert_eq!(
            state.probe(&proxy_pol, NetProbe::TcpConnect { addr: proxy_addr })?,
            ProbeOutcome::Allowed,
            "httpProxyPort must allow connecting to configured loopback port"
        );
        prop_assert_eq!(&accept_thread.join().unwrap_or([0; 4]), b"ping");

        prop_assert_eq!(
            state.probe(&proxy_pol, conn_other)?,
            ProbeOutcome::Denied,
            "httpProxyPort must reject unconfigured loopback port"
        );

        let local_pol = vec![json!({
            "filesystem": { "allowRead": ["/"] },
            "network": { "allowLocalBinding": true }
        })];
        prop_assert_eq!(
            state.probe(&local_pol, NetProbe::TcpBind)?,
            ProbeOutcome::Allowed,
            "allowLocalBinding must permit loopback TCP bind"
        );
        drop(other_listener);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct UdpAndMsghdrCmd;

impl Arbitrary for UdpAndMsghdrCmd {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        Just(Self).boxed()
    }
}

impl Step for UdpAndMsghdrCmd {
    fn apply(&self, state: &mut SandboxState) -> TestCaseResult {
        let deny_pol = vec![json!({
            "filesystem": { "allowRead": ["/"] },
            "network": {}
        })];
        prop_assert_eq!(
            state.probe(&deny_pol, NetProbe::UdpBind)?,
            ProbeOutcome::Denied,
            "UDP bind should be denied with EACCES/EPERM/EAFNOSUPPORT under default policy"
        );

        #[cfg(target_os = "linux")]
        {
            let allow_pol = vec![json!({
                "filesystem": { "allowRead": ["/"] },
                "network": { "allowNetwork": true }
            })];
            for (policy, expected) in [
                (&deny_pol, ProbeOutcome::Denied),
                (&allow_pol, ProbeOutcome::Allowed),
            ] {
                prop_assert_eq!(
                    state.probe(policy, NetProbe::Netlink)?,
                    expected,
                    "netlink socket creation"
                );
            }
        }

        let local_pol = vec![json!({
            "filesystem": { "allowRead": ["/"] },
            "network": { "allowLocalBinding": true }
        })];
        prop_assert_eq!(
            state.probe(&local_pol, NetProbe::UdpLoopbackEcho)?,
            ProbeOutcome::Allowed,
            "loopback UDP must succeed under allowLocalBinding"
        );
        prop_assert_eq!(
            state.probe(&local_pol, NetProbe::UdpMsghdr)?,
            ProbeOutcome::Allowed,
            "vectored sendmsg/recvmsg header semantics failed"
        );
        let remote = NetProbe::UdpSend {
            addr: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 9),
        };
        prop_assert_eq!(
            state.probe(&local_pol, remote)?,
            ProbeOutcome::Denied,
            "remote UDP send must fail under allowLocalBinding"
        );
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct UnixAndAbstractSocketCmd;

impl Arbitrary for UnixAndAbstractSocketCmd {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        Just(Self).boxed()
    }
}

impl Step for UnixAndAbstractSocketCmd {
    fn apply(&self, state: &mut SandboxState) -> TestCaseResult {
        use std::os::unix::net::UnixListener;

        let sock_dir = state.root.join("writable/socks");
        let _ = std::fs::create_dir_all(&sock_dir);
        let sock_path = sock_dir.join("srv.sock");
        let _ = std::fs::remove_file(&sock_path);
        let listener = UnixListener::bind(&sock_path).require("bind unix sock")?;

        let deny_pol = vec![json!({
            "filesystem": {
                "allowRead": ["/"],
                "allowWrite": [state.abs_path("writable")]
            },
            "network": {}
        })];
        let connect = Probe::from(NetProbe::UnixConnect {
            path: sock_path.clone(),
        });
        let mut deny_spec = RunSpec::worker(&state.root, &deny_pol, &connect, &state.ctx)?;
        deny_spec.responder = ResponderMode::ObserveFd;
        prop_assert_eq!(
            ProbeOutcome::try_from(&state.ctx.execute(&deny_spec))?,
            ProbeOutcome::Denied,
            "Unix connect must fail without allowUnixSockets"
        );

        let allow_pol = vec![json!({
            "filesystem": {
                "allowRead": ["/"],
                "allowWrite": [state.abs_path("writable")]
            },
            "network": {
                "allowUnixSockets": [sock_path]
            }
        })];
        let srv_handle = std::thread::spawn(move || {
            let mut buf = [0_u8; 7];
            if let Ok((mut s, _)) = listener.accept() {
                let _ = s.read(&mut buf);
            }
            buf
        });
        prop_assert_eq!(
            state.probe(&allow_pol, connect)?,
            ProbeOutcome::Allowed,
            "Unix connect must succeed when listed in allowUnixSockets"
        );
        prop_assert_eq!(&srv_handle.join().unwrap_or([0; 7]), b"unix-hi");

        let bind_sock = sock_dir.join("bound.sock");
        let bind_pol = vec![json!({
            "filesystem": {
                "allowRead": ["/"],
                "allowWrite": [state.abs_path("writable")]
            },
            "network": {
                "allowUnixSockets": [sock_dir]
            }
        })];
        prop_assert_eq!(
            state.probe(&bind_pol, NetProbe::UnixBind { path: bind_sock })?,
            ProbeOutcome::Allowed,
            "Unix bind must succeed inside an allowUnixSockets directory"
        );

        #[cfg(target_os = "linux")]
        {
            use std::os::linux::net::SocketAddrExt;
            use std::os::unix::net::SocketAddr;

            let abs_name = format!(
                "ls-abs-{}-{}",
                std::process::id(),
                SandboxContext::next_id()
            );
            let addr =
                SocketAddr::from_abstract_name(abs_name.as_bytes()).require("abstract addr")?;
            let _abs_listener = UnixListener::bind_addr(&addr).require("bind abstract")?;
            let unrestricted_unix = vec![json!({
                "filesystem": { "allowRead": ["/"] },
                "network": { "allowAllUnixSockets": true }
            })];
            prop_assert_eq!(
                state.probe(
                    &unrestricted_unix,
                    NetProbe::AbstractConnect { name: abs_name }
                )?,
                ProbeOutcome::Denied,
                "host abstract Unix socket must stay unreachable inside sandbox"
            );
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct SupervisorAndDbusCmd;

#[cfg(target_os = "linux")]
impl Arbitrary for SupervisorAndDbusCmd {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        Just(Self).boxed()
    }
}

#[cfg(target_os = "linux")]
impl Step for SupervisorAndDbusCmd {
    fn apply(&self, state: &mut SandboxState) -> TestCaseResult {
        use std::os::unix::net::UnixListener;

        let rt_dir = state.root.join("rt");
        let systemd_dir = rt_dir.join("systemd");
        let app_dir = rt_dir.join("app");
        let _ = std::fs::create_dir_all(&systemd_dir);
        let _ = std::fs::create_dir_all(&app_dir);

        let priv_sock = systemd_dir.join("private");
        let sneaky_link = app_dir.join("sneaky_private");
        let _ = std::fs::remove_file(&priv_sock);
        let _ = std::fs::remove_file(&sneaky_link);
        let _srv = UnixListener::bind(&priv_sock).require("bind systemd private")?;
        let _ = std::fs::hard_link(&priv_sock, &sneaky_link);

        let rt_s = rt_dir.to_string_lossy().into_owned();
        for target_sock in [&priv_sock, &sneaky_link] {
            let pol = vec![json!({
                "filesystem": { "allowRead": ["/"] },
                "network": { "allowUnixSockets": [priv_sock, app_dir] }
            })];
            let connect = Probe::from(NetProbe::UnixConnect {
                path: target_sock.clone(),
            });
            let env_vars = [("XDG_RUNTIME_DIR", rt_s.as_str())];
            let spec = RunSpec {
                workdir: &state.root,
                cwd: None,
                policies: &pol,
                delivery: PolicyDelivery::JsonSingle,
                responder: ResponderMode::GrantAllow,
                rename_on_query: None,
                inherited_fds: &[],
                env_overrides: &env_vars,
                tool: &state.ctx.exe,
                args: connect.argv()?,
                timeout: Duration::from_secs(10),
            };
            let res = state.ctx.execute(&spec);
            prop_assert_eq!(
                ProbeOutcome::try_from(&res)?,
                ProbeOutcome::Denied,
                "systemd private socket must remain terminal even via hardlink"
            );
            prop_assert!(
                !res.traps
                    .iter()
                    .any(|t| t.get("state").and_then(Value::as_str) == Some("query")),
                "systemd private socket must never emit interactive query"
            );
        }
        Self::verify_dbus_proxy_if_available(state, &rt_dir)?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl SupervisorAndDbusCmd {
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_lines)]
    fn verify_dbus_proxy_if_available(
        state: &SandboxState,
        rt_dir: &std::path::Path,
    ) -> TestCaseResult {
        let Some(dbus_daemon) = which::which("dbus-daemon").ok() else {
            return Ok(());
        };
        let Some(gdbus) = which::which("gdbus").ok() else {
            return Ok(());
        };
        if which::which("xdg-dbus-proxy").is_err() {
            return Ok(());
        }
        let services = rt_dir.join("services");
        let _ = std::fs::create_dir_all(&services);
        let _ = std::fs::write(
            services.join("org.freedesktop.secrets.service"),
            "[D-BUS Service]\nName=org.freedesktop.secrets\nExec=/bin/true\n",
        );
        let marker = rt_dir.join("systemd-activated");
        let _ = std::fs::write(
            services.join("org.freedesktop.systemd1.service"),
            format!(
                "[D-BUS Service]\nName=org.freedesktop.systemd1\nExec=/usr/bin/touch {}\n",
                marker.display()
            ),
        );
        let bus_path = rt_dir.join("bus");
        let conf_path = rt_dir.join("dbus.conf");
        let conf = format!(
            "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN\" \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n<busconfig>\n  <type>session</type>\n  <listen>unix:path={}</listen>\n  <servicedir>{}</servicedir>\n  <policy context=\"default\">\n    <allow send_destination=\"*\" eavesdrop=\"true\"/>\n    <allow eavesdrop=\"true\"/>\n    <allow own=\"*\"/>\n  </policy>\n</busconfig>\n",
            bus_path.display(),
            services.display()
        );
        let _ = std::fs::write(&conf_path, conf);
        let Ok(mut daemon) = std::process::Command::new(dbus_daemon)
            .arg(format!("--config-file={}", conf_path.display()))
            .args(["--nofork", "--nopidfile"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        else {
            return Ok(());
        };
        for _ in 0..50 {
            if bus_path.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        if bus_path.exists() {
            let pol = vec![json!({
                "filesystem": {
                    "allowRead": ["/"],
                    "allowWrite": ["/dev/null"]
                },
                "network": {
                    "allowUnixSockets": [bus_path]
                }
            })];
            let rt_s = rt_dir.to_string_lossy().into_owned();
            let bus_env = format!("unix:path={}", bus_path.display());
            let env_vars = [
                ("XDG_RUNTIME_DIR", rt_s.as_str()),
                ("DBUS_SESSION_BUS_ADDRESS", bus_env.as_str()),
            ];
            let list_args = vec![
                "call".to_owned(),
                "--session".to_owned(),
                "--dest".to_owned(),
                "org.freedesktop.DBus".to_owned(),
                "--object-path".to_owned(),
                "/org/freedesktop/DBus".to_owned(),
                "--method".to_owned(),
                "org.freedesktop.DBus.ListActivatableNames".to_owned(),
            ];
            let spec = RunSpec {
                workdir: &state.root,
                cwd: None,
                policies: &pol,
                delivery: PolicyDelivery::JsonSingle,
                responder: ResponderMode::GrantDeny,
                rename_on_query: None,
                inherited_fds: &[],
                env_overrides: &env_vars,
                tool: &gdbus,
                args: list_args,
                timeout: Duration::from_secs(10),
            };
            let res = state.ctx.execute(&spec);
            prop_assert!(
                res.success(),
                "proxied D-Bus ListActivatableNames failed: {}",
                res.stderr
            );
            let out = res.stdout_str();
            prop_assert!(
                out.contains("org.freedesktop.secrets"),
                "secrets missing: {out}"
            );
            prop_assert!(
                !out.contains("org.freedesktop.systemd1"),
                "systemd1 leaked through D-Bus proxy: {out}"
            );
            prop_assert!(!marker.exists());
        }
        let _ = daemon.kill();
        let _ = daemon.wait();
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum NetworkStep {
    ConfigureNetworkMode(ConfigureNetworkModeCmd),
    TcpMediation(TcpMediationCmd),
    UdpAndMsghdr(UdpAndMsghdrCmd),
    UnixAndAbstractSocket(UnixAndAbstractSocketCmd),
    #[cfg(target_os = "linux")]
    SupervisorAndDbus(SupervisorAndDbusCmd),
}

impl Arbitrary for NetworkStep {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with((): ()) -> Self::Strategy {
        let mut steps = Vec::new();
        steps.extend([
            any::<ConfigureNetworkModeCmd>()
                .prop_map(Self::ConfigureNetworkMode)
                .boxed(),
            any::<TcpMediationCmd>()
                .prop_map(Self::TcpMediation)
                .boxed(),
            any::<UdpAndMsghdrCmd>()
                .prop_map(Self::UdpAndMsghdr)
                .boxed(),
            any::<UnixAndAbstractSocketCmd>()
                .prop_map(Self::UnixAndAbstractSocket)
                .boxed(),
        ]);
        #[cfg(target_os = "linux")]
        steps.push(
            any::<SupervisorAndDbusCmd>()
                .prop_map(Self::SupervisorAndDbus)
                .boxed(),
        );
        Union::new(steps).boxed()
    }
}

impl AsRef<dyn Step> for NetworkStep {
    fn as_ref(&self) -> &(dyn Step + 'static) {
        match self {
            Self::ConfigureNetworkMode(step) => step,
            Self::TcpMediation(step) => step,
            Self::UdpAndMsghdr(step) => step,
            Self::UnixAndAbstractSocket(step) => step,
            #[cfg(target_os = "linux")]
            Self::SupervisorAndDbus(step) => step,
        }
    }
}
