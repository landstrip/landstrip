// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Model-based self-test: drives the sandbox as a randomized state machine
//! across filesystem policy, CLI and descriptor contracts, network mediation,
//! and process isolation, and compares ordinary system calls with the host.

mod cli_and_fds;
#[cfg(target_os = "linux")]
mod compat;
mod context;
mod fs_policy;
mod machine;
#[cfg(unix)]
mod network;
mod oracle;
mod probe;
#[cfg(target_os = "linux")]
mod process;
mod state;

use self::cli_and_fds::CliAndFdsStep;
#[cfg(target_os = "linux")]
use self::compat::CompatStep;
use self::context::SandboxContext;
use self::fs_policy::FsPolicyStep;
use self::machine::{Failure, Machine, Progress};
#[cfg(unix)]
use self::network::NetworkStep;
use self::probe::Probe;
#[cfg(target_os = "linux")]
use self::process::ProcessStep;
use crate::outcome::CommandOutcome;
use clap::ValueEnum;
use clap::builder::PossibleValue;
use proptest::test_runner::{Config, RngSeed};
use std::fmt;
use std::hash::{BuildHasher, RandomState};
use std::io::{self, IsTerminal, Write};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Scenario {
    CliAndFds,
    FsPolicy,
    #[cfg(unix)]
    Network,
    #[cfg(target_os = "linux")]
    Process,
    #[cfg(target_os = "linux")]
    Compat,
}

impl Scenario {
    fn default_cases(self) -> u32 {
        match self {
            Self::CliAndFds => 24,
            Self::FsPolicy => 80,
            #[cfg(unix)]
            Self::Network => 40,
            #[cfg(target_os = "linux")]
            Self::Process => 16,
            #[cfg(target_os = "linux")]
            Self::Compat => 1,
        }
    }

    fn run(self, config: &Config, progress: &dyn Fn(Progress)) -> Result<(), Failure> {
        match self {
            Self::CliAndFds => Machine::<CliAndFdsStep>::run(config, 6..10, progress),
            Self::FsPolicy => Machine::<FsPolicyStep>::run(config, 10..18, progress),
            #[cfg(unix)]
            Self::Network => Machine::<NetworkStep>::run(config, 4..8, progress),
            #[cfg(target_os = "linux")]
            Self::Process => Machine::<ProcessStep>::run(config, 5..9, progress),
            #[cfg(target_os = "linux")]
            Self::Compat => Machine::<CompatStep>::run(config, 1..2, progress),
        }
    }
}

impl fmt::Display for Scenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.to_possible_value()
            .as_ref()
            .map_or("", PossibleValue::get_name)
            .fmt(f)
    }
}

#[derive(Debug, clap::Args)]
pub(crate) struct SelftestArgs {
    /// Seed for case generation; every run prints the seed it used.
    #[arg(long, value_name = "SEED")]
    seed: Option<u64>,

    /// Cases per scenario, overriding each scenario's default.
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u32).range(1..))]
    cases: Option<u32>,

    /// Scenarios to run; all when omitted.
    #[arg(value_enum, value_name = "SCENARIO")]
    scenarios: Vec<Scenario>,
}

impl SelftestArgs {
    pub(crate) fn run(&self) -> io::Result<CommandOutcome> {
        let seed = self
            .seed
            .unwrap_or_else(|| RandomState::new().hash_one(Instant::now()));
        let scenarios = if self.scenarios.is_empty() {
            Scenario::value_variants()
        } else {
            &self.scenarios
        };
        let mut out = io::stdout();
        writeln!(out, "seed {seed}")?;
        let interactive = io::stderr().is_terminal();
        let mut passed = true;
        for &scenario in scenarios {
            let cases = self.cases.unwrap_or_else(|| scenario.default_cases());
            let config = Config {
                cases,
                failure_persistence: None,
                max_shrink_iters: 32,
                rng_seed: RngSeed::Fixed(seed),
                ..Config::default()
            };
            let started = Instant::now();
            let progress = |progress| {
                if !interactive {
                    return;
                }
                let elapsed = started.elapsed().as_secs_f64();
                let line = match progress {
                    Progress::Case(case) => format!("case {case}/{cases}"),
                    Progress::Shrink(step) => format!("failed, shrinking step {step}"),
                };
                let _ = write!(io::stderr(), "\r\x1b[K{scenario:<12} {line} {elapsed:.1}s");
            };
            let result = scenario.run(&config, &progress);
            if interactive {
                write!(io::stderr(), "\r\x1b[K")?;
            }
            let elapsed = started.elapsed().as_secs_f64();
            let verdict = if result.is_ok() { "passed" } else { "failed" };
            writeln!(
                out,
                "{scenario:<12} {verdict} {cases:>3} cases {elapsed:>7.1}s"
            )?;
            if let Err(failure) = result {
                passed = false;
                write!(out, "{failure}")?;
                writeln!(out, "  replay: landstrip selftest --seed {seed} {scenario}")?;
            }
        }
        let _ = state::robust_remove(&SandboxContext::scratch_root());
        Ok(CommandOutcome::Exit(i32::from(!passed)))
    }
}

#[derive(Debug, clap::Args)]
pub(crate) struct WorkerArgs {
    probe: Probe,
}

impl WorkerArgs {
    pub(crate) const SUBCOMMAND: &str = "__worker";

    pub(crate) fn run(&self) -> CommandOutcome {
        CommandOutcome::Exit(self.probe.run())
    }
}
