// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

use super::context::SandboxContext;
use super::state::SandboxState;
use proptest::prelude::*;
use proptest::test_runner::{Config, TestCaseResult, TestError, TestRunner};
use proptest_state_machine::ReferenceStateMachine;
use std::cell::Cell;
use std::fmt::{self, Debug, Display};
use std::marker::PhantomData;
use std::ops::Range;
use std::sync::atomic::{AtomicUsize, Ordering};

pub trait Step: Debug {
    fn apply(&self, state: &mut SandboxState) -> TestCaseResult;
}

pub trait Transition:
    Arbitrary<Strategy = BoxedStrategy<Self>> + AsRef<dyn Step> + Clone + Debug + 'static
{
}

impl<T> Transition for T where
    T: Arbitrary<Strategy = BoxedStrategy<T>> + AsRef<dyn Step> + Clone + Debug + 'static
{
}

pub trait Require<T> {
    fn require(self, what: &str) -> Result<T, TestCaseError>;
}

impl<T, E: Display> Require<T> for Result<T, E> {
    fn require(self, what: &str) -> Result<T, TestCaseError> {
        self.map_err(|error| TestCaseError::fail(format!("{what}: {error}")))
    }
}

impl<T> Require<T> for Option<T> {
    fn require(self, what: &str) -> Result<T, TestCaseError> {
        self.ok_or_else(|| TestCaseError::fail(what.to_owned()))
    }
}

#[derive(Debug)]
pub enum Failure {
    Check { reason: String, steps: Vec<String> },
    Abort(String),
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Check { reason, steps } => {
                writeln!(f, "  reason: {reason}")?;
                writeln!(f, "  steps:")?;
                steps
                    .iter()
                    .enumerate()
                    .try_for_each(|(index, step)| writeln!(f, "    {}. {step}", index + 1))
            }
            Self::Abort(reason) => writeln!(f, "  aborted: {reason}"),
        }
    }
}

/// Where a run is: the case being generated, or the shrink step after a
/// failure.
#[derive(Debug, Clone, Copy)]
pub enum Progress {
    Case(u32),
    Shrink(u32),
}

pub struct Machine<T>(PhantomData<T>);

impl<T: Transition> Machine<T> {
    pub fn run(
        config: &Config,
        steps: Range<usize>,
        ctx: &SandboxContext,
        progress: &dyn Fn(Progress),
    ) -> Result<(), Failure> {
        let failed = Cell::new(false);
        let calls = Cell::new(0);
        TestRunner::new(config.clone())
            .run(
                &Self::sequential_strategy(steps),
                |((), transitions, seen)| {
                    calls.set(calls.get() + 1);
                    progress(if failed.get() {
                        Progress::Shrink(calls.get())
                    } else {
                        Progress::Case(calls.get())
                    });
                    let result = Self::apply(&transitions, ctx, seen.as_deref());
                    if result.is_err() && !failed.replace(true) {
                        calls.set(0);
                    }
                    result
                },
            )
            .map_err(|error| match error {
                TestError::Fail(reason, ((), transitions, _)) => Failure::Check {
                    reason: reason.message().to_owned(),
                    steps: transitions.iter().map(|step| format!("{step:?}")).collect(),
                },
                TestError::Abort(reason) => Failure::Abort(reason.message().to_owned()),
            })
    }

    fn apply(
        transitions: &[T],
        ctx: &SandboxContext,
        seen: Option<&AtomicUsize>,
    ) -> TestCaseResult {
        let mut state = SandboxState::new(ctx.clone());
        state.verify_invariants()?;
        for transition in transitions {
            if let Some(seen) = seen {
                seen.fetch_add(1, Ordering::SeqCst);
            }
            transition.as_ref().apply(&mut state)?;
            state.verify_invariants()?;
        }
        Ok(())
    }
}

impl<T: Transition> ReferenceStateMachine for Machine<T> {
    type State = ();
    type Transition = T;

    fn init_state() -> BoxedStrategy<Self::State> {
        Just(()).boxed()
    }

    fn transitions((): &Self::State) -> BoxedStrategy<Self::Transition> {
        any::<T>()
    }

    fn apply((): Self::State, _: &Self::Transition) -> Self::State {}
}
