// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

#![deny(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable
)]

fn main() {
    landstrip::execute();
}
