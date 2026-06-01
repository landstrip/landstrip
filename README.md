# landstrip

`landstrip` runs a command in a Linux sandbox built from Landlock access control
rules and seccomp.

`landstrip` accepts the Anthropic Sandbox Runtime JSON subset used by the
macOS Seatbelt backend.

## Seatbelt and Landstrip comparison

| Area         | Seatbelt                 | Landstrip                    |
| ------------ | ------------------------ | -----------------------------|
| Policy       | path based rules         | file based rules             |
| Timing       | dynamic subset of paths  | file scan at launch          |
| TCP          | localhost proxy ports    | loopback proxy ports         |
| Unix sockets | allowlist                | allowlist via seccomp broker |

## Licensing

`landstrip` is licensed under `LGPL-2.1-or-later`.
