# landstrip

`landstrip` runs a command in an OS-level sandbox using Landlock LSM on Linux,
Seatbelt on macOS, and LPAC AppContainer on Windows.  It accepts the Anthropic
Sandbox Runtime JSON subset as the policy.

Backends compared:

| Area         | macOS                    | Linux                        | Windows                         |
| ------------ | ------------------------ | ---------------------------- | ------------------------------- |
| Policy       | path based rules         | file based rules             | access control list (ACL)       |
| Timing       | dynamic subset of paths  | file based static ruleset    | persistent ACLs                 |
| TCP          | localhost proxy ports    | loopback proxy ports         | allowlist                       |
| Unix sockets | allowlist                | allowlist via seccomp broker | unsupported                     |

Windows uses a AppContainer. The backend grants the generated AppContainer SID
access to the lowered read and write roots, so Windows policies must use
explicit read allowlists. TCP and Unix socket policies are rejected until
Windows enforcement exists.

## Licensing

`landstrip` is licensed under `LGPL-2.1-or-later`.
