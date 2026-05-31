# landstrip

`landstrip` is an agent sandbox based on Landlock. The state is always
parametrized and there are no pre-defined policy file or directory locations.

## Sandbox model

### Files

`landstrip` defines filesystem configuration as a Landlock allowlist. Deny
rules are handled by traversing the directory tree and allowing only the roots
that remain after subtracting denied paths.

In other words, policy has snapshot semantics: access is based on the
filesystem objects that existed and were opened when the sandbox was created.

Landlock rules are not path-based rules. If an allowed directory is removed and
the same pathname is created again later, the new directory is a different
filesystem object and is not automatically allowed. It becomes accessible only
when an allowed ancestor rule covers it.

Directories created outside the sandbox after policy setup are not exposed
merely because their paths match a previous traversal result.

### Network

`landstrip` uses Landlock TCP port rules to define network policy. When the
sandbox is applied, direct TCP connections are denied by default.
`httpProxyPort` and `socksProxyPort` allow direct connections to configured
proxy ports.

`allowLocalBinding` allows TCP binding to loopback addresses. Because Landlock
cannot process local addresses, this mode uses a seccomp user-notification
broker for `bind(2)` and fails closed if that facility is unavailable.
Domain allow and deny lists are parsed but skipped. `landstrip` does not
currently provide UDP or general address-based network filtering for the time
being.

## Documenting errors

The following snippet demonstrates the recommended pattern for documenting
the return values on error:

```
/// # Errors
///
/// Returns [`<variant's unqualified name>`](<variant's unqualified name>)
/// Returns ...
```

## Licensing

`landstrip` is licensed under `LGPL-2.1-or-later`.
