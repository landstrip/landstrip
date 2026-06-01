# landstrip

`landstrip` is an agent sandbox based on Landlock. The state is always
parametrized and there are no pre-defined policy file or directory locations.

## Sandbox model

### Files

`landstrip` defines filesystem configuration as a Landlock allowlist. Deny rules
are handled by traversing the directory tree and allowing only the roots that
remain after subtracting denied paths.

In other words, policy has snapshot semantics: access is based on the filesystem
objects that existed and were opened when the sandbox was created.

Landlock rules are not path-based rules. If an allowed directory is removed and
the same pathname is created again later, the new directory is a different
filesystem object and is not automatically allowed. It becomes accessible only
when an allowed ancestor rule covers it.

Directories created outside the sandbox after policy setup are not exposed
merely because their paths match a previous traversal result.

### Network

For TCP port rules `landstrip` uses Landlock TCP port rules and a seccomp
user-notification broker for address-level decisions. When the sandbox is
applied, direct TCP connections are denied by default.

`httpProxyPort` and `socksProxyPort` select local HTTP and SOCKS proxy ports.
Connections to these ports are allowed only on loopback addresses. If domain
filters are configured, `landstrip` starts the corresponding proxies and exports
proxy environment variables to the child. `HTTP_PROXY` and `SOCKS_PROXY` provide
defaults that the JSON attributes override.

`allowUnixSockets` lists Unix domain socket paths the policy permits.
`allowAllUnixSockets` disables Unix domain socket path restriction. The default
is to permit no Unix domain socket paths once Unix socket enforcement is active.

## Documenting errors

The following snippet demonstrates the recommended pattern for documenting the
return values on error:

```
/// # Errors
///
/// Returns [`<variant's unqualified name>`](<variant's unqualified name>)
/// Returns ...
```

## Licensing

`landstrip` is licensed under `LGPL-2.1-or-later`.
