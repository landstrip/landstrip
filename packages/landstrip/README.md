# landstrip

This package builds the `landstrip` binary that the CLI and the Node.js API run,
and ships its [man page](man/man1/landstrip.1). The binary enforces the policy
with KVM or Landlock/seccomp on Linux, Seatbelt on macOS, and AppContainer on
Windows. Run `landstrip --help` for the command list.

## Build

```sh
make test
```

## License

Licensed under [LGPL-2.1-or-later](LICENSE).
