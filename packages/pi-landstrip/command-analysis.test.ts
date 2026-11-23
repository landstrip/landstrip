import { describe, expect, it } from 'vitest';
import {
  createDarwinLogTag,
  extractDomainsFromCommand,
  extractCandidatePaths,
  extractNativeDeniedPath,
  extractNativeWriteDeniedPath,
  extractDeniedPath,
  canonicalizePath,
  findReportedSeatbeltDenial,
  parseSeatbeltDenials,
  querySeatbeltDenials,
  serializeTrapStanza,
} from '@landstrip/landstrip-api/shared';

describe('command analysis and denial path extraction in pi-landstrip', () => {
  const cwd = '/workspace/test';

  it('extracts unique domains from command lines', () => {
    expect(extractDomainsFromCommand('')).toEqual([]);
    expect(
      extractDomainsFromCommand(
        'curl https://api.github.com/v1 and http://pkg.go.dev/test and https://api.github.com/v2',
      ),
    ).toEqual(['api.github.com', 'pkg.go.dev']);
  });

  it('extracts candidate file paths from command lines', () => {
    expect(extractCandidatePaths('')).toEqual([]);
    const candidates = extractCandidatePaths('cat /workspace/hosts ./config.json ~/data.bin -v');
    expect(candidates).toContain('/workspace/hosts');
    expect(candidates).toContain('./config.json');
    expect(candidates).toContain('~/data.bin');
    expect(candidates).not.toContain('-v');
  });

  it('extracts native shell and tool denied paths', () => {
    expect(extractNativeDeniedPath('bash: line 1: /workspace/syslog: Permission denied', cwd)).toBe(
      canonicalizePath('/workspace/syslog', cwd),
    );
    expect(extractNativeDeniedPath('cat: ./my-file.txt: Operation not permitted', cwd)).toBe(
      canonicalizePath('/workspace/test/my-file.txt', cwd),
    );
    expect(extractNativeDeniedPath('cmd: /workspace/Secrets/key.txt: Access is denied.', cwd)).toBe(
      canonicalizePath('/workspace/Secrets/key.txt', cwd),
    );
    if (process.platform === 'win32') {
      expect(extractNativeDeniedPath('cmd: C:\\Secrets\\key.txt: Access is denied.', cwd)).toBe(
        canonicalizePath('C:\\Secrets\\key.txt', cwd),
      );
    }
    expect(extractNativeDeniedPath('ok', cwd)).toBeNull();
  });

  it('extracts native write denials', () => {
    expect(
      extractNativeWriteDeniedPath(
        "touch: cannot touch '/workspace/passwd': Permission denied",
        cwd,
      ),
    ).toBe(canonicalizePath('/workspace/passwd', cwd));
    expect(
      extractNativeWriteDeniedPath(
        "sed: couldn't open temporary file /workspace/test/sed123: Permission denied",
        cwd,
      ),
    ).toBe(canonicalizePath('/workspace/test/sed123', cwd));
    expect(
      extractNativeWriteDeniedPath('cat: /workspace/hosts: Permission denied', cwd),
    ).toBeNull();
  });

  it('extracts denied paths from structured traps and fallbacks', () => {
    expect(
      extractDeniedPath(
        serializeTrapStanza({
          kind: 'filesystem',
          code: 'FILESYSTEM_DENIED',
          state: 'info',
          operation: 'read',
          path: '/workspace/shadow',
          syscall: 'openat',
          errno: 'EACCES',
          reason: 'deny_match',
          mechanism: 'kvm',
          pid: 1,
        }),
        { cwd },
      ),
    ).toBe(canonicalizePath('/workspace/shadow', cwd));
    expect(extractDeniedPath('cat: /workspace/shadow: Permission denied', { cwd })).toBe(
      canonicalizePath('/workspace/shadow', cwd),
    );
    expect(
      extractDeniedPath('kind=internal\ncode=INTERNAL_ERROR\nmessage=Denied\n\n', {
        cwd,
        command: 'cat /workspace/shadow',
      }),
    ).toBe(canonicalizePath('/workspace/shadow', cwd));
    expect(
      extractDeniedPath(
        serializeTrapStanza({
          kind: 'filesystem',
          code: 'FILESYSTEM_DENIED',
          state: 'query',
          query_id: '7',
          operation: 'read',
          path: '/workspace/shadow',
          syscall: 'openat',
          errno: 'EACCES',
          reason: 'allow_miss',
          mechanism: 'kvm',
          pid: 1,
        }),
        { cwd, command: 'cat /workspace/shadow' },
      ),
    ).toBeNull();
  });

  it('correlates macOS Seatbelt unified log denials by logTag', async () => {
    const tag = createDarwinLogTag('pi-landstrip', 'custom-session');
    expect(tag.startsWith('custom-session-')).toBe(true);

    const sampleJsonLog = JSON.stringify([
      {
        eventMessage: `Sandbox: touch(9120) deny(1) file-write-create /workspace/test/blocked.txt (${tag})`,
      },
      {
        eventMessage:
          'Sandbox: cat(9121) deny(1) file-read-data /workspace/other.txt (unrelated-tag)',
      },
      {
        eventMessage: `Sandbox: helper(9122) ${tag} deny(1) mach-lookup com.apple.trustd.agent`,
      },
    ]);

    const parsed = parseSeatbeltDenials(sampleJsonLog, { logTag: tag, cwd });
    expect(parsed).toEqual([
      {
        kind: 'filesystem',
        operation: 'write',
        path: canonicalizePath('/workspace/test/blocked.txt', cwd),
        action: 'file-write-create',
      },
      {
        kind: 'mach',
        service: 'com.apple.trustd.agent',
        action: 'mach-lookup',
      },
    ]);

    let capturedArgs: readonly string[] = [];
    const queried = await querySeatbeltDenials(tag, {
      cwd,
      lastSeconds: 15,
      runLogShow: async (args) => {
        capturedArgs = args;
        return sampleJsonLog;
      },
    });
    expect(capturedArgs).toContain(`eventMessage CONTAINS "${tag}"`);
    expect(queried).toEqual(parsed);
  });

  it('ignores Seatbelt denials not named by a permission error', () => {
    const tty = {
      kind: 'filesystem',
      operation: 'write',
      path: '/dev/tty',
      action: 'file-write-data',
    } as const;
    const pem = {
      kind: 'filesystem',
      operation: 'write',
      path: '/workspace/test/test.pem',
      action: 'file-write-create',
    } as const;
    const denials = [
      { ...tty, path: '/dev/dtracehelper' },
      tty,
      { kind: 'mach', service: 'com.apple.trustd.agent', action: 'mach-lookup' } as const,
      pem,
    ];

    const output = '/bin/bash: test.pem: Operation not permitted\n';
    expect(findReportedSeatbeltDenial(denials, output, 'write')).toEqual(pem);
    expect(findReportedSeatbeltDenial(denials, output, 'read')).toBeUndefined();
    expect(
      findReportedSeatbeltDenial(denials, '/bin/bash: readonly.txt: Permission denied\n'),
    ).toBeUndefined();
    expect(findReportedSeatbeltDenial(denials, 'not a tty\ntest.pem written\n')).toBeUndefined();
    expect(
      findReportedSeatbeltDenial(denials, '/bin/bash: test.pem.bak: Permission denied\n'),
    ).toBeUndefined();
  });
});
