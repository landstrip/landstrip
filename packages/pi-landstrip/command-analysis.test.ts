import { describe, expect, it } from 'vitest';
import {
  extractDomainsFromCommand,
  extractCandidatePaths,
  extractNativeDeniedPath,
  extractNativeWriteDeniedPath,
  extractDeniedPath,
  canonicalizePath,
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
});
