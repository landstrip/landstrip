import { describe, expect, it } from 'vitest';

import { createLandstripLauncherEnvironment } from './index.ts';

const host = {
  ProgramData: 'C:\\ProgramData',
  LOCALAPPDATA: 'C:\\Users\\me\\AppData\\Local',
  SystemRoot: 'C:\\Windows',
  windir: 'C:\\Windows',
  ComSpec: 'C:\\Windows\\system32\\cmd.exe',
  PATHEXT: '.COM;.EXE;.BAT;.CMD',
  APPDATA: 'C:\\Users\\me\\AppData\\Roaming',
  OPENAI_API_KEY: 'secret',
};

describe('createLandstripLauncherEnvironment', () => {
  it('adds what the Windows runner and its child need to start', () => {
    const env = createLandstripLauncherEnvironment(
      { PATH: 'C:\\bin', HOME: 'C:\\h' },
      host,
      'win32',
    );
    expect(env).toEqual({
      PATH: 'C:\\bin',
      HOME: 'C:\\h',
      ProgramData: 'C:\\ProgramData',
      LOCALAPPDATA: 'C:\\Users\\me\\AppData\\Local',
      SystemRoot: 'C:\\Windows',
      windir: 'C:\\Windows',
      ComSpec: 'C:\\Windows\\system32\\cmd.exe',
      PATHEXT: '.COM;.EXE;.BAT;.CMD',
    });
  });

  it('copies nothing else from the host', () => {
    const env = createLandstripLauncherEnvironment({}, host, 'win32');
    expect(env.APPDATA).toBeUndefined();
    expect(env.OPENAI_API_KEY).toBeUndefined();
  });

  it('skips variables the host does not have', () => {
    expect(
      createLandstripLauncherEnvironment(
        { PATH: 'C:\\bin' },
        { SystemRoot: 'C:\\Windows' },
        'win32',
      ),
    ).toEqual({
      PATH: 'C:\\bin',
      SystemRoot: 'C:\\Windows',
    });
  });

  it('leaves the environment unchanged elsewhere', () => {
    const provider = { PATH: '/usr/bin', HOME: '/home/me' };
    expect(createLandstripLauncherEnvironment(provider, host, 'linux')).toBe(provider);
    expect(createLandstripLauncherEnvironment(provider, host, 'darwin')).toBe(provider);
  });
});
