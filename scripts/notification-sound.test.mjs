import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

const source = await readFile(new URL('../client/windows/Votport/Notifier.cs', import.meta.url), 'utf8');

test('development chime is silent when notifications are blocked or shell state is unavailable', () => {
  const expression = source.match(/bool CanPlaySound\([^)]*\) =>\s*([^;]+);/)[1];
  const allowed = new Function('enabled', 'queryResult', 'state', `return ${expression};`);
  for (const enabled of [false, true]) {
    for (const result of [-1, 0, 1]) {
      for (const state of [0, 1, 2, 3, 4, 5, 6, 7, 8]) {
        assert.equal(allowed(enabled, result, state), enabled && result === 0 && state === 5);
      }
    }
  }
});

test('packaged notification audio stays native and development playback cannot beep twice', async () => {
  const select = unpackaged => source.replace(/#if VOTPORT_UNPACKAGED\n([\s\S]*?)#endif/g,
    (_, block) => block.split('#else\n')[unpackaged ? 0 : 1] ?? '');
  const packaged = select(false);
  assert.match(packaged, /SetAudioUri\(new Uri\("ms-appx:\/\/\/Assets\/completion.wav"\)\)/);
  assert.doesNotMatch(packaged, /MuteAudio|PlaySound/);
  const development = select(true);
  assert.match(development, /MuteAudio\(\)/);
  assert.doesNotMatch(development, /SetAudioUri/);
  assert.match(development, /SndFilename \| SndAsync \| SndNoDefault \| SndSystem/);
  assert.match(development, /if \(!Settings.Notify\) return;/);
  const project = await readFile(new URL('../client/windows/Votport/Votport.csproj', import.meta.url), 'utf8');
  assert.match(project, /<DefineConstants Condition="'\$\(WindowsPackageType\)' == 'None'">\$\(DefineConstants\);VOTPORT_UNPACKAGED<\/DefineConstants>/);
});
