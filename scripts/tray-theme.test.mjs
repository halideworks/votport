import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

const tray = await readFile(new URL('../client/windows/Votport/Tray.cs', import.meta.url), 'utf8');

test('tray clicks keep the transfer panel separate from the context menu', () => {
  const routing = tray.slice(tray.indexOf('if (mouse == WmLButtonUp)'), tray.indexOf('return IntPtr.Zero;'));
  const dispatch = new Function('mouse', 'panel', 'menu',
    'const WmLButtonUp = 0x0202, WmRButtonUp = 0x0205;\n' + routing);
  for (const mouse of [0x0202, 0x0205, 0]) {
    const calls = [];
    dispatch(mouse, () => calls.push('panel'), () => calls.push('menu'));
    assert.deepEqual(calls, mouse === 0 ? [] : [mouse === 0x0205 ? 'menu' : 'panel']);
  }
});

test('tray window default handling uses Unicode like registration and creation', () => {
  assert.match(tray, /\[DllImport\("user32\.dll", CharSet = CharSet\.Unicode\)\] private static extern IntPtr DefWindowProc/);
});

test('context menu uses native WinUI styling and hides its rich panel host', async () => {
  const panel = await readFile(new URL('../client/windows/Votport/TrayPanel.xaml.cs', import.meta.url), 'utf8');
  assert.match(panel, /new MenuFlyout\(\)/);
  assert.match(panel, /PanelContent.Visibility = Visibility.Collapsed/);
  assert.match(panel, /menu.Closed.*HidePanel\(\)/);
  assert.match(panel, /Control.BorderThicknessProperty, new Thickness\(0\)/);
  assert.doesNotMatch(panel, /RequestedTheme|BackgroundProperty|ForegroundProperty/);
  assert.doesNotMatch(tray, /TrackPopupMenu|CreatePopupMenu/);
});
