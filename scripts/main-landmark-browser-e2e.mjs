import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { chromium } from 'playwright';

const base = process.env.BASE_URL;
const password = process.env.ADMIN_PASSWORD;
if (!base || !password) throw new Error('Use BASE_URL and ADMIN_PASSWORD with an isolated server.');

const browser = await chromium.launch();
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });

  async function checkSkip(route) {
    await page.goto(`${base}${route}`, { waitUntil: 'domcontentloaded' });
    await page.locator('#main-content').waitFor();
    await page.keyboard.press('Tab');
    assert.equal(await page.evaluate(() => document.activeElement?.className), 'skip-link', `${route}: skip link receives first focus`);
    await page.keyboard.press('Enter');
    assert.equal(await page.evaluate(() => document.activeElement?.id), 'main-content', `${route}: skip link focuses main`);
    await page.keyboard.press('Tab');
    assert.ok(await page.evaluate(() => document.querySelector('#main-content').contains(document.activeElement)), `${route}: next tab stays in main`);
  }

  await checkSkip('/');
  await page.fill('#login-password', password);
  await page.locator('#login-form button[type="submit"]').click();
  await page.waitForURL(`${base}/receive`);
  await checkSkip('/receive');
  await checkSkip('/verify');

  await page.context().clearCookies();
  for (const route of ['/', '/verify']) {
    for (const theme of ['dark', 'light']) {
      for (const width of [320, 390, 1440]) {
        await page.setViewportSize({ width, height: 1000 });
        await page.goto(`${base}${route}`, { waitUntil: 'domcontentloaded' });
        await page.evaluate((themeName) => { document.documentElement.dataset.theme = themeName; }, theme);
        assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `${route}: ${theme} overflow at ${width}px`);
      }
    }
  }
  await page.goto(`${base}/`);
  await page.fill('#login-password', password);
  await page.locator('#login-form button[type="submit"]').click();
  await page.waitForURL(`${base}/receive`);
  for (const theme of ['dark', 'light']) {
    for (const width of [320, 390, 1440]) {
      await page.setViewportSize({ width, height: 1000 });
      await page.goto(`${base}/receive`, { waitUntil: 'domcontentloaded' });
      await page.evaluate((themeName) => { document.documentElement.dataset.theme = themeName; }, theme);
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `/receive: ${theme} overflow at ${width}px`);
    }
  }

  const requestStates = {
    closed: {
      usable: false,
      label: 'Closed request fixture',
      needs_password: false,
      authorized: false,
    },
    gate: {
      usable: true,
      label: 'Password request fixture',
      needs_password: true,
      authorized: false,
      chunk_bytes: 8 * 1024 * 1024,
      max_entries: 1000,
      max_bytes: 1000000,
      allow_hidden: true,
    },
    open: {
      usable: true,
      label: 'Open request fixture',
      needs_password: false,
      authorized: true,
      chunk_bytes: 8 * 1024 * 1024,
      max_entries: 1000,
      max_bytes: 1000000,
      allow_hidden: true,
    },
  };
  const requestTokens = new Map(Object.keys(requestStates).map((state) => [`landmark-${state}`, state]));
  await page.route('**/api/r/*', async (route) => {
    const url = new URL(route.request().url());
    const token = url.pathname.split('/').filter(Boolean).at(-1);
    const state = requestTokens.get(token);
    if (!state || url.pathname !== `/api/r/${token}`) return route.continue();
    await route.fulfill({ contentType: 'application/json', body: JSON.stringify(requestStates[state]) });
  });

  const screenshotDir = process.env.SCREENSHOT_DIR;
  if (screenshotDir) await mkdir(screenshotDir, { recursive: true });
  async function checkRequestGeometry(state, theme, width) {
    const token = `landmark-${state}`;
    await page.setViewportSize({ width, height: 1000 });
    await page.goto(`${base}/r/${token}`, { waitUntil: 'domcontentloaded' });
    await page.evaluate((themeName) => { document.documentElement.dataset.theme = themeName; }, theme);
    const visibleSelector = state === 'closed' ? '#closed:not([hidden])' : state === 'gate' ? '#gate:not([hidden])' : '#uploader:not([hidden])';
    await page.waitForSelector(visibleSelector, { timeout: 15000 });
    const geometry = await page.evaluate(() => {
      const read = (selector) => {
        const node = document.querySelector(selector);
        if (!node) return null;
        const rect = node.getBoundingClientRect();
        const style = getComputedStyle(node);
        return {
          top: rect.top,
          bottom: rect.bottom,
          height: rect.height,
          width: rect.width,
          display: style.display,
          flex: style.flex,
          flexDirection: style.flexDirection,
        };
      };
      return {
        sheet: read('.sheet'),
        main: read('#main-content'),
        masthead: read('.masthead'),
        footer: read('.sheet-foot'),
        closed: read('#closed'),
        gate: read('#gate'),
        uploader: read('#uploader'),
        form: read('#upload-form'),
        drop: read('#drop'),
        send: read('#send'),
      };
    });
    assert.equal(geometry.main.display, 'flex', `${state}: main keeps the public sheet flex context`);
    assert.equal(geometry.main.flexDirection, 'column', `${state}: main lays out content vertically`);
    assert.ok(geometry.main.height > 0, `${state}: main has measurable height`);
    assert.ok(geometry.main.bottom <= geometry.sheet.bottom + 1, `${state}: main stays inside the sheet`);
    if (state === 'open') {
      const freeHeight = geometry.main.bottom - geometry.masthead.bottom;
      assert.ok(geometry.uploader.height >= freeHeight * 0.8, 'open request uploader fills the available main height');
      assert.ok(geometry.drop.top - geometry.form.top > geometry.form.height * 0.15, 'open request drop zone is vertically distributed');
      assert.ok(geometry.form.bottom - geometry.send.bottom <= 2, 'open request send action remains at the form bottom');
    } else {
      const panel = geometry[state];
      const freeAbove = panel.top - geometry.masthead.bottom;
      const freeBelow = geometry.main.bottom - panel.bottom;
      assert.ok(freeAbove > 20, `${state}: panel has space above for vertical centering`);
      assert.ok(freeBelow > 20, `${state}: panel has space below for vertical centering`);
      assert.ok(Math.abs(freeAbove - freeBelow) <= Math.max(48, geometry.main.height * 0.18), `${state}: panel remains vertically centered`);
    }
    if (screenshotDir && (width === 320 || width === 1440)) {
      await page.screenshot({ path: join(screenshotDir, `request-${state}-${width}-${theme}.png`), fullPage: true });
    }
  }

  for (const state of ['closed', 'gate', 'open']) {
    for (const theme of ['dark', 'light']) {
      for (const width of [320, 390, 1440]) {
        await checkRequestGeometry(state, theme, width);
      }
    }
  }
  await page.unroute('**/api/r/*');
  console.log('Main landmark browser checks passed: skip focus, main containment, request state geometry, and dark/light overflow at 320/390/1440px.');
} finally {
  await browser.close();
}
