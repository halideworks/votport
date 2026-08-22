import { chromium } from 'playwright';
const browser = await chromium.launch();
const page = await browser.newPage();
page.on('pageerror', (error) => console.log('PAGEERROR at', page.url(), '::', error.stack?.split('\n').slice(0,4).join(' | ')));
await page.goto('http://127.0.0.1:18336/');
await page.waitForSelector('#login');
// forge nothing: log in as admin, land on /links
await page.fill('#login-password', 'browser-e2e-pass');
await page.click('#login-form button[type=submit]');
await page.waitForTimeout(3000);
console.log('final url:', page.url());
await browser.close();
