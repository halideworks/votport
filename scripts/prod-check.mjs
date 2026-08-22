// Read-only production check: forge nothing here; the token arrives via env.
import { chromium } from "playwright";
const browser = await chromium.launch();
const page = await browser.newPage();
const errors = [];
page.on("pageerror", (e) => errors.push(e.message));
await page.goto(process.env.BASE_URL + "/links");
await page.context().addCookies([
  {
    name: "votport_admin",
    value: process.env.ADMIN_TOKEN,
    url: process.env.BASE_URL,
  },
]);
await page.goto(process.env.BASE_URL + "/links");
await page.waitForSelector("#create-form", { timeout: 15000 });
const navItems = await page.$$eval("#nav a", (as) =>
  as.map((a) => a.textContent),
);
const linkCards = await page.$$eval("#links .link-item", (els) => els.length);
const emptyNote = await page.$eval("#links", (el) => el.textContent.trim());
const receiveDir = await page.$eval("#receive-dir", (el) => el.textContent);
console.log("nav:", navItems.join(", "));
console.log("link cards:", linkCards, "| note:", JSON.stringify(emptyNote));
console.log(receiveDir);
console.log("pageerrors:", errors.length ? errors.join(" | ") : "none");
await browser.close();
if (errors.length) process.exit(1);
