// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Drive the deployed Haven console with a real Chromium instance (used when
// the Claude-in-Chrome browser extension isn't connected). Logs in and
// screenshots Command Deck / Realm Studio / Clients / Atlas.
//
// Usage:
//   HAVEN_BASE_URL=http://host:30742 \
//   HAVEN_USER=admin HAVEN_PASSWORD=<keycloak admin password> \
//   OUT_DIR=/path/to/save/screenshots \
//   node scripts/haven-drive.js
//
// Requires playwright-core + a Chromium install (run from a project that
// already has them, e.g. this repo's own e2e setup, or copy into one that
// does — Node resolves playwright-core relative to this file's directory).
const { chromium } = require('playwright-core');

const BASE = process.env.HAVEN_BASE_URL || 'http://175.110.122.71:30742';
const OUT = process.env.OUT_DIR || '.';
const USER = process.env.HAVEN_USER || 'demo';
const PASSWORD = process.env.HAVEN_PASSWORD || 'demo';

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  page.on('pageerror', (err) => console.log('PAGEERROR', err.message));
  page.on('console', (msg) => { if (msg.type() === 'error') console.log('CONSOLE ERROR', msg.text()); });
  page.on('response', (res) => {
    if (res.status() >= 400) console.log('HTTP', res.status(), res.url());
  });

  await page.goto(`${BASE}/login`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(600);
  await page.screenshot({ path: `${OUT}/haven-login.png` });

  await page.locator('input').first().fill(USER);
  await page.locator('input[type="password"]').fill(PASSWORD);
  await page.getByRole('button', { name: /^Sign in$/ }).click();
  await page.waitForTimeout(2500);
  console.log('URL after login attempt:', page.url());

  if (page.url().includes('/login')) {
    console.log('--- still on login ---');
    console.log((await page.evaluate(() => document.body.innerText)).slice(0, 800));
  } else {
    for (const route of ['deck', 'planes', 'atlas', 'realms', 'clients']) {
      await page.goto(`${BASE}/${route}`, { waitUntil: 'networkidle' });
      await page.waitForTimeout(1200);
      await page.screenshot({ path: `${OUT}/haven-${route}.png` });
    }
  }

  await browser.close();
})();
