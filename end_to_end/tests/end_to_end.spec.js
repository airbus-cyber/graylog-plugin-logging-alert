// @ts-check
const { execSync } = require('child_process');
const { test, expect } = require('@playwright/test');

test.beforeAll(async () => {
    test.setTimeout(5*60*1000);
    execSync('../validation/graylog_control start');
});


test.afterAll(async () => {
    execSync('../validation/graylog_control stop');
});

test.beforeEach(async ({ page }) => {
  await page.goto('http://127.0.0.1:9000/');
  // note: could also be: getByRole('textbox', { name: 'Username' })
  await page.getByLabel('Username').fill('admin');
  await page.getByLabel('Password').fill('admin');
  await page.getByRole('button', { name: 'Sign in' }).click();

  // TODO there will most probably be a problem here on the second test: this should only be done once. Find a way to set this state once and for all before (maybe there is some REST API for that...)
  await page.getByText('×Close').click();
});

test('Plugin Logging Alert should be registered (issue #50)', async ({ page }) => {
  await page.getByRole('button', { name: 'System' }).click();
  await page.getByRole('menuitem', { name: 'Configurations' }).click();
  await page.getByRole('button', { name: 'Plugins' }).click();
  
// note: could also be: await expect(page.getByText('Logging Alert')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Logging' })).toHaveText('Logging Alert');
});

