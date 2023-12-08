// @ts-check
const { test, expect } = require('@playwright/test');

test.beforeEach(async ({ page }) => {
  await page.goto('http://127.0.0.1:9000/');
  await page.getByLabel('Username').fill('admin'); // TODO could also be: getByRole('textbox', { name: 'Username' }) // which one is better?
  await page.getByLabel('Password').fill('admin');
  await page.getByRole('button', { name: 'Sign in' }).click();
});

test('Plugin Logging Alert should be registered', async ({ page }) => {
  await page.getByRole('button', { name: 'System' }).click();
  await page.getByRole('menuitem', { name: 'Configurations' }).click();
  await page.getByRole('button', { name: 'Plugins' }).click();
  
  await expect(page.getByRole('button', { name: 'Logging' })).toHaveText('Logging Alert');
//  await expect(page.getByText('Logging Alert')).toBeVisible();
//  await expect(page.getByRole('listitem')).toHaveText(['com.airbus_cyber_security.graylog.events.config.LoggingAlertConfig']); // allows to check the text of several locators
//  await expect(page.getByRole('listitem')).toHaveText('com.airbus_cyber_security.graylog.events.config.LoggingAlertConfig'); // strict mode violation
//  await expect(page.getByRole('button')).toHaveText('com.airbus_cyber_security.graylog.events.config.LoggingAlertConfig'); // strict mode violation
//  await expect(page.getByRole('button')).toContainText('com.airbus_cyber_security.graylog.events.config.LoggingAlertConfig'); // strict mode violation
//  await page.getByRole('button', { name: 'com.airbus_cyber_security.' }).click(); // getByRole('button', { name: 'Logging' })
});

/*
test('Plugin name should be short', async ({ page }) => {
  await page.goto('http://127.0.0.1:9000/');
  await page.getByLabel('Username').fill('admin');
  await page.getByLabel('Password').fill('admin');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByText('×Close').click();
  await page.getByRole('menuitem', { name: 'Configurations' }).click();
  await page.getByRole('button', { name: 'Plugins' }).click();
  await page.getByRole('button', { name: 'com.airbus_cyber_security.' }).click();
  await expect(page.locator('#app-root')).toContainText('com.airbus_cyber_security.graylog.events.config.LoggingAlertConfig');
  await page.getByRole('button', { name: 'com.airbus_cyber_security.' }).click();
});
*/

/*
test('get started link', async ({ page }) => {
  await page.goto('https://playwright.dev/');

  // Click the get started link.
  await page.getByRole('link', { name: 'Get started' }).click();

  // Expects page to have a heading with the name of Installation.
  await expect(page.getByRole('heading', { name: 'Installation' })).toBeVisible();
});
*/
