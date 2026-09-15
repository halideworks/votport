import assert from 'node:assert/strict';

export function apiClient(context, base) {
  return async (route, data, method = data ? 'POST' : 'GET') => {
    const response = await context.request.fetch(`${base}/api/${route}`, { method, data, headers: { 'X-Votport': '1' } });
    assert.ok(response.ok(), `${route}: ${response.status()} ${await response.text()}`); return response.json();
  };
}

export async function openAncestors(locator) {
  for (const details of await locator.locator('xpath=ancestor::details').all()) {
    if (await details.getAttribute('open') === null) await details.locator(':scope > summary').click();
  }
}
export async function chooseNotification(host, destination, event) {
  await openAncestors(host);
  await host.getByRole('combobox', { name: 'Send notifications', exact: true }).selectOption('custom');
  const group = host.getByRole('group', { name: destination, exact: true });
  if (!await group.count()) {
    const option = host.locator('.notification-add option').filter({ hasText: `${destination} ·` });
    await host.getByRole('combobox', { name: 'Destination to add', exact: true }).selectOption(await option.getAttribute('value'));
    await host.getByRole('button', { name: 'Add destination', exact: true }).click();
  }
  const checkbox = group.getByLabel(event, { exact: true });
  await openAncestors(checkbox); await checkbox.check();
}
