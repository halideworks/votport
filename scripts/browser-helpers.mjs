import assert from 'node:assert/strict';

export function apiClient(context, base) {
  return async (route, data, method = data ? 'POST' : 'GET') => {
    const response = await context.request.fetch(`${base}/api/${route}`, { method, data, headers: { 'X-Votport': '1' } });
    assert.ok(response.ok(), `${route}: ${response.status()} ${await response.text()}`); return response.json();
  };
}

// POSTs a library grant; when the server answers 202 with a preparation id,
// polls the progress endpoint to a terminal state and returns the grant
// payload (`grant`/`url`) the synchronous API used to give.
export async function settleGrant(context, base, data) {
  const fetch = (route, options) => context.request.fetch(`${base}/api/${route}`, { headers: { 'X-Votport': '1' }, ...options });
  const response = await fetch('admin/outbound-grants/preparations', { method: 'POST', data });
  if (response.status() !== 202) {
    assert.ok(response.ok(), `admin/outbound-grants/preparations: ${response.status()} ${await response.text()}`);
    return response.json();
  }
  const { preparation_id: id } = await response.json();
  for (;;) {
    const poll = await fetch(`admin/outbound-grants/preparations/${id}`, { method: 'GET' });
    assert.ok(poll.ok(), `grant preparation ${id}: ${poll.status()} ${await poll.text()}`);
    const snapshot = await poll.json();
    assert.notEqual(snapshot.status, 'failed', `grant preparation failed: ${snapshot.error}`);
    if (snapshot.status === 'complete') return { grant: snapshot.grant, url: snapshot.url };
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

// One-shot page.route interceptions intermittently stall the next navigation forever on an idle keep-alive connection (Chromium/Playwright CDP Fetch race); a fresh page in the same context always loads.
export async function reloadWithInterceptRetry(page, arm, navigate, { attempts = 2 } = {}) {
  for (let left = attempts; ; left -= 1) {
    await arm(page);
    try {
      await navigate(page);
      return page;
    } catch (error) {
      if (error.name !== 'TimeoutError' || left <= 1) throw error;
      await page.close();
      page = await page.context().newPage();
    }
  }
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
