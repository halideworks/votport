// Status strip poll shared by the Receive and Deliver pages.
// VOTPORT PROPRIETARY LICENSE.
//
// Polls /api/admin/status: every 4 seconds while `active(status)` says
// something is moving, every 30 seconds otherwise, never while the tab is
// hidden. `render(status)` paints the cells and may return a promise.

import { api } from '/assets/admin-common.js';

function startOfToday() {
  const day = new Date();
  day.setHours(0, 0, 0, 0);
  return Math.floor(day.getTime() / 1000);
}

export function startStatusPoll({ render, active = () => false }) {
  let timer = null;
  const schedule = (status) => {
    clearTimeout(timer);
    timer = setTimeout(tick, status && active(status) ? 4_000 : 30_000);
  };
  async function tick() {
    clearTimeout(timer);
    if (document.hidden) return;
    let status;
    try {
      status = await api(`/api/admin/status?since=${startOfToday()}`);
    } catch (error) {
      // The session expired under an open tab: the reload lands on sign-in.
      if (error.status === 401) {
        window.location.reload();
        return;
      }
      schedule(null);
      return;
    }
    try {
      await render(status);
    } finally {
      schedule(status);
    }
  }
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) tick();
  });
  tick();
}
