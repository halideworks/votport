let hintId = 0;
const mounted = new WeakSet();
export function mountHints(root = document) {
  for (const trigger of root.querySelectorAll('[data-hint]')) {
    if (mounted.has(trigger)) continue;
    mounted.add(trigger);
    const hint = document.createElement('span'); hint.id = `field-hint-${++hintId}`; hint.className = 'field-hint';
    hint.popover = 'auto'; hint.setAttribute('role', 'tooltip'); hint.textContent = trigger.dataset.hint;
    trigger.after(hint); trigger.setAttribute('aria-describedby', hint.id);
    const place = () => {
      const box = trigger.getBoundingClientRect();
      hint.style.left = `${Math.max(12, Math.min(box.left, window.innerWidth - hint.offsetWidth - 12))}px`;
      hint.style.top = `${Math.max(12, box.bottom + hint.offsetHeight + 20 < window.innerHeight ? box.bottom + 8 : box.top - hint.offsetHeight - 8)}px`;
    };
    let hoverTimer;
    const show = () => { clearTimeout(hoverTimer); if (hint.isConnected) { hint.showPopover(); place(); } };
    const close = () => { clearTimeout(hoverTimer); if (hint.matches(':popover-open')) hint.hidePopover(); };
    const reposition = () => {
      if (!hint.matches(':popover-open')) return;
      const box = trigger.getBoundingClientRect();
      if (box.bottom < 0 || box.top > window.innerHeight) close(); else place();
    };
    const leave = () => { clearTimeout(hoverTimer); setTimeout(() => { if (!hint.matches(':hover') && !trigger.matches(':hover, :focus-visible')) close(); }, 80); };
    trigger.addEventListener('pointerenter', (event) => { if (event.pointerType === 'mouse') hoverTimer = setTimeout(show, 250); });
    if (trigger.tagName === 'BUTTON') trigger.addEventListener('click', (event) => { event.preventDefault(); show(); });
    else trigger.addEventListener('click', close);
    trigger.addEventListener('focus', () => { if (trigger.matches(':focus-visible')) show(); });
    trigger.addEventListener('pointerleave', leave); trigger.addEventListener('blur', leave); hint.addEventListener('pointerleave', leave);
    hint.addEventListener('toggle', () => { if (hint.matches(':popover-open')) place(); });
    hint.addEventListener('reposition', reposition);
  }
}

function repositionHints() { for (const hint of document.querySelectorAll('.field-hint:popover-open')) hint.dispatchEvent(new window.Event('reposition')); }
window.addEventListener('resize', repositionHints); document.addEventListener('scroll', repositionHints, true);
mountHints();
