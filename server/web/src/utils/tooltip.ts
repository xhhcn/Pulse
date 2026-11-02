// Tooltips like Beszel's for buttons and links that show only an icon: the
// control's name in a small bordered card with an arrow, under the control
// (above it when there is no room), after 100 ms of hover or at once on
// keyboard focus. The browser's own title tooltip is taken off those
// controls (the title becomes the aria-label, which keeps the name for
// screen readers), or both would show. A control can also ask for one with
// data-tooltip="…", or opt out with data-no-tooltip.

const SHOW_DELAY_MS = 100;
const GAP_PX = 8;
const EDGE_PX = 8;

let tip: HTMLDivElement | null = null;
let arrow: HTMLSpanElement | null = null;
let current: HTMLElement | null = null;
let timer = 0;

function tooltipFor(target: EventTarget | null): HTMLElement | null {
  if (!(target instanceof Element)) return null;
  const el = target.closest<HTMLElement>('[data-tooltip], button, a');
  if (!el || el.closest('[data-no-tooltip]')) return null;
  if (!el.hasAttribute('data-tooltip')) {
    const iconOnly = !!el.querySelector('svg') && (el.textContent || '').trim() === '';
    if (!iconOnly) return null;
  }
  return labelOf(el) ? el : null;
}

function labelOf(el: HTMLElement): string {
  return (el.dataset.tooltip || el.getAttribute('title') || el.getAttribute('aria-label') || '').trim();
}

// The title is the freshest name (translations rewrite it): it becomes the
// aria-label and leaves, so no native tooltip follows ours.
function takeTitle(el: HTMLElement) {
  const title = el.getAttribute('title');
  if (!title) return;
  el.setAttribute('aria-label', title);
  el.removeAttribute('title');
}

function ensureTip() {
  if (tip) return;
  tip = document.createElement('div');
  tip.className = 'pulse-tooltip';
  tip.setAttribute('role', 'tooltip');
  tip.setAttribute('aria-hidden', 'true');
  const text = document.createElement('span');
  text.className = 'pulse-tooltip-text';
  arrow = document.createElement('span');
  arrow.className = 'pulse-tooltip-arrow';
  tip.append(text, arrow);
  document.body.appendChild(tip);
}

function place() {
  if (!tip || !arrow || !current) return;
  const r = current.getBoundingClientRect();
  const t = tip.getBoundingClientRect();
  let side = 'bottom';
  let top = r.bottom + GAP_PX;
  if (top + t.height > window.innerHeight - EDGE_PX && r.top - GAP_PX - t.height > EDGE_PX) {
    side = 'top';
    top = r.top - GAP_PX - t.height;
  }
  const centre = r.left + r.width / 2;
  const left = Math.min(Math.max(centre - t.width / 2, EDGE_PX), window.innerWidth - EDGE_PX - t.width);
  tip.dataset.side = side;
  tip.style.top = `${Math.round(top)}px`;
  tip.style.left = `${Math.round(left)}px`;
  arrow.style.left = `${Math.round(Math.min(Math.max(centre - left, 12), t.width - 12))}px`;
}

function show(el: HTMLElement) {
  ensureTip();
  if (!tip) return;
  takeTitle(el);
  const label = labelOf(el);
  if (!label) return;
  current = el;
  (tip.firstElementChild as HTMLElement).textContent = label;
  tip.classList.remove('is-open');
  tip.style.display = 'block';
  place();
  void tip.offsetWidth;
  tip.classList.add('is-open');
}

function hide() {
  window.clearTimeout(timer);
  current = null;
  if (!tip) return;
  tip.classList.remove('is-open');
  tip.style.display = 'none';
}

function init() {
  document.addEventListener('pointerover', (e) => {
    if (e.pointerType === 'touch') return;
    const el = tooltipFor(e.target);
    if (!el || el === current) return;
    // Taken now, before the browser's own tooltip delay runs out.
    takeTitle(el);
    window.clearTimeout(timer);
    if (current) hide();
    timer = window.setTimeout(() => show(el), SHOW_DELAY_MS);
  });
  document.addEventListener('pointerout', (e) => {
    const el = tooltipFor(e.target);
    if (!el) return;
    if (e.relatedTarget instanceof Node && el.contains(e.relatedTarget)) return;
    if (el === current || !current) hide();
  });
  document.addEventListener('focusin', (e) => {
    const el = tooltipFor(e.target);
    if (el && el.matches(':focus-visible')) show(el);
  });
  document.addEventListener('focusout', () => hide());
  document.addEventListener('pointerdown', () => hide(), true);
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') hide(); });
  window.addEventListener('scroll', () => hide(), true);
  window.addEventListener('resize', () => hide());
}

if (typeof window !== 'undefined' && !(window as unknown as { __pulseTooltips?: boolean }).__pulseTooltips) {
  (window as unknown as { __pulseTooltips?: boolean }).__pulseTooltips = true;
  init();
}
