// Gives the neutral greys of the compiled CSS the slight hue of the Beszel
// theme Pulse follows: warm in the light theme (hue 30), cool in the dark
// theme (hue 220), at Beszel's saturations (backgrounds 8 % / 5.5 %,
// borders 8 % / 3.5 %, text 3 %). Only pure greys (R = G = B) change, and
// they keep their lightness, so every contrast stays where it was.
//
// The theme of a rule comes from its selector (.dark / .light). A rule with
// neither takes it from the colour: a dark background or border belongs to
// the dark theme, dark text to the light theme. Glass rules keep their own
// colours.
const HUE = { light: 30, dark: 220 };
const SAT = {
  light: { bg: 0.08, border: 0.08, text: 0.03 },
  dark: { bg: 0.055, border: 0.035, text: 0.03 },
};

function roleOf(prop) {
  if (/^(color|fill|stroke|caret-color|text-decoration-color|-webkit-text-fill-color)$/.test(prop)) return 'text';
  if (/^(border|outline|column-rule)(-|$)|^--tw-ring-(offset-)?color$/.test(prop)) return 'border';
  if (/^background(-color)?$|^--tw-gradient-(from|via|to|stops)$/.test(prop)) return 'bg';
  return null;
}

function themeOf(selector) {
  if (/\.dark(?![\w\\-])/.test(selector)) return 'dark';
  if (/\.light(?![\w\\-])/.test(selector)) return 'light';
  return null;
}

function hsl(h, s, l) {
  const a = s * Math.min(l, 1 - l);
  const f = (n) => {
    const k = (n + h / 30) % 12;
    return l - a * Math.max(-1, Math.min(k - 3, 9 - k, 1));
  };
  return [f(0), f(8), f(4)].map((x) => Math.round(x * 255));
}

function tint(v, role, theme) {
  const t = theme || ((role === 'text') === (v / 255 < 0.5) ? 'light' : 'dark');
  return hsl(HUE[t], SAT[t][role], v / 255);
}

const hex2 = (n) => n.toString(16).padStart(2, '0');

// Splits at the separator only outside parentheses: rgb(28 28 28 /
// var(--tw-bg-opacity, 1)) has a comma inside its alpha.
function splitTop(s, sep) {
  const out = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '(') depth++;
    else if (s[i] === ')') depth--;
    else if (s[i] === sep && depth === 0) { out.push(s.slice(start, i)); start = i + 1; }
  }
  out.push(s.slice(start));
  return out;
}

function tintColors(text, role, theme) {
  return text
    .replace(/#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})(?![0-9a-fA-F])/g, (m, h) => {
      const full = h.length === 3 ? h.split('').map((c) => c + c).join('') : h;
      const [r, g, b] = [0, 2, 4].map((i) => parseInt(full.slice(i, i + 2), 16));
      if (r !== g || g !== b) return m;
      const [R, G, B] = tint(r, role, theme);
      return R === r && G === r && B === r ? m : '#' + [R, G, B].map(hex2).join('');
    })
    .replace(/\b(rgba?)\(((?:[^()]|\([^()]*\))*)\)/g, (m, fn, inner) => {
      const args = splitTop(inner, ',');
      const comma = args.length > 1;
      let parts;
      let alpha = '';
      if (comma) {
        parts = args.slice(0, 3).map((s) => s.trim());
        alpha = args.slice(3).map((s) => s.trim()).join(', ');
      } else {
        const [channels, ...rest] = splitTop(inner, '/');
        parts = channels.trim().split(/\s+/);
        alpha = rest.join('/').trim();
      }
      if (parts.length !== 3 || !parts.every((p) => /^\d+$/.test(p))) return m;
      const [r, g, b] = parts.map(Number);
      if (r !== g || g !== b) return m;
      const [R, G, B] = tint(r, role, theme);
      if (R === r && G === r && B === r) return m;
      return comma
        ? `${fn}(${R}, ${G}, ${B}${alpha ? ', ' + alpha : ''})`
        : `${fn}(${R} ${G} ${B}${alpha ? ' / ' + alpha : ''})`;
    });
}

// Colours inside url(…) (inline SVG backgrounds) stay as they are.
function tintValue(value, role, theme) {
  return value.split(/(url\((?:[^()]|\([^()]*\))*\))/).map((part, i) => (i % 2 ? part : tintColors(part, role, theme))).join('');
}

module.exports = () => ({
  postcssPlugin: 'pulse-tint-neutrals',
  Declaration(decl) {
    const role = roleOf(decl.prop);
    if (!role) return;
    const rule = decl.parent;
    const selector = rule && rule.type === 'rule' ? rule.selector : '';
    if (/glass/.test(selector)) return;
    const next = tintValue(decl.value, role, themeOf(selector));
    if (next !== decl.value) decl.value = next;
  },
});
module.exports.postcss = true;
module.exports.tintValue = tintValue;
