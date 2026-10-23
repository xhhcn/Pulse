#!/usr/bin/env node
// Regenerates the icons shipped with the dashboard (public/icons) and the
// manifest the pages read (src/utils/icon-manifest.ts). Run it by hand from
// server/web with network access — `node scripts/sync-icons.mjs` — and commit
// the result; builds never fetch icons.
//
// Icons larger than MAX_LOCAL_BYTES (a few flags with detailed coats of arms,
// up to ~0.9 MB, and the 195 KB Linux penguin) are left out of the bundle:
// pages fetch those from the Iconify API instead (src/utils/icons.ts).
//
// Flags: every Unicode regional-indicator flag that Emoji One v1 draws, keyed
// by ISO 3166-1 alpha-2 code. The code → name mapping comes from Unicode's
// emoji-test.txt (CLDR short names, matched against the set's names and
// aliases) instead of a hand-written table, plus the four countries whose
// v1 names predate their current CLDR names.
// Logos: the OS icons the agent reports (client/main.go getOSIcon) and the
// CPU brand icons of the admin page, plus the glyphs shown instead of an
// agent icon that does not work at icon size (DISPLAY_ALIASES in
// src/utils/icons.ts).

import { mkdir, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const outDir = join(root, 'public', 'icons');

const EMOJI_TEST = 'https://unicode.org/Public/emoji/latest/emoji-test.txt';
const EMOJIONE_V1 = 'https://cdn.jsdelivr.net/npm/@iconify-json/emojione-v1@1.2.3/icons.json';
const ICONIFY_API = 'https://api.iconify.design';
const MAX_LOCAL_BYTES = 64 * 1024;

// Countries Emoji One v1 knows under an older name.
const FLAG_EXTRA = {
  MM: 'flag-for-myanmar',
  SH: 'flag-for-st-helena',
  TR: 'flag-for-turkey',
  VI: 'flag-for-us-virgin-islands',
};

// Icon name → height requested before (OS icons at 26 px in the Pulse table,
// CPU logos at 32 px on the admin page).
const LOGOS = {
  'devicon:almalinux': 26, 'devicon:apple': 26, 'devicon:archlinux': 26,
  'devicon:centos': 26, 'devicon:debian': 26, 'devicon:fedora': 26,
  'devicon:gentoo': 26, 'devicon:linux': 26, 'devicon:nixos': 26,
  'devicon:opensuse': 26, 'devicon:oracle': 26, 'devicon:redhat': 26,
  'devicon:rockylinux': 26, 'logos:ubuntu': 26, 'logos:microsoft-windows-icon': 26,
  'logos:amd': 32, 'logos:apple': 32, 'logos:arm': 32, 'logos:intel': 32,
  'simple-icons:oracle': 26,
};

// Logos drawn in currentColor, given their brand colour here.
const LOGO_COLORS = {
  'simple-icons:oracle': '#ea1b22',
};

async function get(url, as = 'text') {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return as === 'json' ? res.json() : res.text();
}

function slug(s) {
  return s.normalize('NFKD').replace(/[̀-ͯ]/g, '').toLowerCase()
    .replace(/&/g, 'and').replace(/[’']/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

async function main() {
  const [emojiTest, set] = await Promise.all([get(EMOJI_TEST), get(EMOJIONE_V1, 'json')]);
  const aliases = set.aliases || {};
  const resolve = (name) => {
    for (let i = 0; i < 5 && aliases[name]; i++) name = aliases[name].parent;
    return set.icons[name] ? name : null;
  };

  const flags = {};
  const re = /^(1F1[0-9A-F]{2}) (1F1[0-9A-F]{2})\s*; fully-qualified\s*#\s*\S+\s+E[\d.]+\s+flag: (.+)$/;
  for (const line of emojiTest.split('\n')) {
    const m = re.exec(line.trim());
    if (!m) continue;
    const iso = String.fromCharCode(parseInt(m[1], 16) - 0x1f1e6 + 65, parseInt(m[2], 16) - 0x1f1e6 + 65);
    const s = slug(m[3]);
    const hit = resolve(`flag-for-flag-${s}`) || resolve(`flag-for-${s}`);
    if (hit) flags[iso] = hit;
  }
  for (const [iso, name] of Object.entries(FLAG_EXTRA)) {
    if (!set.icons[name]) throw new Error(`emojione-v1 has no ${name}`);
    flags[iso] = name;
  }

  await rm(outDir, { recursive: true, force: true });
  const local = [];
  const remote = [];
  const save = async (prefix, name, svg) => {
    if (Buffer.byteLength(svg) > MAX_LOCAL_BYTES) {
      remote.push(`${prefix}:${name}`);
      return;
    }
    await mkdir(join(outDir, prefix), { recursive: true });
    await writeFile(join(outDir, prefix, `${name}.svg`), svg);
    local.push(`${prefix}:${name}`);
  };

  const width = set.width || 16, height = set.height || 16;
  for (const name of new Set(Object.values(flags))) {
    const icon = set.icons[name];
    if (icon.rotate || icon.hFlip || icon.vFlip) throw new Error(`${name}: transformed icons are not handled`);
    const w = icon.width || width, h = icon.height || height;
    // Same markup the iconify API returns for `?height=32`.
    await save('emojione-v1', name, `<svg xmlns="http://www.w3.org/2000/svg" width="${Math.round((32 * w) / h)}" height="32" viewBox="${icon.left || 0} ${icon.top || 0} ${w} ${h}">${icon.body}</svg>`);
  }

  for (const [full, px] of Object.entries(LOGOS)) {
    const [prefix, name] = full.split(':');
    const color = LOGO_COLORS[full] ? `&color=${encodeURIComponent(LOGO_COLORS[full])}` : '';
    await save(prefix, name, await get(`${ICONIFY_API}/${prefix}/${name}.svg?height=${px}${color}`));
  }

  await writeFile(join(outDir, 'ATTRIBUTION.txt'), [
    'Icons shipped with the dashboard (regenerate with scripts/sync-icons.mjs).',
    '',
    'emojione-v1/  Emoji One (v1) by Emoji One — CC BY-SA 4.0',
    '              https://github.com/joypixels/emojione-legacy',
    '              https://creativecommons.org/licenses/by-sa/4.0/',
    'devicon/      Devicon by konpa — MIT',
    '              https://github.com/devicons/devicon/blob/master/LICENSE',
    'logos/        SVG Logos by Gil Barbara — CC0 1.0',
    '              https://github.com/gilbarbara/logos',
    'simple-icons/ Simple Icons — CC0 1.0',
    '              https://github.com/simple-icons/simple-icons',
    '',
    'Files are unmodified icon data, as served by the Iconify API (simple-icons/',
    'oracle.svg with its brand colour, through the API\'s color parameter).',
    '',
  ].join('\n'));

  local.sort();
  const sortedFlags = Object.fromEntries(Object.entries(flags).sort(([a], [b]) => a.localeCompare(b)));
  await writeFile(join(root, 'src', 'utils', 'icon-manifest.ts'), [
    '// Generated by scripts/sync-icons.mjs — do not edit by hand.',
    '',
    '/** ISO 3166-1 alpha-2 code → Emoji One (v1) flag icon name. */',
    `export const FLAG_ICONS: Readonly<Record<string, string>> = ${JSON.stringify(sortedFlags, null, 2)};`,
    '',
    '/** Icons served from /icons/<prefix>/<name>.svg. */',
    `export const LOCAL_ICONS: ReadonlySet<string> = new Set(${JSON.stringify(local, null, 2)});`,
    '',
  ].join('\n'));

  console.log(`flags for ${Object.keys(flags).length} codes; ${local.length} icons shipped, ${remote.length} left to the API: ${remote.sort().join(' ')}`);
}

main().catch((err) => { console.error(err); process.exit(1); });
