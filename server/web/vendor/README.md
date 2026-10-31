# Vendored browser libraries

The TCPing chart's libraries, served by this site instead of a public CDN.
The files are the unmodified release builds from npm. The table component
imports them with `?url`, so the build copies them byte for byte into
`dist/_astro/` under a content-hashed name, cached as immutable. The
`integrity` value the page loads each one with is the SHA-384 below.

| File | Package | npm tarball integrity | SHA-384 (SRI) |
| --- | --- | --- | --- |
| `chart.js/chart.umd.js` | [chart.js 4.4.0](https://www.npmjs.com/package/chart.js/v/4.4.0) `dist/chart.umd.js` | `sha512-vQEj6d+z0dcsKLlQvbKIMYFHd3t8W/7L2vfJIbYcfyPcRx92CsHqECpueN8qVGNlKyDcr5wBrYAYKnfu/9Q1hQ==` | `sha384-FcQlsUOd0TJjROrBxhJdUhXTUgNJQxTMcxZe6nHbaEfFL1zjQ+bq/uRoBQxb0KMo` |
| `chartjs-adapter-date-fns/chartjs-adapter-date-fns.bundle.min.js` | [chartjs-adapter-date-fns 3.0.0](https://www.npmjs.com/package/chartjs-adapter-date-fns/v/3.0.0) `dist/chartjs-adapter-date-fns.bundle.min.js` (date-fns 2 bundled in) | `sha512-Rs3iEB3Q5pJ973J93OBTpnP7qoGwvq3nUnoMdtxO+9aoJof7UFcRbWcIDteXuYd1fgAvct/32T9qaLyLuZVwCg==` | `sha384-cVMg8E3QFwTvGCDuK+ET4PD341jF3W8nO1auiXfuZNQkzbUUiBGLsIQUE+b1mxws` |

A CDN or proxy in front of the site has to pass these files through
unchanged (no JavaScript minification or other rewriting), or the integrity
check stops them and the chart does not load.

Chart.js, the adapter and date-fns are MIT licensed; their license files
are next to the scripts.

To check a file against the release (from `server/web`):

```sh
npm pack chart.js@4.4.0 && tar -xzf chart.js-4.4.0.tgz package/dist/chart.umd.js
cmp package/dist/chart.umd.js vendor/chart.js/chart.umd.js
```

To upgrade, replace the file, update the version and both hashes here, and
the `integrity` values in `src/components/SystemTable.astro` and the preload
links in `src/pages/index.astro`
(`openssl dgst -sha384 -binary FILE | base64`).
