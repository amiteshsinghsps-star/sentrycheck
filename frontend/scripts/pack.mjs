import { readFile, writeFile } from 'node:fs/promises';
// Raw source imports may use CRLF on Windows. Keep the tracked embedded asset
// identical across contributor platforms and Linux CI.
const html = (await readFile(new URL('../dist/index.html', import.meta.url), 'utf8')).replaceAll('\r\n', '\n');
const marker = ['__', 'SENTRYCHECK', '_DATA', '__'].join('');
if (html.split(marker).length !== 2) throw new Error('Expected exactly one payload placeholder');
if (!html.includes(`<script id="sentrycheck-data" type="application/json">"${marker}"</script>`)) {
  throw new Error('The payload script contract changed');
}
if (/<script\b[^>]*\bsrc\s*=|<link\b[^>]*\brel=["']stylesheet/i.test(html)) {
  throw new Error('Viewer is not self-contained: external script or stylesheet found');
}
await writeFile(new URL('../template.html', import.meta.url), html);
console.log(`Packed standalone template.html (${new TextEncoder().encode(html).length.toLocaleString()} bytes)`);
