/* Verify the translation catalog.
 *
 * A missing key renders as the raw key name in the UI, which looks broken and
 * is easy to miss in review. This check is cheap and catches it every build.
 */
import { readFileSync } from 'node:fs';

const html = readFileSync('src/smartdns_dash/templates/index.html', 'utf8');
const js = readFileSync('src/smartdns_dash/static/app.js', 'utf8');

// Keys referenced from the markup and from t() calls in the script.
const used = new Set([
  ...html.matchAll(/data-i18n(?:-html|-ph|-title)?="([^"]+)"/g),
  ...js.matchAll(/\bt\('([^']+)'/g),
].map((m) => m[1]));

// Evaluate just the catalog literal.
const start = js.indexOf('const STR = {');
const end = js.indexOf('\n};', start);
if (start < 0 || end < 0) {
  console.error('could not locate the STR catalog in app.js');
  process.exit(1);
}
const STR = eval('(' + js.slice(start + 'const STR = '.length, end + 2) + ')');

const problems = [];

for (const key of used) {
  if (!(key in STR)) problems.push(`missing key: ${key}`);
}
for (const key of Object.keys(STR)) {
  if (!used.has(key)) problems.push(`unused key: ${key}`);
  const v = STR[key];
  if (!Array.isArray(v) || v.length !== 2) {
    problems.push(`${key}: expected [en, fa]`);
  } else {
    if (!v[0]) problems.push(`${key}: empty English string`);
    if (!v[1]) problems.push(`${key}: empty Persian string`);
  }
}

console.log(`catalog entries: ${Object.keys(STR).length}`);
console.log(`referenced keys: ${used.size}`);

if (problems.length) {
  console.error('\nproblems:');
  for (const p of problems) console.error('  ' + p);
  process.exit(1);
}
console.log('translation catalog is complete');
