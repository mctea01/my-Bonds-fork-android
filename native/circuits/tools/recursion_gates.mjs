// Cost-only fallback for bb 2.1.9's native CircuitStats recursion metadata bug.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { gunzipSync } from 'node:zlib';

const [packagePath, acirPath] = process.argv.slice(2);
const root = resolve(packagePath);
const metadata = JSON.parse(readFileSync(`${root}/package.json`, 'utf8'));
if (metadata.name !== '@aztec/bb.js' || metadata.version !== '2.1.9') {
  throw new Error('Use @aztec/bb.js 2.1.9');
}
const { Barretenberg } = await import(pathToFileURL(`${root}/dest/node/index.js`));
const acir = JSON.parse(readFileSync(acirPath, 'utf8'));
const bytecode = Uint8Array.from(gunzipSync(Buffer.from(acir.bytecode, 'base64')));
const api = await Barretenberg.new({ threads: 1 });
try {
  // The legacy API exposes honk_recursion; native CircuitStats passes zero.
  // Both paths finalize UltraCircuitBuilder and read its finalized gate count.
  const [gates, dyadicSize] = await api.acirGetCircuitSizes(bytecode, false, true);
  process.stdout.write(JSON.stringify({ gates, dyadic_size: dyadicSize }) + '\n');
} finally {
  await api.destroy();
}
