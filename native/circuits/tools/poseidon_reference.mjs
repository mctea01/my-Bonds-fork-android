// Synthetic witness oracle only; pinned bb.js already listed in NOTICE.
import readline from 'node:readline';
import { pathToFileURL } from 'node:url';
const { Barretenberg, Fr } = await import(pathToFileURL(process.argv[2]).href);
const api = await Barretenberg.new({ threads: 1 });
for await (const line of readline.createInterface({ input: process.stdin })) {
    const fields = JSON.parse(line).map(x => new Fr(BigInt(x)));
    const result = await api.poseidon2Hash(fields);
    process.stdout.write(JSON.stringify(result.toString()) + '\n');
}
await api.destroy();
