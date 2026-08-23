import { createInterface } from "node:readline";

import { isMutation, publicError, validateRequest } from "./protocol.js";
import { EvedexSdkGateway } from "./sdk_gateway.js";

const MAX_LINE_BYTES = 1024 * 1024;
const MAX_EFFECTS = 10_000;
const seenEffects = new Map();
let gateway;
let queue = Promise.resolve();

function write(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function rememberEffect(effectId) {
  if (seenEffects.has(effectId)) {
    throw new Error("effect_id was already submitted during this sidecar process");
  }
  seenEffects.set(effectId, true);
  if (seenEffects.size > MAX_EFFECTS) {
    seenEffects.delete(seenEffects.keys().next().value);
  }
}

async function handle(line) {
  let id = "invalid";
  try {
    if (Buffer.byteLength(line, "utf8") > MAX_LINE_BYTES) {
      throw new TypeError("request exceeds the 1 MiB protocol limit");
    }
    const request = validateRequest(JSON.parse(line));
    id = request.id;
    if (isMutation(request.operation)) rememberEffect(request.payload.effect_id);
    gateway ??= new EvedexSdkGateway();
    const result = await gateway.call(request.operation, request.payload);
    write({ id, ok: true, result, effect_id: request.payload.effect_id ?? null });
  } catch (error) {
    write({
      id,
      ok: false,
      error: publicError(error, [gateway?.apiKey, gateway?.privateKey]),
    });
  }
}

const input = createInterface({ input: process.stdin, crlfDelay: Infinity, terminal: false });
input.on("line", (line) => {
  // A single promise chain serializes SDK session refresh and every mutation.
  queue = queue.then(() => handle(line));
});
input.on("close", async () => {
  await queue;
  await gateway?.close();
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, async () => {
    await queue;
    await gateway?.close();
    process.exit(0);
  });
}
