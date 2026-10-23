import assert from "node:assert/strict";
import test from "node:test";

import { MAX_RESPONSE_BYTES, serializeProdResponse } from "../src/prod_protocol.js";

test("bounded multi-megabyte parsed SDK responses pass through one NDJSON envelope", () => {
  const result = { payload: "x".repeat(4 * 1024 * 1024) };
  const frame = serializeProdResponse("request-1", { ok: true, result });
  assert.ok(Buffer.byteLength(frame, "utf8") > 4 * 1024 * 1024);
  assert.ok(Buffer.byteLength(frame, "utf8") <= MAX_RESPONSE_BYTES + 1);
  assert.deepEqual(JSON.parse(frame), { id: "request-1", ok: true, result });
});

test("an oversized SDK response becomes a fixed refusal that marks outcome unresolved", () => {
  const frame = serializeProdResponse("request-2", {
    ok: true,
    result: { payload: "x".repeat(MAX_RESPONSE_BYTES + 1) },
  });
  const response = JSON.parse(frame);
  assert.equal(response.id, "request-2");
  assert.equal(response.ok, false);
  assert.deepEqual(response.error, {
    code: "RESPONSE_TOO_LARGE",
    message: "EVEDEX SDK response exceeded the IPC limit; mutation outcome may be unresolved. Reconcile before retry.",
  });
  assert.ok(Buffer.byteLength(frame, "utf8") <= MAX_RESPONSE_BYTES + 1);
});
