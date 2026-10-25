import { createInterface } from "node:readline";
import { readFileSync } from "node:fs";

import { EvedexProdSdkGateway, safeProdError } from "./prod_sdk_gateway.js";
import { serializeProdResponse } from "./prod_protocol.js";

const MAX_LINE_BYTES = 1024 * 1024;
const MAX_RAW_CAPTURE_BYTES = 2 * 1024 * 1024;
let gateway;
let apiKey;
let queue = Promise.resolve();

function secret(name) {
  const path = process.env[`${name}_FILE`];
  if (typeof path !== "string" || path.length === 0 || path.includes("\0")) throw new Error(`${name}_FILE is required`);
  const value = readFileSync(path, "utf8").trim();
  if (!value) throw new Error(`${name}_FILE is empty`);
  return value;
}

function validate(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError("request must be an object");
  if (typeof value.id !== "string" || value.id.length === 0 || value.id.length > 200) throw new TypeError("request id is malformed");
  if (!value.payload || typeof value.payload !== "object" || Array.isArray(value.payload)) throw new TypeError("request payload must be an object");
  const payload = value.payload;
  if (value.operation === "send_signed_post") {
    exactKeys(payload, ["method", "path", "body"]);
    if (payload.method !== "POST" || typeof payload.path !== "string" || !payload.body || typeof payload.body !== "object" || Array.isArray(payload.body)) {
      throw new TypeError("signed post request is malformed");
    }
    return { id: value.id, operation: value.operation, payload };
  }
  if (value.operation === "preflight") {
    exactKeys(payload, []);
    return { id: value.id, operation: value.operation, payload };
  }
  if (value.operation === "cancel_order") {
    exactKeys(payload, ["effect_id", "instrument", "order_id"]);
    requireTextFields(payload, ["effect_id", "instrument", "order_id"]);
    return { id: value.id, operation: value.operation, payload };
  }
  if (value.operation === "cancel_tpsl") {
    exactKeys(payload, ["effect_id", "instrument", "protection_id"]);
    requireTextFields(payload, ["effect_id", "instrument", "protection_id"]);
    return { id: value.id, operation: value.operation, payload };
  }
  if (value.operation === "fetch_account_identity" || value.operation === "fetch_funding") {
    exactKeys(payload, []);
    return { id: value.id, operation: value.operation, payload };
  }
  if (value.operation === "fetch_order_history_page") {
    const allowed = ["version", "limit", "offset", ...(Object.hasOwn(payload, "next") ? ["next"] : [])];
    exactKeys(payload, allowed);
    if (payload.version !== 2 || !Number.isInteger(payload.limit) || !Number.isInteger(payload.offset) ||
        ("next" in payload && (typeof payload.next !== "string" || payload.next.length === 0 || payload.next.length > 500))) {
      throw new TypeError("order history page query is malformed");
    }
    return { id: value.id, operation: value.operation, payload };
  }
  if (value.operation === "fetch_tpsl_page") {
    exactKeys(payload, ["limit", "offset"]);
    if (!Number.isInteger(payload.limit) || !Number.isInteger(payload.offset)) throw new TypeError("TP/SL page query is malformed");
    return { id: value.id, operation: value.operation, payload };
  }
  if (value.operation === "fetch_raw_capture") {
    const source = payload.source;
    if (source === "account_identity" || source === "funding") {
      exactKeys(payload, ["source"]);
      return { id: value.id, operation: value.operation, payload };
    }
    if (source === "order_page") {
      const allowed = ["source", "version", "limit", "offset", ...(Object.hasOwn(payload, "next_cursor") ? ["next_cursor"] : [])];
      exactKeys(payload, allowed);
      if (payload.version !== 2 || !Number.isInteger(payload.limit) || payload.limit < 1 || payload.limit > 100 ||
          !Number.isInteger(payload.offset) || payload.offset < 0 || payload.offset > 10_000 ||
          ("next_cursor" in payload && (typeof payload.next_cursor !== "string" || payload.next_cursor.length === 0 || payload.next_cursor.length > 500))) {
        throw new TypeError("raw order page query is malformed");
      }
      return { id: value.id, operation: value.operation, payload };
    }
    if (source === "tpsl_page") {
      exactKeys(payload, ["source", "limit", "offset"]);
      if (!Number.isInteger(payload.limit) || payload.limit < 1 || payload.limit > 100 ||
          !Number.isInteger(payload.offset) || payload.offset < 0 || payload.offset > 10_000) {
        throw new TypeError("raw TP/SL page query is malformed");
      }
      return { id: value.id, operation: value.operation, payload };
    }
    throw new TypeError("raw capture source is outside the fixed account/history allowlist");
  }
  throw new TypeError("production SDK operation is not supported");
}

function exactKeys(value, allowed) {
  const keys = Object.keys(value).sort();
  const expected = [...allowed].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new TypeError("production SDK payload fields are not exact");
  }
}

function requireTextFields(value, fields) {
  for (const key of fields) {
    if (typeof value[key] !== "string" || value[key].length === 0 || value[key].length > 500) {
      throw new TypeError(`production SDK ${key} is malformed`);
    }
  }
}

async function handle(line) {
  let id = "invalid";
  try {
    if (Buffer.byteLength(line, "utf8") > MAX_LINE_BYTES) throw new TypeError("request exceeds the protocol bound");
    const request = validate(JSON.parse(line));
    id = request.id;
    apiKey ??= secret("EVEDEX_PROD_API_KEY");
    gateway ??= new EvedexProdSdkGateway({
      apiKey,
      expectedAccountId: process.env.EVEDEX_PROD_EXPECTED_ACCOUNT_ID,
    });
    let result;
    if (request.operation === "preflight") {
      result = await gateway.preflight();
    } else if (request.operation === "send_signed_post") {
      result = await gateway.sendSignedPost(request.payload);
    } else if (request.operation === "cancel_order") {
      result = await gateway.cancelOrder({ instrument: request.payload.instrument, orderId: request.payload.order_id });
    } else if (request.operation === "cancel_tpsl") {
      result = await gateway.cancelTpSl({ instrument: request.payload.instrument, protectionId: request.payload.protection_id });
    } else if (request.operation === "fetch_account_identity") {
      result = await gateway.fetchAccountIdentity();
    } else if (request.operation === "fetch_order_history_page") {
      result = await gateway.fetchOrderHistoryPage(request.payload);
    } else if (request.operation === "fetch_tpsl_page") {
      result = await gateway.fetchTpSlPage(request.payload);
    } else if (request.operation === "fetch_funding") {
      result = await gateway.fetchFunding();
    } else if (request.operation === "fetch_raw_capture") {
      const { source, next_cursor: next, ...query } = request.payload;
      result = await gateway.fetchRawCapture({ source, ...query, ...(next === undefined ? {} : { next }) });
      if (result.body_bytes > MAX_RAW_CAPTURE_BYTES) throw new Error("raw capture exceeded the fixed IPC payload bound");
    } else {
      throw new TypeError("production SDK operation is not supported");
    }
    process.stdout.write(serializeProdResponse(id, { ok: true, result }));
  } catch (error) {
    process.stdout.write(serializeProdResponse(id, { ok: false, error: safeProdError(error) }));
  }
}

const input = createInterface({ input: process.stdin, crlfDelay: Infinity, terminal: false });
input.on("line", (line) => { queue = queue.then(() => handle(line)); });
input.on("close", async () => { await queue; await gateway?.close(); });
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, async () => { await queue; await gateway?.close(); process.exit(0); });
}
