const MUTATIONS = new Set([
  "place_market",
  "place_limit",
  "close_position",
  "cancel_order",
  "create_tpsl",
  "cancel_tpsl",
  "set_leverage",
]);

const READS = new Set([
  "health",
  "fetch_account",
  "fetch_open_orders",
  "fetch_positions",
  "fetch_tpsl",
  "fetch_instruments",
  "fetch_depth",
  "drain_events",
]);

export function isMutation(operation) {
  return MUTATIONS.has(operation);
}

export function validateRequest(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("request must be a JSON object");
  }
  if (typeof value.id !== "string" || value.id.length === 0 || value.id.length > 200) {
    throw new TypeError("request.id must be a non-empty string of at most 200 characters");
  }
  if (typeof value.operation !== "string" || (!READS.has(value.operation) && !MUTATIONS.has(value.operation))) {
    throw new TypeError("request.operation is not supported");
  }
  const payload = value.payload ?? {};
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    throw new TypeError("request.payload must be a JSON object");
  }
  if (isMutation(value.operation)) {
    requireText(payload, "effect_id");
    if (["place_market", "place_limit", "close_position"].includes(value.operation)) {
      requireText(payload, "client_order_id");
    }
  }
  return { id: value.id, operation: value.operation, payload };
}

export function requireText(payload, field) {
  const value = payload[field];
  if (typeof value !== "string" || value.length === 0 || value.length > 500) {
    throw new TypeError(`${field} must be a non-empty string of at most 500 characters`);
  }
  return value;
}

export function requirePositive(payload, field) {
  const value = payload[field];
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    throw new TypeError(`${field} must be finite and positive`);
  }
  return value;
}

export function requireNonNegative(payload, field) {
  const value = payload[field];
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new TypeError(`${field} must be finite and non-negative`);
  }
  return value;
}

export function requireSide(payload) {
  if (payload.side !== "BUY" && payload.side !== "SELL") {
    throw new TypeError("side must be BUY or SELL");
  }
  return payload.side;
}

export function requireDevInstrument(payload, field = "instrument") {
  const value = requireText(payload, field).toUpperCase();
  if (!/^(BTC|ETH|SOL|BNB|XRP)USD:DEV$/.test(value)) {
    throw new TypeError(`${field} is not an allowlisted EVEDEX DEV instrument`);
  }
  return value;
}

export function publicError(error, secrets = []) {
  let message = error instanceof Error ? error.message : "unknown sidecar error";
  for (const secret of secrets) {
    if (typeof secret === "string" && secret.length > 0) {
      message = message.split(secret).join("[REDACTED]");
    }
  }
  message = message
    .replace(/Bearer\s+\S+/gi, "Bearer [REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, "[REDACTED]")
    .replace(/\b0x[0-9a-f]{64}\b/gi, "[REDACTED]");
  return {
    code: error instanceof Error ? error.name : "Error",
    message: message.slice(0, 1000),
  };
}
