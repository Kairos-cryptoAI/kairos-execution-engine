// Keep the complete serialized result envelope within the HTTP response bound
// plus a fixed allowance for the IPC wrapper. The newline is outside this
// budget and is included in Python's StreamReader limit separately.
export const MAX_RESPONSE_BYTES = 4 * 1024 * 1024 + 4 * 1024;

const OVERSIZED_RESPONSE = Object.freeze({
  code: "RESPONSE_TOO_LARGE",
  message: "EVEDEX SDK response exceeded the IPC limit; mutation outcome may be unresolved. Reconcile before retry.",
});

export function serializeProdResponse(id, { ok, result, error }) {
  const response = ok ? { id, ok: true, result } : { id, ok: false, error };
  const encoded = JSON.stringify(response);
  if (Buffer.byteLength(encoded, "utf8") <= MAX_RESPONSE_BYTES) return `${encoded}\n`;

  const fallback = JSON.stringify({ id, ok: false, error: OVERSIZED_RESPONSE });
  // Request IDs are already limited to 200 characters by prod_main.js, so the
  // fixed public refusal always fits comfortably within this frame budget.
  return `${fallback}\n`;
}
