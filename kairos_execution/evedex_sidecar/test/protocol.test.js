import assert from "node:assert/strict";
import test from "node:test";

import {
  isMutation,
  publicError,
  requireDevInstrument,
  validateRequest,
} from "../src/protocol.js";
import {
  assertPinnedDevProfile,
  DEV_PROFILE,
  fetchAllPages,
  installedSdkDevChainId,
  LocalMutationBudget,
  PINNED_SDK_VERSION,
  tokenExpiresAtMs,
} from "../src/sdk_gateway.js";

test("the installed SDK endpoints match and Kairos pins the official master chain", () => {
  assert.doesNotThrow(() => assertPinnedDevProfile());
  assert.equal(PINNED_SDK_VERSION, "1.2.11");
  // npm 1.2.11 still embeds the obsolete DEV chain. This regression sentinel
  // makes it impossible to silently fall back to that value while the exact,
  // non-configurable official-master override below remains 16182.
  assert.equal(installedSdkDevChainId(), "421614");
  assert.deepEqual(DEV_PROFILE, {
    exchangeURI: "https://trading-api.evedex.tech",
    authURI: "https://auth-api.evedex.tech",
    centrifugeURI: "wss://ws.evedex.tech/connection/websocket",
    centrifugePrefix: "futures-perp-dev",
    chainId: "16182",
  });
});

test("mutations require a durable effect id and deterministic order id", () => {
  assert.equal(isMutation("place_market"), true);
  assert.throws(
    () => validateRequest({ id: "1", operation: "place_market", payload: {} }),
    /effect_id/,
  );
  assert.doesNotThrow(() =>
    validateRequest({
      id: "1",
      operation: "place_market",
      payload: { effect_id: "effect-1", client_order_id: "order-1" },
    }),
  );
});

test("only the five DEV instruments are accepted", () => {
  for (const instrument of ["BTCUSD:DEV", "ETHUSD:DEV", "SOLUSD:DEV", "BNBUSD:DEV", "XRPUSD:DEV"]) {
    assert.equal(requireDevInstrument({ instrument }), instrument);
  }
  assert.throws(() => requireDevInstrument({ instrument: "BTCUSD" }), /DEV instrument/);
  assert.throws(() => requireDevInstrument({ instrument: "BTCUSD:DEMO" }), /DEV instrument/);
  assert.throws(() => requireDevInstrument({ instrument: "DOGEUSD:DEV" }), /DEV instrument/);
});

test("update TP/SL is intentionally outside the v1 protocol", () => {
  assert.throws(
    () => validateRequest({ id: "1", operation: "update_tpsl", payload: {} }),
    /not supported/,
  );
});

test("local mutation reserve protects compensation capacity and replenishes", () => {
  let now = 1_000;
  const budget = new LocalMutationBudget({
    capacity: 7,
    windowMs: 100,
    entryCompensationReserve: 4,
    clock: () => now,
  });
  assert.equal(budget.remaining(), 7);
  const underfunded = new LocalMutationBudget({
    capacity: 7,
    windowMs: 100,
    entryCompensationReserve: 4,
    clock: () => now,
  });
  underfunded.reserve("cancel_order");
  underfunded.reserve("cancel_tpsl");
  assert.equal(underfunded.remaining(), 5);
  assert.throws(() => underfunded.reserve("place_limit"), /mandatory STOP and TARGET/);
  assert.equal(budget.reserve("place_limit"), 6);
  assert.equal(budget.reserve("create_tpsl"), 5);
  assert.equal(budget.reserve("create_tpsl"), 4);
  assert.throws(() => budget.reserve("place_limit"), /mandatory STOP and TARGET/);
  assert.throws(() => budget.reserve("create_tpsl"), /held for exposure compensation/);
  assert.equal(budget.reserve("cancel_tpsl"), 3);
  assert.equal(budget.reserve("cancel_tpsl"), 2);
  assert.equal(budget.reserve("close_position"), 1);
  assert.equal(budget.reserve("cancel_order"), 0);
  assert.throws(() => budget.reserve("close_position"), /reserve is exhausted/);
  now += 101;
  assert.equal(budget.remaining(), 7);
});

test("authoritative pagination rejects partial and duplicate snapshots", async () => {
  const pages = [
    { list: [{ id: "a" }, { id: "b" }], count: 3 },
    { list: [{ id: "c" }], count: 3 },
  ];
  const complete = await fetchAllPages(async () => pages.shift());
  assert.deepEqual(complete.map(({ id }) => id), ["a", "b", "c"]);

  await assert.rejects(
    fetchAllPages(async () => ({ list: [], count: 1 })),
    /incomplete/,
  );
  let page = 0;
  await assert.rejects(
    fetchAllPages(async () => {
      page += 1;
      return page === 1
        ? { list: [{ id: "same" }], count: 2 }
        : { list: [{ id: "same" }], count: 2 };
    }),
    /duplicate IDs/,
  );
});

test("JWT expiry telemetry exposes time only, never token content", () => {
  const payload = Buffer.from(JSON.stringify({ exp: 1234 })).toString("base64url");
  assert.equal(tokenExpiresAtMs({ session: { accessToken: `x.${payload}.y` } }), 1_234_000);
  assert.equal(tokenExpiresAtMs({ session: { apiKey: "secret" } }), null);
});

test("sidecar errors redact exact credentials, JWTs, bearer values, and private keys", () => {
  const apiKey = "api-key-value";
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature";
  const privateKey = `0x${"a".repeat(64)}`;
  const result = publicError(
    new Error(`${apiKey} Bearer ${jwt} ${privateKey}`),
    [apiKey, privateKey],
  );
  assert.equal(result.message.includes(apiKey), false);
  assert.equal(result.message.includes(jwt), false);
  assert.equal(result.message.includes(privateKey), false);
});
