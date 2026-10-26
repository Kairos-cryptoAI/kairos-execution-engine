import assert from "node:assert/strict";
import test from "node:test";

import { EvedexProdSdkGateway, PinnedProdRestClient, PROD_HISTORY_OPENAPI_SOURCE, validateProdHistoryRead } from "../src/prod_sdk_gateway.js";

test("real pinned SDK PROD read methods retain exact bodies and fixed GET queries", async () => {
  const requests = [];
  const nativeBody = '{"exact":123456789012345678.123400,"updatedAt":"2020-01-01T00:00:00Z"}';
  const gateway = new EvedexProdSdkGateway({
    apiKey: "offline-key", expectedAccountId: "acct-prod-1",
    axiosAdapter: async (config) => {
      requests.push(config);
      const data = config.url.endsWith("/api/user/me")
        ? Buffer.from('{"exchangeId":"acct-prod-1"}') : Buffer.from(nativeBody);
      return { data, status: 200, statusText: "OK", headers: {}, config };
    },
  });
  await gateway.preflight();
  const cases = [
    ["available_balance", {}, "/api/market/available-balance", {}],
    ["positions", {}, "/api/position", {}],
    ["open_orders", {}, "/api/order/opened", {}],
    ["instruments", {}, "/api/market/instrument", { fields: "metrics" }],
    ["depth", { instrument: "BTCUSD", max_level: 20 }, "/api/market/BTCUSD/deep", { maxLevel: "20" }],
  ];
  for (const [source, payload, path, query] of cases) {
    const capture = await gateway.fetchRawCapture({ source, ...payload });
    assert.equal(capture.source, source);
    assert.equal(capture.path, path);
    assert.deepEqual(JSON.parse(capture.query_json), query);
    assert.equal(Buffer.from(capture.body_base64, "base64").toString(), nativeBody);
    assert.ok(capture.requested_at <= capture.received_at);
    const request = requests.at(-1);
    assert.equal(request.method.toUpperCase(), "GET");
    assert.equal(new URL(request.url).origin, "https://trading-api.evedex.com");
    assert.equal(request.maxRedirects, 0);
    assert.equal(request.responseType, "arraybuffer");
    if (source !== "instruments" && source !== "depth") {
      assert.equal(request.headers.get("x-api-key"), "offline-key");
    }
  }
  const count = requests.length;
  for (const payload of [
    { instrument: "../DEV", max_level: 20 }, { instrument: "BTCUSD", max_level: 0 },
    { instrument: "BTCUSD", max_level: true }, { instrument: "BTCUSD", max_level: 101 },
  ]) {
    await assert.rejects(gateway.fetchRawCapture({ source: "depth", ...payload }), /malformed/);
  }
  assert.equal(requests.length, count);
  await gateway.close();
});

test("PROD actual HTTP budget preserves entry/protection/compensation headroom and truthful health", async () => {
  let now = Date.parse("2026-10-27T00:00:00.000Z");
  const requests = [];
  const gateway = new EvedexProdSdkGateway({
    apiKey: "offline-key", expectedAccountId: "acct-prod-1", clock: () => now,
    axiosAdapter: async (config) => {
      requests.push(config);
      return { data: config.url.endsWith("/api/user/me")
        ? Buffer.from('{"exchangeId":"acct-prod-1"}') : { accepted: true },
        status: 200, statusText: "OK", headers: {}, config };
    },
  });
  assert.throws(() => gateway.readHealth(), /preflight/);
  await gateway.preflight();
  now += 50;
  const initial = gateway.readHealth();
  assert.equal(initial.profile, "PROD");
  assert.equal(initial.exchange_url, "https://trading-api.evedex.com");
  assert.equal(initial.auth_age_ms, 50);
  assert.equal(initial.preflight_capture.received_at, "2026-10-27T00:00:00.000Z");
  assert.equal(initial.auth_expires_in_ms, null);
  assert.equal(initial.local_mutation_rate_limit_reserve, 30);
  assert.equal(initial.local_mutation_rate_limit_capacity, 30);
  assert.equal(initial.local_mutation_rate_limit_window_ms, 60_000);
  assert.equal(initial.local_mutation_compensation_reserve, 4);
  assert.equal(initial.local_mutation_entry_min_reserve, 7);
  assert.equal(initial.venue_rate_limit_observable, false);
  assert.equal(initial.venue_rate_limit_reserve, null);
  const send = (method, path) => gateway.httpClient.authRequest({
    method, url: `https://trading-api.evedex.com${path}`, headers: {}, body: "{}",
  });
  for (let i = 0; i < 24; i++) await send("POST", "/api/v2/order/limit");
  assert.equal(gateway.readHealth().local_mutation_rate_limit_reserve, 6);
  const beforeDenied = requests.length;
  await assert.rejects(send("POST", "/api/v2/order/market"), /mandatory STOP and TARGET/);
  await assert.rejects(send("POST", "/api/v2/order/stop-limit"), /mandatory STOP and TARGET/);
  assert.equal(requests.length, beforeDenied);
  await send("POST", "/api/tpsl/BTCUSD");
  await send("POST", "/api/tpsl/BTCUSD");
  assert.equal(gateway.readHealth().local_mutation_rate_limit_reserve, 4);
  await assert.rejects(send("POST", "/api/tpsl/BTCUSD"), /held for exposure compensation/);
  await send("POST", "/api/v2/position/BTCUSD/close");
  await send("DELETE", "/api/order/entry-1");
  await send("DELETE", "/api/tpsl/BTCUSD/stop-1");
  await send("DELETE", "/api/order/entry-2");
  assert.equal(gateway.readHealth().local_mutation_rate_limit_reserve, 0);
  const exhaustedCount = requests.length;
  await assert.rejects(send("DELETE", "/api/order/entry-3"), /exhausted/);
  assert.equal(requests.length, exhaustedCount);
  await gateway.fetchAccountIdentity();
  await gateway.preflight(); // Cached preflight does not reset the spent budget.
  assert.equal(gateway.readHealth().local_mutation_rate_limit_reserve, 0);
  assert.equal(requests.length, exhaustedCount + 1);
  now += 60_000; // Only expiry of the real rolling window restores capacity.
  assert.equal(gateway.readHealth().local_mutation_rate_limit_reserve, 30);
  await gateway.close();
});

test("failed/ambiguous PROD mutation consumes one HTTP reservation with no retry or refund", async () => {
  let attempts = 0;
  const client = new PinnedProdRestClient({ adapter: async () => {
    attempts += 1;
    throw new Error("unresolved network outcome");
  } });
  client.setSession({ apiKey: "offline-key" });
  await assert.rejects(client.authRequest({
    method: "POST", url: "https://trading-api.evedex.com/api/v2/order/limit", headers: {}, body: "{}",
  }), /transport failed/);
  assert.equal(attempts, 1);
  assert.equal(client.mutationBudget.remaining(), 29);
  await assert.rejects(client.authRequest({
    method: "POST", url: "https://evil.invalid/api/v2/order/limit", headers: {}, body: "{}",
  }), /destination/);
  assert.equal(attempts, 1);
  assert.equal(client.mutationBudget.remaining(), 29);
});

test("PROD preflight cannot mint authentication age from an SDK object without original HTTP bytes", async () => {
  const gateway = new EvedexProdSdkGateway({
    apiKey: "offline-key", expectedAccountId: "acct-prod-1",
    gatewayFactory: () => ({ createApiKeyAccount: async () => ({ exchangeAccount: { exchangeId: "acct-prod-1" } }) }),
  });
  await assert.rejects(gateway.preflight(), /no response capture/);
  assert.throws(() => gateway.readHealth(), /preflight/);
});

test("documented current OpenAPI history uses only bounded exact authenticated GET and original bytes", async () => {
  assert.equal(PROD_HISTORY_OPENAPI_SOURCE, "https://exchange-api.evedex.com/api/openapi.json");
  const requests = [];
  const body = '[{"id":"native-fill","fillQuantity":0.000000000000000001}]';
  const gateway = new EvedexProdSdkGateway({
    apiKey: "offline-key", expectedAccountId: "acct-prod-1",
    axiosAdapter: async (config) => {
      requests.push(config);
      return { data: config.url.endsWith("/api/user/me") ? Buffer.from('{"exchangeId":"acct-prod-1"}') : Buffer.from(body),
        status: 200, statusText: "OK", headers: {}, config };
    },
  });
  await gateway.preflight();
  const orderId = `00001:${"a".repeat(26)}`;
  const interval = { after: "2026-10-27T00:00:00.000Z", before: "2026-10-27T01:00:00.000Z", limit: 10, offset: 20 };
  const cases = [
    [{ source: "order_fills", order_id: orderId }, `/api/order/${orderId}/fill`, { version: "2" }],
    [{ source: "funding_transfers", ...interval, transfer_type: "fundingRate" }, "/api/user/funding-transfer",
      { ...interval, limit: "10", offset: "20", type: "fundingRate" }],
    [{ source: "fill_history", ...interval, instrument: "BTCUSD" }, "/api/fill",
      { ...interval, limit: "10", offset: "20", instrument: "BTCUSD" }],
  ];
  for (const [payload, path, query] of cases) {
    const capture = await gateway.fetchRawCapture(payload);
    assert.equal(capture.path, path);
    assert.deepEqual(JSON.parse(capture.query_json), query);
    assert.equal(Buffer.from(capture.body_base64, "base64").toString(), body);
    assert.equal(requests.at(-1).method.toUpperCase(), "GET");
    assert.equal(requests.at(-1).headers.get("x-api-key"), "offline-key");
    assert.equal(new URL(requests.at(-1).url).origin, "https://trading-api.evedex.com");
  }
  const count = requests.length;
  for (const change of [
    { after: "2026-10-27T00:00:00+00:00" }, { before: interval.after },
    { before: "2026-10-29T00:00:00.000Z" }, { after: "2026-02-30T00:00:00.000Z" },
    { limit: true }, { limit: 101 }, { offset: -1 }, { transfer_type: "madeUp" },
  ]) {
    await assert.rejects(gateway.fetchRawCapture({ source: "funding_transfers", ...interval, ...change }), /contract/);
  }
  assert.throws(() => validateProdHistoryRead({ source: "order_fills", order_id: "../other" }), /V2 order/);
  assert.throws(() => validateProdHistoryRead({ source: "funding_transfers", ...interval, next: "unsupported" }), /exact/);
  assert.equal(requests.length, count);
  await gateway.close();
});
