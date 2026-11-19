import assert from "node:assert/strict";
import test from "node:test";

import { EvedexProdSdkGateway, PinnedProdRestClient } from "../src/prod_sdk_gateway.js";

const body = {
  id: "market-fixture", instrument: "BTCUSD", side: "BUY", timeInForce: "IOC",
  leverage: 1, cashQuantity: "10", chainId: 42161, signature: `0x${"12".repeat(65)}`,
};
const request = (value = body) => ({
  method: "POST", url: "https://trading-api.evedex.com/api/v2/order/market", headers: {},
  body: JSON.stringify(value),
});

function clientFixture() {
  let now = 100_000;
  const calls = [];
  const client = new PinnedProdRestClient({
    clock: () => now,
    adapter: async (config) => { calls.push(config); return { data: {}, status: 200, config }; },
  });
  client.setSession({ apiKey: "test-only" });
  return { client, calls, setNow: (value) => { now = value; } };
}

test("market HTTP requires same frozen body and a current bounded deadline", async () => {
  const { client, calls } = clientFixture();
  await assert.rejects(client.authRequest(request()), /deadline/);
  assert.throws(() => client.beginMarketDeadline(body, 100_000), /deadline/);
  assert.throws(() => client.beginMarketDeadline(body, 130_001), /deadline/);
  client.beginMarketDeadline(body, 102_000);
  await assert.rejects(client.authRequest(request({ ...body, cashQuantity: "11" })), /body changed/);
  assert.equal(calls.length, 0);
  await assert.rejects(client.authRequest(request()), /not qualified to reduce/);
  assert.equal(calls.length, 0);
  client.endMarketDeadline();
});

test("expiry while awaiting a queued operation or rollback stops before market HTTP", async () => {
  for (const nextTime of [102_000, 99_999]) {
    const { client, calls, setNow } = clientFixture();
    client.beginMarketDeadline(body, 102_000);
    let unblock;
    const gate = new Promise((resolve) => { unblock = resolve; });
    const queued = gate.then(() => client.authRequest(request()));
    setNow(nextTime);
    unblock();
    await assert.rejects(queued, /deadline|clock moved backwards/);
    assert.equal(calls.length, 0);
    client.endMarketDeadline();
    // Risk exits remain independent from an expired market-entry scope.
    await client.authRequest({
      method: "POST", url: "https://trading-api.evedex.com/api/v2/position/BTCUSD/close",
      headers: {}, body: "{}",
    });
    await assert.rejects(client.authRequest({
      method: "POST", url: "https://trading-api.evedex.com/api/tpsl/BTCUSD",
      headers: {}, body: "{}",
    }), /not qualified to reduce/);
    assert.equal(calls.length, 1);
  }
});

test("rollback between request preparation and the last market deadline check is refused", async () => {
  const clockValues = [100_000, 101_500, 101_000];
  let calls = 0;
  const client = new PinnedProdRestClient({
    clock: () => clockValues.shift(),
    adapter: async () => { calls += 1; },
  });
  client.setSession({ apiKey: "test-only" });
  client.beginMarketDeadline(body, 102_000);
  await assert.rejects(client.authRequest(request()), /deadline/);
  assert.equal(calls, 0);
  client.endMarketDeadline();
});

test("gateway refuses an IPC-queued market request if deadline elapsed before handling", async () => {
  let now = 100_000;
  let sdkCalls = 0;
  const gateway = new EvedexProdSdkGateway({
    apiKey: "test-only", expectedAccountId: "acct-prod-1", clock: () => now,
    axiosAdapter: async (config) => ({
      data: Buffer.from('{"exchangeId":"acct-prod-1"}'), status: 200, statusText: "OK", headers: {}, config,
    }),
    gatewayFactory: ({ httpClient }) => ({
      createApiKeyAccount: async (apiKey) => {
        httpClient.setSession(apiKey);
        await httpClient.authRequest({ method: "GET", url: "https://trading-api.evedex.com/api/user/me", headers: {} });
        return { exchangeAccount: { exchangeId: "acct-prod-1" }, exchangeGateway: {
          createMarketOrderV2: async () => { sdkCalls += 1; return {}; },
        } };
      },
      closeWsConnection: async () => {},
    }),
  });
  await gateway.preflight();
  let unblock;
  const gate = new Promise((resolve) => { unblock = resolve; });
  const queued = gate.then(() => gateway.sendSignedPost({
    method: "POST", path: "/api/v2/order/market", body, deadline_ms: 102_000,
  }));
  now = 102_000;
  unblock();
  await assert.rejects(queued, /deadline/);
  assert.equal(sdkCalls, 0);
  await gateway.close();
});
