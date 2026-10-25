import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

import { EvedexProdSdkGateway, PinnedProdRestClient, PROD_SDK_PROFILE, safeProdError } from "../src/prod_sdk_gateway.js";

const require = createRequire(import.meta.url);
const evedex = require("@evedex/exchange-bot-sdk");
const axios = require("axios");

const SIGNATURE = `0x${"12".repeat(65)}`;
const cases = [
  ["/api/v2/order/limit", { id: "entry-1", instrument: "BTCUSD", side: "BUY", leverage: 1, quantity: "0.25", limitPrice: "60000", chainId: 42161, timeInForce: "IOC", signature: SIGNATURE }, "createLimitOrderV2"],
  ["/api/v2/order/market", { id: "market-1", instrument: "BTCUSD", side: "BUY", timeInForce: "IOC", leverage: 1, cashQuantity: "100", chainId: 42161, signature: SIGNATURE }, "createMarketOrderV2"],
  ["/api/v2/order/stop-limit", { id: "stop-1", instrument: "BTCUSD", side: "BUY", leverage: 1, quantity: "0.25", limitPrice: "60000", stopPrice: "59000", chainId: 42161, signature: SIGNATURE }, "createStopLimitOrderV2"],
  ["/api/v2/position/BTCUSD/close", { id: "close-1", instrument: "BTCUSD", leverage: 1, quantity: "0.25", chainId: 42161, signature: SIGNATURE }, "closePositionV2"],
  ["/api/tpsl/BTCUSD", { instrument: "BTCUSD", type: "stop-loss", side: "BUY", quantity: "0.25", price: "59000", order: "entry-1", signature: SIGNATURE }, "createTpSl"],
];

function fixture({ exchangeId = "acct-prod-1", orderRecord = null, tpslPage = null } = {}) {
  const calls = [];
  const optionsSeen = [];
  let closed = 0;
  const exchangeGateway = {};
  for (const [, , method] of cases) {
    exchangeGateway[method] = async (body) => {
      calls.push([method, body]);
      return { accepted: true };
    };
  }
  exchangeGateway.cancelOrder = async (query) => { calls.push(["cancelOrder", query]); };
  exchangeGateway.cancelTpSl = async (query) => { calls.push(["cancelTpSl", query]); };
  exchangeGateway.getOrder = async (id) => {
    calls.push(["getOrder", id]);
    return orderRecord ?? { id, instrument: "BTCUSD", status: "CANCELLED" };
  };
  exchangeGateway.me = async () => { calls.push(["me"]); return { exchangeId }; };
  exchangeGateway.getTpSl = async (query) => {
    calls.push(["getTpSl", query]);
    return tpslPage ?? { count: 1, list: [{ id: "stop-1", instrument: "BTCUSD", status: "cancelled" }] };
  };
  exchangeGateway.getFunding = async () => ({ list: [{ balance: "1.2300" }] });
  exchangeGateway.getOrders = async (query) => { calls.push(["getOrders", query]); return { count: 0, list: [], query }; };
  const account = {
    exchangeGateway,
    exchangeAccount: { exchangeId },
  };
  const gateway = new EvedexProdSdkGateway({
    apiKey: "api-key-test",
    expectedAccountId: "acct-prod-1",
    gatewayFactory: (options) => {
      optionsSeen.push(options);
      return {
        createApiKeyAccount: async (apiKey) => {
          assert.deepEqual(apiKey, { apiKey: "api-key-test" });
          return account;
        },
        closeWsConnection: async () => { closed += 1; },
      };
    },
  });
  return { gateway, calls, optionsSeen, closed: () => closed };
}

test("uses the pinned PROD SDK profile and only the API-key account constructor", async () => {
  assert.deepEqual(PROD_SDK_PROFILE, {
    exchangeURI: "https://trading-api.evedex.com",
    authURI: "https://auth-api.evedex.com",
    centrifugeURI: "wss://ws.evedex.com/connection/websocket",
    centrifugePrefix: "futures-perp",
    chainId: "42161",
    sdkVersion: "1.2.11",
    exchangeApiVersion: "1.0.70",
  });
  const { gateway, optionsSeen } = fixture();
  await gateway.preflight();
  assert.deepEqual(await gateway.preflight(), { exchangeId: "acct-prod-1" });
  await gateway.sendSignedPost({ method: "POST", path: cases[0][0], body: cases[0][1] });
  assert.deepEqual({
    authURI: optionsSeen[0].authURI,
    exchangeURI: optionsSeen[0].exchangeURI,
    centrifuge: optionsSeen[0].centrifuge,
  }, {
    authURI: "https://auth-api.evedex.com",
    exchangeURI: "https://trading-api.evedex.com",
    centrifuge: { uri: "wss://ws.evedex.com/connection/websocket", prefix: "futures-perp" },
  });
  assert.equal(optionsSeen[0].httpClient.constructor.name, "PinnedProdRestClient");
  assert.equal("wallets" in optionsSeen[0], false);
  assert.equal("gatewayOverrides" in optionsSeen[0], false);
  await gateway.close();
});

test("real pinned SDK Gateway uses isolated bounded HTTPS transport and x-api-key only", async () => {
  const axiosDefaultsBefore = { proxy: axios.defaults.proxy, timeout: axios.defaults.timeout, maxRedirects: axios.defaults.maxRedirects };
  const requests = [];
  const adapter = async (config) => {
    requests.push(config);
    const data = config.url.endsWith("/api/user/me")
      ? { exchangeId: "acct-prod-1" }
      : { id: "entry-1", status: "NEW" };
    return { data, status: 200, statusText: "OK", headers: {}, config };
  };
  const gateway = new EvedexProdSdkGateway({
    apiKey: "api-key-test",
    expectedAccountId: "acct-prod-1",
    axiosAdapter: adapter,
  });
  assert.equal(gateway.gatewayFactory instanceof Function, true);
  await gateway.preflight();
  await gateway.sendSignedPost({ method: "POST", path: cases[0][0], body: cases[0][1] });

  assert.equal(requests.length, 2);
  assert.equal(requests[0].url, "https://trading-api.evedex.com/api/user/me");
  assert.equal(requests[1].url, "https://trading-api.evedex.com/api/v2/order/limit");
  for (const request of requests) {
    assert.equal(request.maxRedirects, 0);
    assert.equal(request.proxy, false);
    assert.equal(request.timeout, 20_000);
    assert.equal(request.maxContentLength, 4 * 1024 * 1024);
    assert.equal(request.maxBodyLength, 4 * 1024 * 1024);
    assert.ok(request.httpsAgent);
    assert.equal(request.headers.get("x-api-key"), "api-key-test");
    assert.equal(request.headers.get("Authorization"), undefined);
  }
  assert.equal(requests[1].data, JSON.stringify(cases[0][1]));
  assert.deepEqual(
    { proxy: axios.defaults.proxy, timeout: axios.defaults.timeout, maxRedirects: axios.defaults.maxRedirects },
    axiosDefaultsBefore,
  );
  await gateway.close();
});

test("pinned SDK RestClient rejects untrusted origins, routes, and JWT sessions before adapter use", async () => {
  const attempts = [];
  const client = new PinnedProdRestClient({ adapter: async (config) => { attempts.push(config); } });
  client.setSession({ apiKey: "api-key-test" });
  await assert.rejects(client.authRequest({ method: "GET", url: "https://evil.invalid/api/user/me", headers: {} }), /destination/);
  await assert.rejects(client.authRequest({ method: "POST", url: "https://trading-api.evedex.com/api/transfer/pf/withdraw", headers: {} }), /route/);
  client.setSession({ accessToken: "token", refreshToken: "refresh" });
  await assert.rejects(client.authRequest({ method: "GET", url: "https://trading-api.evedex.com/api/user/me", headers: {} }), /API-key authentication only/);
  assert.equal(attempts.length, 0);
  assert.equal(evedex.GatewayParamsMap.get(evedex.Environment.PROD).exchangeURI, PROD_SDK_PROFILE.exchangeURI);
});

test("API-key 401 failure is not retried by the SDK auth client", async () => {
  let attempts = 0;
  const gateway = new EvedexProdSdkGateway({
    apiKey: "api-key-test",
    expectedAccountId: "acct-prod-1",
    axiosAdapter: async (config) => {
      attempts += 1;
      const response = { data: { error: "secret-bearing body" }, status: 401, statusText: "Unauthorized", headers: {}, config };
      throw new axios.AxiosError("private details", "ERR_BAD_REQUEST", config, undefined, response);
    },
  });
  await assert.rejects(gateway.preflight(), /exact configured PROD account|HTTP transport failed/);
  assert.equal(attempts, 1);
  await assert.rejects(gateway.preflight(), /already failed/);
  assert.equal(attempts, 1);
});

test("passes exact pre-signed bodies through the corresponding SDK API method", async () => {
  const { gateway, calls } = fixture();
  await gateway.preflight();
  for (const [path, body, method] of cases) {
    const result = await gateway.sendSignedPost({ method: "POST", path, body });
    assert.deepEqual(result, { accepted: true });
    assert.equal(calls.at(-1)[0], method);
    assert.equal(calls.at(-1)[1], body);
    assert.equal(calls.at(-1)[1].signature, SIGNATURE);
  }
  assert.equal(calls.length, cases.length);
  await gateway.close();
});

test("uses only the typed unsigned cancellation endpoints", async () => {
  const { gateway, calls } = fixture();
  await gateway.preflight();
  assert.deepEqual(await gateway.cancelOrder({ instrument: "BTCUSD", orderId: "entry-1" }), { id: "entry-1", status: "CANCELED" });
  assert.deepEqual(await gateway.cancelTpSl({ instrument: "BTCUSD", protectionId: "stop-1" }), { id: "stop-1", status: "CANCELED" });
  assert.deepEqual(calls, [
    ["cancelOrder", { orderId: "entry-1" }],
    ["getOrder", "entry-1"],
    ["cancelTpSl", { instrument: "BTCUSD", id: "stop-1" }],
    ["getTpSl", { instrument: "BTCUSD", limit: 100, offset: 0 }],
  ]);
  await gateway.close();
});

test("does not claim cancellation after an unconfirmed delete, missing record, or fill race", async () => {
  const notCancelled = fixture({ orderRecord: { id: "entry-1", instrument: "BTCUSD", status: "FILLED" } });
  await notCancelled.gateway.preflight();
  await assert.rejects(notCancelled.gateway.cancelOrder({ instrument: "BTCUSD", orderId: "entry-1" }), /not positively confirmed/);
  const missingTpsl = fixture({ tpslPage: { count: 0, list: [] } });
  await missingTpsl.gateway.preflight();
  await assert.rejects(missingTpsl.gateway.cancelTpSl({ instrument: "BTCUSD", protectionId: "stop-1" }), /not positively confirmed/);
  const triggeredTpsl = fixture({ tpslPage: { count: 1, list: [{ id: "stop-1", instrument: "BTCUSD", status: "triggered" }] } });
  await triggeredTpsl.gateway.preflight();
  await assert.rejects(triggeredTpsl.gateway.cancelTpSl({ instrument: "BTCUSD", protectionId: "stop-1" }), /not positively confirmed/);
});

test("read methods preserve raw SDK-parsed JSON and strict page query shapes", async () => {
  const { gateway, calls } = fixture();
  await gateway.preflight();
  assert.deepEqual(await gateway.fetchAccountIdentity(), { exchangeId: "acct-prod-1" });
  assert.deepEqual(await gateway.fetchOrderHistoryPage({ version: 2, limit: 50, offset: 100, next: "cursor-2" }), {
    count: 0, list: [], query: { version: 2, limit: 50, offset: 100, next: "cursor-2" },
  });
  assert.deepEqual(await gateway.fetchFunding(), { list: [{ balance: "1.2300" }] });
  assert.deepEqual(calls[0], ["me"]);
  assert.deepEqual(calls[1], ["getOrders", { version: 2, limit: 50, offset: 100, next: "cursor-2" }]);
  await assert.rejects(gateway.fetchOrderHistoryPage({ version: 1, limit: 100, offset: 0 }), /query is malformed/);
  await gateway.close();
});

test("raw capture returns bounded original application body bytes with exact GET metadata", async () => {
  const body = Buffer.from('{"list":[{"quantity":12345678901234567890.123456789012345}],"count":1}', "utf8");
  const requests = [];
  const gateway = new EvedexProdSdkGateway({
    apiKey: "api-key-test",
    expectedAccountId: "acct-prod-1",
    axiosAdapter: async (config) => {
      requests.push(config);
      const data = config.url.endsWith("/api/user/me")
        ? { exchangeId: "acct-prod-1" }
        : body;
      return { data, status: 200, statusText: "OK", headers: {}, config };
    },
  });
  await gateway.preflight();
  const capture = await gateway.fetchRawCapture({ source: "order_page", version: 2, limit: 50, offset: 100 });
  assert.equal(requests.length, 2);
  assert.equal(requests[1].method.toUpperCase(), "GET");
  assert.equal(requests[1].url, "https://trading-api.evedex.com/api/order?version=2&limit=50&offset=100&withTpSL=");
  assert.equal(requests[1].maxRedirects, 0);
  assert.equal(requests[1].proxy, false);
  assert.equal(capture.source, "order_page");
  assert.equal(capture.path, "/api/order");
  assert.deepEqual(JSON.parse(capture.query_json), { version: "2", limit: "50", offset: "100", withTpSL: "" });
  assert.equal(capture.status, 200);
  assert.equal(Buffer.from(capture.body_base64, "base64").toString("utf8"), body.toString("utf8"));
  assert.equal(capture.body_bytes, body.length);
  assert.match(capture.body_sha256, /^[a-f0-9]{64}$/);
  assert.ok(Date.parse(capture.received_at) >= Date.parse(capture.requested_at));
  await gateway.close();
});

test("raw capture refuses non-allowlisted source, mismatched route/query and oversized body", async () => {
  let attempts = 0;
  const gateway = new EvedexProdSdkGateway({
    apiKey: "api-key-test",
    expectedAccountId: "acct-prod-1",
    axiosAdapter: async (config) => {
      attempts += 1;
      const data = config.url.endsWith("/api/user/me")
        ? { exchangeId: "acct-prod-1" }
        : Buffer.alloc(2 * 1024 * 1024 + 1, 0x20);
      return { data, status: 200, statusText: "OK", headers: {}, config };
    },
  });
  await gateway.preflight();
  const before = attempts;
  await assert.rejects(gateway.fetchRawCapture({ source: "arbitrary", path: "/api/order" }), /outside the fixed/);
  assert.equal(attempts, before);

  const client = new PinnedProdRestClient({ adapter: async (config) => { attempts += 1; return { data: {}, status: 200, config }; } });
  client.setSession({ apiKey: "api-key-test" });
  client.beginRawCapture({ source: "funding", path: "/api/user/me", query: {} });
  const mismatchedRequest = { method: "GET", url: "https://trading-api.evedex.com/api/user/funding", headers: {} };
  await assert.rejects(client.authRequest(mismatchedRequest), /fixed GET route/);
  assert.equal(mismatchedRequest.headers["x-api-key"], undefined);
  assert.equal(attempts, before);

  await assert.rejects(
    gateway.fetchRawCapture({ source: "order_page", version: 2, limit: 1, offset: 0 }),
    /no response capture/,
  );
  await gateway.close();
});

test("raw capture is limited to the other fixed account endpoints and retains HTTP status without headers", async () => {
  const fundingBody = Buffer.from('[{"coin":"USDT","quantity":1.2300}]', "utf8");
  const requests = [];
  const gateway = new EvedexProdSdkGateway({
    apiKey: "api-key-test",
    expectedAccountId: "acct-prod-1",
    axiosAdapter: async (config) => {
      requests.push(config);
      if (config.url.endsWith("/api/user/me")) {
        const data = config.responseType === "arraybuffer"
          ? Buffer.from('{"exchangeId":"acct-prod-1"}')
          : { exchangeId: "acct-prod-1" };
        return { data, status: 200, statusText: "OK", headers: {}, config };
      }
      if (config.url.endsWith("/api/user/funding")) {
        const response = { data: fundingBody, status: 503, statusText: "Unavailable", headers: { "x-private": "discard" }, config };
        throw new axios.AxiosError("private adapter detail", "ERR_BAD_RESPONSE", config, undefined, response);
      }
      const data = Buffer.from('{"count":0,"list":[]}');
      return { data, status: 200, statusText: "OK", headers: {}, config };
    },
  });
  await gateway.preflight();
  const identity = await gateway.fetchRawCapture({ source: "account_identity" });
  assert.equal(identity.path, "/api/user/me");
  assert.equal(Buffer.from(identity.body_base64, "base64").toString("utf8"), '{"exchangeId":"acct-prod-1"}');
  const funding = await gateway.fetchRawCapture({ source: "funding" });
  assert.equal(funding.path, "/api/user/funding");
  assert.equal(funding.status, 503);
  assert.equal(Buffer.from(funding.body_base64, "base64").toString("utf8"), fundingBody.toString("utf8"));
  assert.deepEqual(Object.keys(funding).sort(), [
    "body_base64", "body_bytes", "body_sha256", "path", "query_json", "received_at", "requested_at", "source", "status",
  ]);
  const tpsl = await gateway.fetchRawCapture({ source: "tpsl_page", limit: 100, offset: 0 });
  assert.equal(tpsl.path, "/api/tpsl");
  assert.deepEqual(JSON.parse(tpsl.query_json), { limit: "100", offset: "0" });
  assert.equal(requests[3].url, "https://trading-api.evedex.com/api/tpsl?limit=100&offset=0");
  await gateway.close();
});

test("raw capture refuses parsed adapter objects instead of relabeling them as original response bytes", async () => {
  const gateway = new EvedexProdSdkGateway({
    apiKey: "api-key-test",
    expectedAccountId: "acct-prod-1",
    axiosAdapter: async (config) => ({
      data: config.url.endsWith("/api/user/me") ? { exchangeId: "acct-prod-1" } : { quantity: 1.23 },
      status: 200,
      statusText: "OK",
      headers: {},
      config,
    }),
  });
  await gateway.preflight();
  await assert.rejects(gateway.fetchRawCapture({ source: "funding" }), /no response capture/);
  await gateway.close();
});

test("SDK errors never expose error text or secret-bearing diagnostics", () => {
  const result = safeProdError(new Error("Authorization x-api-key=secret-1 url=https://api?token=secret-2"));
  assert.equal(JSON.stringify(result).includes("secret-1"), false);
  assert.equal(JSON.stringify(result).includes("secret-2"), false);
  assert.equal(JSON.stringify(result).includes("api-key"), false);
  assert.equal(result.message, "EVEDEX PROD SDK operation failed; reconcile before any further mutation.");
});

test("rejects chain mismatch, route/body substitution, and account aliases", async () => {
  const { gateway } = fixture();
  await assert.rejects(
    gateway.sendSignedPost({ method: "POST", path: cases[0][0], body: { ...cases[0][1], chainId: 161803 } }),
    /chain differs/,
  );
  await assert.rejects(
    gateway.sendSignedPost({ method: "PUT", path: cases[0][0], body: cases[0][1] }),
    /only exact signed POST/,
  );
  await assert.rejects(
    gateway.sendSignedPost({ method: "POST", path: "/api/order/mass-cancel", body: cases[0][1] }),
    /outside the fixed/,
  );
  const wrongAccount = new EvedexProdSdkGateway({
    apiKey: "api-key-test",
    expectedAccountId: "acct-prod-1",
    gatewayFactory: () => ({
      createApiKeyAccount: async () => ({ exchangeGateway: {}, exchangeAccount: { id: "acct-prod-1", exchangeId: "other" } }),
      closeWsConnection: async () => {},
    }),
  });
  await assert.rejects(wrongAccount.preflight(), /exact configured PROD account/);
});
