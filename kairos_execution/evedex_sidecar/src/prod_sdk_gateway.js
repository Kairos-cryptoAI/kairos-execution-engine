import { createRequire } from "node:module";
import { Agent as HttpsAgent } from "node:https";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { createHash } from "node:crypto";

// Importing this module only defines the existing budget/helper classes. No
// DEV gateway, wallet, signer, network connection or container is constructed.
import { LocalMutationBudget } from "./sdk_gateway.js";

const require = createRequire(import.meta.url);
const evedex = require("@evedex/exchange-bot-sdk");
const sdkEntry = require.resolve("@evedex/exchange-bot-sdk");
const { RestClient } = require(join(dirname(sdkEntry), "utils", "rest.js"));
const axios = require("axios");
const SDK_VERSION = "1.2.11";
const EXCHANGE_API_VERSION = "1.0.70";
const EXCHANGE_CRYPTO_VERSION = "1.1.0";
const PAGE_LIMIT = 100;
const MAX_RECORDS = 10_000;
const HTTP_TIMEOUT_MS = 20_000;
const MAX_HTTP_BYTES = 4 * 1024 * 1024;
const MAX_RAW_CAPTURE_BYTES = 2 * 1024 * 1024;
const PROD_PROFILE = Object.freeze({
  exchangeURI: "https://trading-api.evedex.com",
  authURI: "https://auth-api.evedex.com",
  centrifugeURI: "wss://ws.evedex.com/connection/websocket",
  centrifugePrefix: "futures-perp",
  chainId: "42161",
});

const HTTP_ORIGINS = new Set([new URL(PROD_PROFILE.exchangeURI).origin, new URL(PROD_PROFILE.authURI).origin]);
export const PROD_HISTORY_OPENAPI_SOURCE = "https://exchange-api.evedex.com/api/openapi.json";
const FUNDING_TRANSFER_TYPES = new Set([
  "deposit", "withdraw", "faucet", "faucetLiquidity", "realizedPnl", "orderFillFee",
  "fundingRate", "liquidationFee", "bonusRefund", "yieldReward", "copyTradingFee",
]);

export function validateProdHistoryRead(payload) {
  const source = payload.source;
  const required = source === "order_fills" ? ["source", "order_id"] : ["source", "after", "before", "limit", "offset"];
  const optional = source === "funding_transfers" ? "transfer_type" : "instrument";
  const expected = [...required, ...(source !== "order_fills" && Object.hasOwn(payload, optional) ? [optional] : [])].sort();
  const keys = Object.keys(payload).sort();
  if (!["order_fills", "funding_transfers", "fill_history"].includes(source) ||
      keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new TypeError("raw documented history fields are not exact");
  }
  if (source === "order_fills") {
    if (typeof payload.order_id !== "string" || !/^[0-9]{5}:[0-9A-Fa-f]{26}$/.test(payload.order_id)) {
      throw new TypeError("order fills require one exact V2 order ID");
    }
    return;
  }
  const times = [payload.after, payload.before];
  if (times.some((value) => typeof value !== "string" ||
      !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/.test(value) ||
      !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) ||
      Date.parse(payload.before) <= Date.parse(payload.after) ||
      Date.parse(payload.before) - Date.parse(payload.after) > 86_400_000 ||
      !Number.isInteger(payload.limit) || payload.limit < 1 || payload.limit > 100 ||
      !Number.isInteger(payload.offset) || payload.offset < 0 || payload.offset > 10_000 ||
      (Object.hasOwn(payload, "transfer_type") && !FUNDING_TRANSFER_TYPES.has(payload.transfer_type)) ||
      (Object.hasOwn(payload, "instrument") && (typeof payload.instrument !== "string" || !/^[A-Z0-9]{1,32}$/.test(payload.instrument)))) {
    throw new TypeError("raw documented history query is outside its bounded UTC read contract");
  }
}

function validateProdHttpUrl(request) {
  if (typeof request?.url !== "string") throw new TypeError("EVEDEX HTTP URL is missing");
  let url;
  try {
    url = new URL(request.url);
  } catch {
    throw new TypeError("EVEDEX HTTP URL is malformed");
  }
  if (url.protocol !== "https:" || !HTTP_ORIGINS.has(url.origin) || url.username || url.password || url.hash) {
    throw new TypeError("EVEDEX HTTP destination is outside the fixed HTTPS PROD origins");
  }
  const route = `${String(request.method).toUpperCase()} ${url.pathname}`;
  if (url.origin !== new URL(PROD_PROFILE.exchangeURI).origin) {
    throw new TypeError("EVEDEX PROD API-key account does not authorize auth-origin requests");
  }
  const allowed = new Set([
    "GET /api/user/me",
    "GET /api/user/funding",
    "GET /api/order",
    "GET /api/tpsl",
    "GET /api/market/available-balance",
    "GET /api/position",
    "GET /api/order/opened",
    "GET /api/market/instrument",
    "GET /api/user/funding-transfer",
    "GET /api/fill",
    "POST /api/v2/order/limit",
    "POST /api/v2/order/market",
    "POST /api/v2/order/stop-limit",
  ]);
  if (!allowed.has(route) && !/^GET \/api\/market\/[A-Z0-9]{1,32}\/deep$/.test(route) &&
      !/^GET \/api\/order\/[0-9]{5}:[0-9A-Fa-f]{26}\/fill$/.test(route) &&
      !/^GET \/api\/order\/[A-Za-z0-9_.:-]{1,160}$/.test(route) &&
      !/^DELETE \/api\/order\/[A-Za-z0-9_.:-]{1,160}$/.test(route) &&
      !/^POST \/api\/v2\/position\/[A-Z0-9]{1,32}\/close$/.test(route) &&
      !/^POST \/api\/tpsl\/[A-Z0-9]{1,32}$/.test(route) &&
      !/^DELETE \/api\/tpsl\/[A-Z0-9]{1,32}\/[A-Za-z0-9_.:-]{1,160}$/.test(route)) {
    throw new TypeError("EVEDEX HTTP route is outside the fixed PROD method allowlist");
  }
  return url;
}

export class PinnedProdRestClient extends RestClient {
  constructor({ adapter, clock = () => Date.now() } = {}) {
    super({});
    this.adapter = adapter;
    this.clock = clock;
    this.mutationBudget = new LocalMutationBudget({ clock });
    this.httpsAgent = new HttpsAgent({ keepAlive: false, maxSockets: 8 });
    this.rawCaptureExpected = undefined;
    this.rawCapture = undefined;
  }

  beginRawCapture(expected) {
    if (this.rawCaptureExpected || this.rawCapture) throw new Error("a raw HTTP capture is already active");
    this.rawCaptureExpected = expected;
  }

  takeRawCapture() {
    const capture = this.rawCapture;
    this.rawCapture = undefined;
    this.rawCaptureExpected = undefined;
    if (!capture) throw new Error("the fixed raw HTTP read produced no response capture");
    return capture;
  }

  #validateCaptureRequest(request, url) {
    if (!this.rawCaptureExpected) return;
    if (String(request.method).toUpperCase() !== "GET" || url.pathname !== this.rawCaptureExpected.path) {
      throw new TypeError("raw capture request differs from its fixed GET route");
    }
    const actual = [...url.searchParams.entries()].sort(([a], [b]) => a.localeCompare(b));
    const expected = Object.entries(this.rawCaptureExpected.query).map(([key, value]) => [key, String(value)])
      .sort(([a], [b]) => a.localeCompare(b));
    if (actual.length !== expected.length || actual.some(([key, value], index) =>
      key !== expected[index][0] || value !== expected[index][1])) {
      throw new TypeError("raw capture request query differs from its fixed read contract");
    }
  }

  #retainRawCapture(request, url, response, requestedAt) {
    if (!this.rawCaptureExpected) return;
    const data = response?.data;
    if (!(Buffer.isBuffer(data) || data instanceof Uint8Array || typeof data === "string")) {
      throw new TypeError("raw HTTP capture requires original application response bytes");
    }
    const bytes = Buffer.from(data);
    if (bytes.length > MAX_RAW_CAPTURE_BYTES) throw new Error("raw HTTP response exceeds the capture bound");
    const receivedAt = new Date(this.clock()).toISOString();
    const query = Object.fromEntries([...url.searchParams.entries()]);
    this.rawCapture = {
      source: this.rawCaptureExpected.source,
      path: url.pathname,
      query_json: JSON.stringify(query, Object.keys(query).sort()),
      status: response.status,
      requested_at: requestedAt,
      received_at: receivedAt,
      body_bytes: bytes.length,
      body_sha256: createHash("sha256").update(bytes).digest("hex"),
      body_base64: bytes.toString("base64"),
    };
  }

  async authRequest(request) {
    // Check destination before the SDK adds the API-key header.
    const url = validateProdHttpUrl(request);
    this.#validateCaptureRequest(request, url);
    const session = this.getSession();
    if (!session || typeof session.apiKey !== "string" || Object.keys(session).length !== 1) {
      throw new TypeError("EVEDEX PROD HTTP client accepts API-key authentication only");
    }
    return super.authRequest(request);
  }

  async request(request) {
    const url = validateProdHttpUrl(request);
    this.#validateCaptureRequest(request, url);
    const requestedAt = new Date(this.clock()).toISOString();
    const captureActive = this.rawCaptureExpected !== undefined;
    const config = {
      url: url.toString(),
      method: request.method,
      headers: request.headers,
      data: request.body,
      timeout: HTTP_TIMEOUT_MS,
      maxRedirects: 0,
      proxy: false,
      ...(captureActive ? { responseType: "arraybuffer" } : {}),
      maxContentLength: captureActive ? MAX_RAW_CAPTURE_BYTES : MAX_HTTP_BYTES,
      maxBodyLength: MAX_HTTP_BYTES,
      httpsAgent: this.httpsAgent,
      ...(this.adapter ? { adapter: this.adapter } : {}),
    };
    const method = String(request.method).toUpperCase();
    if (method === "POST" || method === "DELETE") {
      let operation;
      if (/^\/api\/v2\/order\/(limit|stop-limit)$/.test(url.pathname)) operation = "place_limit";
      else if (url.pathname === "/api/v2/order/market") operation = "place_market";
      else if (/^\/api\/v2\/position\/[A-Z0-9]{1,32}\/close$/.test(url.pathname)) operation = "close_position";
      else if (method === "POST" && /^\/api\/tpsl\//.test(url.pathname)) operation = "create_tpsl";
      else if (method === "DELETE" && /^\/api\/tpsl\//.test(url.pathname)) operation = "cancel_tpsl";
      else if (method === "DELETE" && /^\/api\/order\//.test(url.pathname)) operation = "cancel_order";
      else throw new TypeError("PROD mutation has no enforced local budget classification");
      // Reserve at the single actual HTTP-send boundary, not at SDK dispatch
      // or authentication. Failed/ambiguous sends are spent, never refunded.
      this.mutationBudget.reserve(operation);
    }
    try {
      const response = await axios.request(config);
      if (!captureActive) return response;
      if (!(Buffer.isBuffer(response.data) || response.data instanceof Uint8Array || typeof response.data === "string")) {
        throw new TypeError("raw HTTP capture requires original application response bytes");
      }
      const bytes = Buffer.from(response.data);
      if (captureActive) this.#retainRawCapture(request, url, { ...response, data: bytes }, requestedAt);
      let parsed;
      try {
        parsed = JSON.parse(bytes.toString("utf8"));
      } catch {
        throw new Error("EVEDEX PROD HTTP response was not valid JSON");
      }
      return { ...response, data: parsed };
    } catch (error) {
      if (captureActive && error?.response) {
        try {
          this.#retainRawCapture(request, url, error.response, requestedAt);
        } catch {
          // Raw evidence that exceeds the fixed bound is never returned.
        }
      }
      // The SDK's RequestError retains request headers, so never pass it through.
      throw new Error("EVEDEX PROD HTTP transport failed");
    }
  }
}

const OPERATIONS = new Map([
  ["/api/v2/order/limit", {
    keys: ["id", "instrument", "side", "leverage", "quantity", "limitPrice", "chainId", "timeInForce", "signature"],
    call: (gateway, body) => gateway.createLimitOrderV2(body),
  }],
  ["/api/v2/order/market", {
    keys: ["id", "instrument", "side", "timeInForce", "leverage", "cashQuantity", "chainId", "signature"],
    call: (gateway, body) => gateway.createMarketOrderV2(body),
  }],
  ["/api/v2/order/stop-limit", {
    keys: ["id", "instrument", "side", "leverage", "quantity", "limitPrice", "stopPrice", "chainId", "signature"],
    call: (gateway, body) => gateway.createStopLimitOrderV2(body),
  }],
  ["/api/v2/position/{instrument}/close", {
    keys: ["id", "instrument", "leverage", "quantity", "chainId", "signature"],
    call: (gateway, body) => gateway.closePositionV2(body),
  }],
  ["/api/tpsl/{instrument}", {
    keys: ["instrument", "type", "side", "quantity", "price", "order", "signature"],
    call: (gateway, body) => gateway.createTpSl(body),
  }],
]);

function packageVersion(packageName) {
  const entry = require.resolve(packageName);
  let directory = dirname(entry);
  for (;;) {
    const candidate = join(directory, "package.json");
    try {
      const parsed = JSON.parse(readFileSync(candidate, "utf8"));
      if (parsed.name === packageName) return parsed.version;
    } catch {
      // Continue to the package root; no package contents are trusted as config.
    }
    const parent = dirname(directory);
    if (parent === directory) throw new Error("pinned EVEDEX dependency metadata is unavailable");
    directory = parent;
  }
}

export function assertPinnedProdProfile(sdk = evedex) {
  if (
    packageVersion("@evedex/exchange-bot-sdk") !== SDK_VERSION ||
    packageVersion("@evedex/exchange-api") !== EXCHANGE_API_VERSION ||
    packageVersion("@evedex/exchange-crypto") !== EXCHANGE_CRYPTO_VERSION
  ) {
    throw new Error("installed EVEDEX SDK components differ from the reviewed production pins");
  }
  const actual = sdk.GatewayParamsMap.get(sdk.Environment.PROD);
  if (!actual || Object.keys(PROD_PROFILE).some((key) => actual[key] !== PROD_PROFILE[key])) {
    throw new Error("installed EVEDEX SDK production profile differs from the reviewed endpoint and chain pin");
  }
  return { ...PROD_PROFILE, sdkVersion: SDK_VERSION, exchangeApiVersion: EXCHANGE_API_VERSION };
}

function text(value, field) {
  if (typeof value !== "string" || value.length === 0 || value.length > 160 || /[\u0000-\u001f]/.test(value)) {
    throw new TypeError(`${field} is malformed`);
  }
  return value;
}

function validateBody(path, body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new TypeError("signed body must be an object");
  const operation = OPERATIONS.get(path);
  if (!operation) {
    const closeMatch = /^\/api\/v2\/position\/([A-Z0-9]{1,32})\/close$/.exec(path);
    const tpslMatch = /^\/api\/tpsl\/([A-Z0-9]{1,32})$/.exec(path);
    const matchedPath = closeMatch ? "/api/v2/position/{instrument}/close" : tpslMatch ? "/api/tpsl/{instrument}" : null;
    if (!matchedPath || body.instrument !== (closeMatch?.[1] ?? tpslMatch?.[1])) {
      throw new TypeError("signed operation is outside the fixed EVEDEX production allowlist");
    }
    path = matchedPath;
  }
  const selected = OPERATIONS.get(path);
  const keys = Object.keys(body).sort();
  const expected = [...selected.keys].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new TypeError("signed body fields differ from the pinned EVEDEX production schema");
  }
  if (!/^0x[0-9a-fA-F]{130}$/.test(body.signature)) throw new TypeError("signed body signature is malformed");
  if (!/^[A-Z0-9]{1,32}$/.test(text(body.instrument, "instrument"))) throw new TypeError("instrument is malformed");
  if ("chainId" in body && body.chainId !== 42161) throw new TypeError("signed message chain differs from the pinned EVEDEX production chain");
  if ("side" in body && !["BUY", "SELL"].includes(body.side)) throw new TypeError("signed side is malformed");
  if ("timeInForce" in body && body.timeInForce !== "IOC") throw new TypeError("only the pinned IOC policy is supported");
  for (const field of ["quantity", "limitPrice", "stopPrice", "cashQuantity", "price"]) {
    if (field in body && (typeof body[field] !== "string" || !/^(0|[1-9][0-9]*)(\.[0-9]*[1-9])?$/.test(body[field]))) {
      throw new TypeError(`${field} must be a canonical decimal string`);
    }
  }
  if ("id" in body) text(body.id, "id");
  if ("order" in body) text(body.order, "order");
  if ("type" in body && !["stop-loss", "take-profit"].includes(body.type)) throw new TypeError("TP/SL type is malformed");
  return { operation: selected, body };
}

function expectedAccount(account, expectedAccountId) {
  if (!account || String(account.exchangeId ?? "") !== expectedAccountId) {
    throw new Error("authenticated EVEDEX API key does not match the exact configured PROD account");
  }
}

export class EvedexProdSdkGateway {
  constructor({ apiKey, expectedAccountId, gatewayFactory, axiosAdapter, clock = () => Date.now() } = {}) {
    this.profile = assertPinnedProdProfile();
    if (typeof apiKey !== "string" || apiKey.length === 0) throw new Error("EVEDEX_PROD_API_KEY is required");
    if (typeof expectedAccountId !== "string" || expectedAccountId.length === 0) {
      throw new Error("EVEDEX_PROD_EXPECTED_ACCOUNT_ID is required");
    }
    this.apiKey = apiKey;
    this.expectedAccountId = expectedAccountId;
    this.gatewayFactory = gatewayFactory ?? ((options) => new evedex.Gateway(options));
    this.axiosAdapter = axiosAdapter;
    this.clock = clock;
    this.httpClient = undefined;
    this.gateway = undefined;
    this.account = undefined;
    this.authPromise = undefined;
    this.preflightAttempted = false;
    this.preflightFailed = false;
  }

  async preflight() {
    if (this.account) return this.authenticatedIdentity;
    if (this.authPromise) return this.authPromise;
    if (this.preflightFailed || this.preflightAttempted) throw new Error("EVEDEX PROD SDK preflight already failed; create a fresh client after reconciliation");
    this.preflightAttempted = true;
    this.authPromise = (async () => {
      const httpClient = new PinnedProdRestClient({ adapter: this.axiosAdapter, clock: this.clock });
      const gateway = this.gatewayFactory({
        authURI: this.profile.authURI,
        exchangeURI: this.profile.exchangeURI,
        centrifuge: { uri: this.profile.centrifugeURI, prefix: this.profile.centrifugePrefix },
        httpClient,
      });
      try {
        httpClient.beginRawCapture({ source: "account_identity", path: "/api/user/me", query: {} });
        const account = await gateway.createApiKeyAccount({ apiKey: this.apiKey });
        const identity = account?.exchangeAccount;
        expectedAccount(identity, this.expectedAccountId);
        const preflightCapture = httpClient.takeRawCapture();
        if (preflightCapture.status < 200 || preflightCapture.status >= 300) {
          throw new Error("PROD authentication did not produce a successful native response");
        }
        this.gateway = gateway;
        this.httpClient = httpClient;
        this.account = account;
        this.authenticatedIdentity = identity;
        this.preflightCapture = preflightCapture;
        this.authenticatedAtMs = Date.parse(preflightCapture.received_at);
        return identity;
      } catch (error) {
        this.preflightFailed = true;
        await gateway.closeWsConnection?.();
        throw error;
      }
    })();
    try {
      await this.authPromise;
      return this.authenticatedIdentity;
    } finally {
      this.authPromise = undefined;
    }
  }

  #requirePreflight() {
    assertPinnedProdProfile();
    if (!this.account || this.preflightFailed) throw new Error("EVEDEX PROD SDK preflight is required before any operation");
  }

  readHealth() {
    this.#requirePreflight();
    const age = this.clock() - this.authenticatedAtMs;
    if (!Number.isSafeInteger(age) || age < 0) throw new Error("PROD authentication clock is invalid");
    const budget = this.httpClient.mutationBudget;
    return {
      ok: true, profile: "PROD", chain_id: Number(this.profile.chainId),
      exchange_url: this.profile.exchangeURI, auth_url: this.profile.authURI,
      sdk_version: SDK_VERSION, account_id: this.expectedAccountId,
      auth_age_ms: age, auth_expires_in_ms: null,
      local_mutation_rate_limit_observable: true,
      local_mutation_rate_limit_reserve: budget.remaining(),
      local_mutation_rate_limit_capacity: budget.capacity,
      local_mutation_rate_limit_window_ms: budget.windowMs,
      local_mutation_compensation_reserve: budget.entryCompensationReserve,
      local_mutation_entry_min_reserve: budget.entryCompensationReserve + 3,
      venue_rate_limit_observable: false, venue_rate_limit_reserve: null,
      preflight_capture: { ...this.preflightCapture },
    };
  }

  async sendSignedPost({ method, path, body }) {
    if (method !== "POST") throw new TypeError("only exact signed POST operations are supported");
    const validated = validateBody(path, body);
    this.#requirePreflight();
    return validated.operation.call(this.account.exchangeGateway, validated.body);
  }

  async cancelOrder({ instrument, orderId }) {
    text(instrument, "instrument");
    text(orderId, "orderId");
    if (!/^[A-Z0-9]{1,32}$/.test(instrument)) throw new TypeError("instrument is malformed");
    if (!/^[A-Za-z0-9_.:-]{1,160}$/.test(orderId)) throw new TypeError("orderId is malformed");
    this.#requirePreflight();
    await this.account.exchangeGateway.cancelOrder({ orderId });
    const record = await this.account.exchangeGateway.getOrder(orderId);
    if (record?.id !== orderId || record?.instrument !== instrument || record?.status !== "CANCELLED") {
      throw new Error("EVEDEX cancellation was not positively confirmed by the exact order record");
    }
    return { id: orderId, status: "CANCELED" };
  }

  async cancelTpSl({ instrument, protectionId }) {
    text(instrument, "instrument");
    text(protectionId, "protectionId");
    if (!/^[A-Z0-9]{1,32}$/.test(instrument)) throw new TypeError("instrument is malformed");
    if (!/^[A-Za-z0-9_.:-]{1,160}$/.test(protectionId)) throw new TypeError("protectionId is malformed");
    this.#requirePreflight();
    await this.account.exchangeGateway.cancelTpSl({ instrument, id: protectionId });
    const record = await this.#findCancelledTpSl(instrument, protectionId);
    if (!record) throw new Error("EVEDEX cancellation was not positively confirmed by the exact TP/SL record");
    return { id: protectionId, status: "CANCELED" };
  }

  async #findCancelledTpSl(instrument, protectionId) {
    let expectedCount;
    const seen = new Set();
    for (let offset = 0; offset <= MAX_RECORDS; offset += PAGE_LIMIT) {
      const page = await this.account.exchangeGateway.getTpSl({ instrument, limit: PAGE_LIMIT, offset });
      if (!page || !Number.isInteger(page.count) || page.count < 0 || page.count > MAX_RECORDS ||
          !Array.isArray(page.list) || page.list.length > PAGE_LIMIT) {
        throw new Error("EVEDEX TP/SL cancellation verification page is malformed");
      }
      if (expectedCount === undefined) expectedCount = page.count;
      if (page.count !== expectedCount) throw new Error("EVEDEX TP/SL history changed during cancellation verification");
      for (const item of page.list) {
        if (typeof item?.id !== "string" || seen.has(item.id)) throw new Error("EVEDEX TP/SL cancellation history has invalid identities");
        seen.add(item.id);
        if (item.id === protectionId) return item.instrument === instrument && item.status === "cancelled" ? item : null;
      }
      if (seen.size === expectedCount) return null;
      if (page.list.length === 0 || seen.size > expectedCount) throw new Error("EVEDEX TP/SL cancellation history is incomplete");
    }
    throw new Error("EVEDEX TP/SL cancellation verification exceeded its bound");
  }

  async fetchAccountIdentity() {
    this.#requirePreflight();
    return this.account.exchangeGateway.me();
  }

  async fetchOrderHistoryPage({ version, limit, offset, next }) {
    if (version !== 2 || !Number.isInteger(limit) || limit < 1 || limit > 100 ||
        !Number.isInteger(offset) || offset < 0 || offset > MAX_RECORDS ||
        (next !== undefined && (typeof next !== "string" || next.length === 0 || next.length > 500))) {
      throw new TypeError("order history page query is malformed");
    }
    this.#requirePreflight();
    return this.account.exchangeGateway.getOrders({ version, limit, offset, ...(next === undefined ? {} : { next }) });
  }

  async fetchTpSlPage({ limit, offset }) {
    if (!Number.isInteger(limit) || limit < 1 || limit > 100 || !Number.isInteger(offset) || offset < 0 || offset > MAX_RECORDS) {
      throw new TypeError("TP/SL history page query is malformed");
    }
    this.#requirePreflight();
    return this.account.exchangeGateway.getTpSl({ limit, offset });
  }

  async fetchFunding() {
    this.#requirePreflight();
    return this.account.exchangeGateway.getFunding();
  }

  async fetchRawCapture({ source, version, limit, offset, next, instrument, max_level,
    order_id, after, before, transfer_type }) {
    this.#requirePreflight();
    let path;
    let query;
    let read;
    if (["order_fills", "funding_transfers", "fill_history"].includes(source)) {
      const payload = source === "order_fills" ? { source, order_id } : {
        source, after, before, limit, offset,
        ...(transfer_type === undefined ? {} : { transfer_type }),
        ...(instrument === undefined ? {} : { instrument }),
      };
      validateProdHistoryRead(payload);
      path = source === "order_fills" ? `/api/order/${order_id}/fill`
        : source === "funding_transfers" ? "/api/user/funding-transfer" : "/api/fill";
      query = source === "order_fills" ? { version: 2 } : {
        after, before, limit, offset,
        ...(transfer_type === undefined ? {} : { type: transfer_type }),
        ...(instrument === undefined ? {} : { instrument }),
      };
      // The current official OpenAPI documents these GETs, but SDK 1.2.11 has
      // no named method. Use its existing authenticated GET, never a new client.
      read = () => this.account.exchangeGateway.authGet(path, new URLSearchParams(query).toString());
    } else if (source === "account_identity") {
      path = "/api/user/me";
      query = {};
      read = () => this.account.exchangeGateway.me();
    } else if (source === "funding") {
      path = "/api/user/funding";
      query = {};
      read = () => this.account.exchangeGateway.getFunding();
    } else if (source === "available_balance") {
      path = "/api/market/available-balance";
      query = {};
      read = () => this.account.exchangeGateway.getAvailableBalance();
    } else if (source === "positions") {
      path = "/api/position";
      query = {};
      read = () => this.account.exchangeGateway.getPositions();
    } else if (source === "open_orders") {
      path = "/api/order/opened";
      query = {};
      read = () => this.account.exchangeGateway.getOpenedOrders();
    } else if (source === "instruments") {
      path = "/api/market/instrument";
      query = { fields: "metrics" };
      read = () => this.account.exchangeGateway.getInstrumentsMetrics();
    } else if (source === "depth") {
      if (typeof instrument !== "string" || !/^[A-Z0-9]{1,32}$/.test(instrument) ||
          !Number.isInteger(max_level) || max_level < 1 || max_level > 100) {
        throw new TypeError("raw depth query is malformed");
      }
      path = `/api/market/${instrument}/deep`;
      query = { maxLevel: max_level };
      read = () => this.account.exchangeGateway.getMarketDepth({ instrument, maxLevel: max_level });
    } else if (source === "order_page") {
      if (version !== 2 || !Number.isInteger(limit) || limit < 1 || limit > PAGE_LIMIT ||
          !Number.isInteger(offset) || offset < 0 || offset > MAX_RECORDS ||
          (next !== undefined && (typeof next !== "string" || next.length < 1 || next.length > 500))) {
        throw new TypeError("raw order page query is malformed");
      }
      path = "/api/order";
      const sdkQuery = { version, limit, offset, ...(next === undefined ? {} : { next }) };
      // The pinned SDK always serializes this false/default field as an empty
      // query parameter; bind it explicitly rather than infer extra parameters.
      query = { ...sdkQuery, withTpSL: "" };
      read = () => this.account.exchangeGateway.getOrders(sdkQuery);
    } else if (source === "tpsl_page") {
      if (!Number.isInteger(limit) || limit < 1 || limit > PAGE_LIMIT ||
          !Number.isInteger(offset) || offset < 0 || offset > MAX_RECORDS) {
        throw new TypeError("raw TP/SL page query is malformed");
      }
      path = "/api/tpsl";
      query = { limit, offset };
      read = () => this.account.exchangeGateway.getTpSl(query);
    } else {
      throw new TypeError("raw capture source is outside the fixed account/history allowlist");
    }
    this.httpClient.beginRawCapture({ source, path, query });
    try {
      await read();
    } catch {
      // An HTTP error response may still have a bounded captured body/status.
      // Network and parse failures without a response remain failed reads.
    }
    return this.httpClient.takeRawCapture();
  }

  async close() {
    const gateway = this.gateway;
    this.gateway = undefined;
    this.account = undefined;
    this.httpClient = undefined;
    await gateway?.closeWsConnection?.();
  }
}

export const PROD_SDK_PROFILE = Object.freeze({ ...PROD_PROFILE, sdkVersion: SDK_VERSION, exchangeApiVersion: EXCHANGE_API_VERSION });

export function safeProdError(error) {
  const knownCode = ["TypeError", "RangeError", "Error"].includes(error?.name) ? error.name : "SdkOperationError";
  return { code: knownCode, message: "EVEDEX PROD SDK operation failed; reconcile before any further mutation." };
}
