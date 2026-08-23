import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";

import WebSocket from "ws";

import {
  requireDevInstrument,
  requireNonNegative,
  requirePositive,
  requireSide,
  requireText,
} from "./protocol.js";

// SDK 1.2.11 publishes both module formats, but its ESM bundle contains
// extensionless directory imports rejected by current Node. Its official CJS
// export is equivalent and works on all supported Node versions.
const require = createRequire(import.meta.url);
const evedex = require("@evedex/exchange-bot-sdk");
const sdkEntryPath = require.resolve("@evedex/exchange-bot-sdk");
const sdkPackage = JSON.parse(
  readFileSync(join(dirname(dirname(dirname(sdkEntryPath))), "package.json"), "utf8"),
);

export const PINNED_SDK_VERSION = "1.2.11";
const PAGE_LIMIT = 100;
const MAX_AUTHORITATIVE_RECORDS = 10_000;
const ENTRY_COMPENSATION_RESERVE = 4;
const ENTRY_REQUIRED_HEADROOM = ENTRY_COMPENSATION_RESERVE + 2;

export const DEV_PROFILE = Object.freeze({
  exchangeURI: "https://trading-api.evedex.tech",
  authURI: "https://auth-api.evedex.tech",
  centrifugeURI: "wss://ws.evedex.tech/connection/websocket",
  centrifugePrefix: "futures-perp-dev",
  chainId: "16182",
});

const MUTATION_OPERATIONS = new Set([
  "place_market",
  "place_limit",
  "close_position",
  "cancel_order",
  "create_tpsl",
  "cancel_tpsl",
  "set_leverage",
]);

export class LocalMutationBudget {
  constructor({
    capacity = 30,
    windowMs = 60_000,
    entryCompensationReserve = ENTRY_COMPENSATION_RESERVE,
    clock = () => Date.now(),
  } = {}) {
    if (
      !Number.isInteger(capacity) ||
      capacity <= 0 ||
      !Number.isFinite(windowMs) ||
      windowMs <= 0 ||
      !Number.isInteger(entryCompensationReserve) ||
      entryCompensationReserve < 0 ||
      entryCompensationReserve >= capacity
    ) {
      throw new TypeError("local mutation budget requires a positive capacity and window");
    }
    this.capacity = capacity;
    this.windowMs = windowMs;
    this.entryCompensationReserve = entryCompensationReserve;
    this.clock = clock;
    this.timestamps = [];
  }

  reserve(operation) {
    this.#prune();
    const remaining = this.capacity - this.timestamps.length;
    if (remaining <= 0) {
      throw new Error("local EVEDEX mutation rate-limit reserve is exhausted");
    }
    const entry = ["place_market", "place_limit"].includes(operation);
    const compensating = ["cancel_order", "cancel_tpsl", "close_position"].includes(operation);
    if (entry && remaining <= this.entryCompensationReserve + 2) {
      throw new Error("local EVEDEX mutation reserve cannot fund mandatory STOP and TARGET");
    }
    if (!entry && !compensating && remaining <= this.entryCompensationReserve) {
      throw new Error("local EVEDEX mutation reserve is held for exposure compensation");
    }
    this.timestamps.push(this.clock());
    return this.remaining();
  }

  remaining() {
    this.#prune();
    return this.capacity - this.timestamps.length;
  }

  #prune() {
    const cutoff = this.clock() - this.windowMs;
    while (this.timestamps.length > 0 && this.timestamps[0] <= cutoff) this.timestamps.shift();
  }
}

export function assertPinnedDevProfile() {
  if (sdkPackage?.version !== PINNED_SDK_VERSION) {
    throw new Error("installed EVEDEX SDK version differs from the exact Kairos pin");
  }
  const actual = evedex.GatewayParamsMap.get(evedex.Environment.DEV);
  const endpointKeys = ["exchangeURI", "authURI", "centrifugeURI", "centrifugePrefix"];
  if (!actual || endpointKeys.some((key) => actual[key] !== DEV_PROFILE[key])) {
    throw new Error("installed EVEDEX SDK DEV endpoints differ from the pinned Kairos allowlist");
  }
}

export async function fetchAllPages(fetchPage, baseQuery = {}) {
  const records = [];
  const ids = new Set();
  let expectedCount;
  for (let offset = 0; offset <= MAX_AUTHORITATIVE_RECORDS; offset += PAGE_LIMIT) {
    const page = await fetchPage({ ...baseQuery, limit: PAGE_LIMIT, offset });
    if (
      !page ||
      typeof page !== "object" ||
      !Array.isArray(page.list) ||
      !Number.isInteger(page.count) ||
      page.count < 0 ||
      page.count > MAX_AUTHORITATIVE_RECORDS ||
      page.list.length > PAGE_LIMIT
    ) {
      throw new Error("EVEDEX authoritative paginated response is malformed or exceeds its bound");
    }
    if (expectedCount === undefined) expectedCount = page.count;
    if (page.count !== expectedCount) {
      throw new Error("EVEDEX authoritative paginated response changed during reconciliation");
    }
    for (const record of page.list) {
      const id = record?.id;
      if (typeof id !== "string" || id.length === 0 || ids.has(id)) {
        throw new Error("EVEDEX authoritative paginated response has missing or duplicate IDs");
      }
      ids.add(id);
      records.push(record);
    }
    if (records.length === expectedCount) return records;
    if (page.list.length === 0 || records.length > expectedCount) {
      throw new Error("EVEDEX authoritative paginated response is incomplete");
    }
  }
  throw new Error("EVEDEX authoritative pagination exceeded its safety bound");
}

export function installedSdkDevChainId() {
  const actual = evedex.GatewayParamsMap.get(evedex.Environment.DEV);
  if (!actual || typeof actual.chainId !== "string") {
    throw new Error("installed EVEDEX SDK DEV chain metadata is malformed");
  }
  return actual.chainId;
}

function readSecretFile(name) {
  const path = process.env[`${name}_FILE`];
  if (typeof path !== "string" || path.length === 0 || path.includes("\0")) {
    throw new Error(`${name}_FILE is required`);
  }
  const value = readFileSync(path, { encoding: "utf8" }).trim();
  if (value.length === 0) {
    throw new Error(`${name}_FILE is empty`);
  }
  return value;
}

function side(value) {
  return value === "BUY" ? evedex.Side.Buy : evedex.Side.Sell;
}

function tpSlType(value) {
  if (value === "STOP_LOSS") return evedex.TpSlType.StopLoss;
  if (value === "TAKE_PROFIT") return evedex.TpSlType.TakeProfit;
  throw new TypeError("tpsl_type must be STOP_LOSS or TAKE_PROFIT");
}

function tokenExpiresSoon(account) {
  const expiresAt = tokenExpiresAtMs(account);
  return expiresAt !== null && expiresAt <= Date.now() + 60_000;
}

export function tokenExpiresAtMs(account) {
  const token = account?.session?.accessToken;
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3) return 0;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    return typeof payload.exp === "number" ? payload.exp * 1000 : 0;
  } catch {
    return 0;
  }
}

export class EvedexSdkGateway {
  constructor({ apiKey, privateKey, expectedAccountId } = {}) {
    assertPinnedDevProfile();
    this.apiKey = apiKey ?? readSecretFile("EVEDEX_DEV_API_KEY");
    this.privateKey = privateKey ?? readSecretFile("EVEDEX_DEV_PRIVATE_KEY");
    this.expectedAccountId =
      expectedAccountId ?? process.env.EVEDEX_DEV_EXPECTED_ACCOUNT_ID;
    if (!this.expectedAccountId) throw new Error("EVEDEX_DEV_EXPECTED_ACCOUNT_ID is required");
    this.container = undefined;
    this.walletAccount = undefined;
    this.readAccount = undefined;
    this.authPromise = undefined;
    this.balance = undefined;
    this.events = [];
    this.eventSequence = 0;
    this.authenticatedAtMs = undefined;
    this.mutationBudget = new LocalMutationBudget();
  }

  async ensureAccounts({ force = false } = {}) {
    if (
      !force &&
      this.walletAccount &&
      this.readAccount &&
      !tokenExpiresSoon(this.walletAccount)
    ) {
      return;
    }
    if (this.authPromise) return this.authPromise;
    this.authPromise = this.#authenticate();
    try {
      await this.authPromise;
    } finally {
      this.authPromise = undefined;
    }
  }

  async #authenticate() {
    if (this.balance?.listening) await this.balance.unListen();
    this.container?.closeWsConnection();
    const container = new evedex.Container({
      environment: evedex.Environment.DEV,
      centrifugeWebSocket: WebSocket,
      wallets: { signing: { privateKey: this.privateKey } },
      apiKeys: { readonly: { apiKey: this.apiKey } },
      // SDK 1.2.11 still embeds the superseded 421614 DEV chain. This exact,
      // non-configurable override mirrors official repository master. No
      // environment variable or request can alter it.
      gatewayOverrides: DEV_PROFILE,
    });
    // No gateway overrides are permitted: the SDK profile is the safety boundary.
    const [walletAccount, readAccount] = await Promise.all([
      container.account("signing"),
      container.apiKeyAccount("readonly"),
    ]);
    const [signingAccount, readOnlyAccount, instruments] = await Promise.all([
      walletAccount.fetchMe(),
      readAccount.fetchMe(),
      container.gateway().fetchInstruments(),
    ]);
    const signingIdentity = this.#assertExpectedAccount(signingAccount, "signing wallet");
    const readIdentity = this.#assertExpectedAccount(readOnlyAccount, "API key");
    if (signingIdentity !== readIdentity) {
      throw new Error("EVEDEX signing wallet and API key resolve to different PAPER accounts");
    }
    this.#assertVenueInstruments(instruments);
    const balance = walletAccount.getBalance();
    balance.onAccountUpdate((value) => this.#recordEvent("ACCOUNT", value));
    balance.onFundingUpdate((value) => this.#recordEvent("FUNDING", value));
    balance.onPositionUpdate((value) => this.#recordEvent("POSITION", value));
    balance.onOrderUpdate((value) => this.#recordEvent("ORDER", value));
    balance.onTpSlUpdate((value) => this.#recordEvent("TPSL", value));
    balance.onOrderFillsUpdate((value) => this.#recordEvent("FILL", value));
    await balance.listen();
    this.container = container;
    this.walletAccount = walletAccount;
    this.readAccount = readAccount;
    this.balance = balance;
    this.authenticatedAtMs = Date.now();
  }

  #recordEvent(type, payload) {
    this.eventSequence += 1;
    this.events.push({ sequence: this.eventSequence, type, payload });
    if (this.events.length > 10_000) this.events.shift();
  }

  #assertExpectedAccount(account, credential) {
    if (!account || typeof account !== "object") {
      throw new Error("EVEDEX DEV account preflight returned malformed metadata");
    }
    const identities = new Set(
      [account.id, account.exchangeId, account.user]
        .filter((value) => value !== null && value !== undefined)
        .map(String),
    );
    if (!identities.has(this.expectedAccountId)) {
      throw new Error(`authenticated EVEDEX ${credential} does not match the dedicated PAPER account`);
    }
    return this.expectedAccountId;
  }

  #assertVenueInstruments(instruments) {
    if (!Array.isArray(instruments)) {
      throw new Error("EVEDEX DEV instrument preflight returned a malformed list");
    }
    const required = new Set([
      "BTCUSD:DEV",
      "ETHUSD:DEV",
      "SOLUSD:DEV",
      "BNBUSD:DEV",
      "XRPUSD:DEV",
    ]);
    for (const instrument of instruments) {
      if (!required.has(String(instrument?.name ?? "").toUpperCase())) continue;
      const trading = String(instrument?.trading ?? "").toLowerCase();
      if (trading !== "all") {
        throw new Error("an allowlisted EVEDEX DEV instrument is not fully tradeable");
      }
      required.delete(String(instrument.name).toUpperCase());
    }
    if (required.size !== 0) {
      throw new Error("EVEDEX DEV is missing one or more allowlisted PAPER instruments");
    }
  }

  async call(operation, payload) {
    const readOnly = operation.startsWith("fetch_") || operation === "health";
    await this.ensureAccounts();
    if (MUTATION_OPERATIONS.has(operation)) this.mutationBudget.reserve(operation);
    try {
      return await this.#dispatch(operation, payload);
    } catch (error) {
      // A read can be repeated after a serialized full SIWE re-auth. Mutations
      // are never retried here because their outcome may be ambiguous.
      if (readOnly && error?.name === "RefreshTokenExpiredError") {
        await this.ensureAccounts({ force: true });
        return this.#dispatch(operation, payload);
      }
      throw error;
    }
  }

  async #dispatch(operation, payload) {
    const wallet = this.walletAccount;
    const read = this.readAccount;
    if (!wallet || !read || !this.container) throw new Error("EVEDEX accounts are not authenticated");

    switch (operation) {
      case "health":
        {
          const now = Date.now();
          const expiresAt = tokenExpiresAtMs(this.walletAccount);
          return {
            ok: true,
            profile: "DEV",
            chain_id: Number(DEV_PROFILE.chainId),
            exchange_url: DEV_PROFILE.exchangeURI,
            auth_url: DEV_PROFILE.authURI,
            sdk_version: PINNED_SDK_VERSION,
            auth_age_ms: Math.max(0, now - (this.authenticatedAtMs ?? now)),
            auth_expires_in_ms: expiresAt === null ? null : Math.max(0, expiresAt - now),
            local_mutation_rate_limit_reserve: this.mutationBudget.remaining(),
            local_mutation_rate_limit_capacity: this.mutationBudget.capacity,
            local_mutation_rate_limit_window_ms: this.mutationBudget.windowMs,
            local_mutation_compensation_reserve: this.mutationBudget.entryCompensationReserve,
            local_mutation_entry_min_reserve: ENTRY_REQUIRED_HEADROOM + 1,
            venue_rate_limit_reserve: null,
            venue_rate_limit_observable: false,
          };
        }
      case "fetch_account":
        return Promise.all([
          read.fetchMe(),
          read.fetchAvailableBalance(),
          read.fetchPositions(),
          read.fetchOpenOrders(),
          fetchAllPages((query) => read.fetchTpSlList(query)),
          fetchAllPages((query) => read.fetchOrders(query)),
          this.container.gateway().fetchInstrumentsWithMetrics(),
        ]).then(([account, balance, positions, orders, tpsl, orderHistory, instruments]) => ({
          account,
          balance,
          positions,
          orders,
          tpsl,
          order_history: orderHistory,
          instruments,
        }));
      case "fetch_open_orders":
        return read.fetchOpenOrders();
      case "fetch_positions":
        return read.fetchPositions();
      case "fetch_tpsl": {
        const instrument = payload.instrument
          ? requireDevInstrument(payload)
          : undefined;
        return fetchAllPages(
          (query) => read.fetchTpSlList(query),
          instrument ? { instrument } : {},
        );
      }
      case "fetch_instruments":
        return this.container.gateway().fetchInstrumentsWithMetrics();
      case "fetch_depth":
        return this.container.gateway().fetchMarketDepth({
          instrument: requireDevInstrument(payload),
          maxLevel: Math.min(100, Math.max(1, payload.max_level ?? 20)),
        });
      case "drain_events": {
        const limit = Math.min(1000, Math.max(1, payload.limit ?? 100));
        return { events: this.events.splice(0, limit) };
      }
      case "place_market":
        return wallet.createMarketOrderV2({
          id: requireText(payload, "client_order_id"),
          instrument: requireDevInstrument(payload),
          side: side(requireSide(payload)),
          leverage: requirePositive(payload, "leverage"),
          timeInForce: evedex.TimeInForce.IOC,
          cashQuantity: requirePositive(payload, "cash_quantity"),
        });
      case "place_limit":
        return wallet.createLimitOrderV2({
          id: requireText(payload, "client_order_id"),
          instrument: requireDevInstrument(payload),
          side: side(requireSide(payload)),
          leverage: requirePositive(payload, "leverage"),
          quantity: requirePositive(payload, "quantity"),
          limitPrice: requirePositive(payload, "limit_price"),
          postOnly: false,
          timeInForce: evedex.TimeInForce.IOC,
        });
      case "close_position":
        return wallet.createClosePositionOrderV2({
          id: requireText(payload, "client_order_id"),
          instrument: requireDevInstrument(payload),
          leverage: requirePositive(payload, "leverage"),
          quantity: requirePositive(payload, "quantity"),
        });
      case "cancel_order": {
        const orderId = requireText(payload, "client_order_id");
        await wallet.cancelOrder({ orderId });
        return { id: orderId, status: "CANCELED" };
      }
      case "create_tpsl":
        return wallet.createTpSl({
          instrument: requireDevInstrument(payload),
          side: side(requireSide(payload)),
          type: tpSlType(payload.tpsl_type),
          quantity: requireNonNegative(payload, "quantity"),
          price: requirePositive(payload, "price"),
          order: payload.parent_order_id ?? null,
        });
      case "cancel_tpsl": {
        const id = requireText(payload, "tpsl_id");
        await wallet.cancelTpSl({
          instrument: requireDevInstrument(payload),
          id,
        });
        return { id, status: "CANCELED" };
      }
      case "set_leverage":
        return wallet.updatePosition({
          instrument: requireDevInstrument(payload),
          leverage: requirePositive(payload, "leverage"),
        });
      default:
        throw new TypeError(`unsupported operation ${operation}`);
    }
  }

  async close() {
    if (this.balance?.listening) await this.balance.unListen();
    this.container?.closeWsConnection();
  }
}
