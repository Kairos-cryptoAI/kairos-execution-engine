import assert from "node:assert/strict";
import test from "node:test";

import { EvedexSdkGateway } from "../src/sdk_gateway.js";

const EXPECTED_ACCOUNT = "paper-account";
const INSTRUMENTS = ["BTC", "ETH", "SOL", "BNB", "XRP"].map((symbol) => ({
  name: `${symbol}USD:DEV`,
  trading: "all",
}));

function makeGateway(configure = () => ({})) {
  const containers = [];
  const gateway = new EvedexSdkGateway({
    apiKey: "offline-api-key",
    privateKey: `0x${"1".repeat(64)}`,
    expectedAccountId: EXPECTED_ACCOUNT,
    containerFactory(options) {
      const config = configure(containers.length, options) ?? {};
      const listeners = new Map();
      const balance = {
        listening: false,
        unlistenCalls: 0,
        onAccountUpdate: (handler) => listeners.set("ACCOUNT", handler),
        onFundingUpdate: (handler) => listeners.set("FUNDING", handler),
        onPositionUpdate: (handler) => listeners.set("POSITION", handler),
        onOrderUpdate: (handler) => listeners.set("ORDER", handler),
        onTpSlUpdate: (handler) => listeners.set("TPSL", handler),
        onOrderFillsUpdate: (handler) => listeners.set("FILL", handler),
        async listen() {
          this.listening = true;
          for (const [type, value] of Object.entries(config.eventsOnListen ?? {})) {
            listeners.get(type)?.(value);
          }
          config.emitDuringListen?.((type, value) => listeners.get(type)?.(value));
          await config.listen?.();
        },
        emit(type, value) {
          listeners.get(type)?.(value);
        },
        async unListen() {
          this.unlistenCalls += 1;
          this.listening = false;
        },
      };
      const walletAccount = {
        async fetchMe() {
          return { id: config.signingId ?? EXPECTED_ACCOUNT };
        },
        getBalance: () => balance,
        async createLimitOrderV2(args) {
          config.onMutationDispatch?.(gateway.mutationBudget.remaining(), args);
          if (config.mutationError) throw config.mutationError;
          return { accepted: true };
        },
      };
      const readAccount = {
        async fetchMe() {
          return { id: config.readId ?? EXPECTED_ACCOUNT };
        },
        async fetchOpenOrders() {
          if (config.openOrdersError) throw config.openOrdersError;
          return config.openOrders ?? [];
        },
      };
      const container = {
        balance,
        closeCalls: 0,
        account(name) {
          assert.equal(name, "signing");
          return walletAccount;
        },
        apiKeyAccount(name) {
          assert.equal(name, "readonly");
          return readAccount;
        },
        gateway() {
          return {
            async fetchInstruments() {
              return config.instruments ?? INSTRUMENTS;
            },
          };
        },
        closeWsConnection() {
          this.closeCalls += 1;
        },
      };
      containers.push(container);
      return container;
    },
  });
  return { gateway, containers };
}

test("authentication rejects a mismatched account and invalidates the old session", async () => {
  const { gateway, containers } = makeGateway((index) =>
    index === 1 ? { readId: "different-account" } : {},
  );
  await gateway.ensureAccounts();
  const oldBalance = gateway.balance;

  await assert.rejects(
    gateway.ensureAccounts({ force: true }),
    /does not match the dedicated PAPER account/,
  );
  assert.equal(oldBalance.unlistenCalls, 1);
  assert.equal(containers[0].closeCalls, 1);
  assert.equal(containers[1].closeCalls, 1);
  assert.equal(gateway.container, undefined);
  assert.equal(gateway.walletAccount, undefined);
  assert.equal(gateway.readAccount, undefined);
  assert.equal(gateway.balance, undefined);
  assert.equal(gateway.authenticatedAtMs, undefined);
});

test("authentication fails closed for missing or disabled required instruments", async (t) => {
  for (const [name, instruments] of [
    ["missing required symbol", INSTRUMENTS.slice(1)],
    ["disabled required symbol", INSTRUMENTS.map((item, index) =>
      index === 0 ? { ...item, trading: "close-only" } : item,
    )],
  ]) {
    await t.test(name, async () => {
      const { gateway, containers } = makeGateway(() => ({ instruments }));
      await assert.rejects(gateway.ensureAccounts(), /EVEDEX DEV/);
      assert.equal(containers[0].closeCalls, 1);
      assert.equal(gateway.container, undefined);
      assert.equal(gateway.walletAccount, undefined);
      assert.equal(gateway.readAccount, undefined);
      assert.equal(gateway.balance, undefined);
    });
  }
});

test("concurrent authentication requests share one container", async () => {
  const { gateway, containers } = makeGateway();
  await Promise.all([gateway.ensureAccounts(), gateway.ensureAccounts(), gateway.ensureAccounts()]);
  assert.equal(containers.length, 1);
  assert.ok(gateway.walletAccount);
  assert.ok(gateway.readAccount);
});

test("failed reauthentication cannot reuse stale accounts and the next attempt is fresh", async () => {
  const { gateway, containers } = makeGateway((index) =>
    index === 1 ? { signingId: "wrong-account" } : {},
  );
  await gateway.ensureAccounts();
  const priorWallet = gateway.walletAccount;

  await assert.rejects(gateway.ensureAccounts({ force: true }), /dedicated PAPER account/);
  assert.notEqual(gateway.walletAccount, priorWallet);
  assert.equal(gateway.walletAccount, undefined);
  assert.equal(containers[1].closeCalls, 1);

  await gateway.ensureAccounts();
  assert.equal(containers.length, 3);
  assert.ok(gateway.walletAccount);
  assert.notEqual(gateway.walletAccount, priorWallet);
  assert.equal(containers[2].closeCalls, 0);
});

test("a failed balance listen cleans up tentative events and the new container", async () => {
  const { gateway, containers } = makeGateway(() => ({
    eventsOnListen: { ACCOUNT: { balance: 12 } },
    listen: async () => {
      throw new Error("offline listener failure");
    },
  }));
  await assert.rejects(gateway.ensureAccounts(), /offline listener failure/);
  assert.equal(containers[0].balance.unlistenCalls, 1);
  assert.equal(containers[0].closeCalls, 1);
  assert.deepEqual(gateway.events, []);
  assert.equal(gateway.container, undefined);
  assert.equal(gateway.balance, undefined);
  containers[0].balance.emit("ORDER", { stale: true });
  assert.deepEqual(gateway.events, []);
});

test("a read retries exactly once after refresh-token expiry", async () => {
  const expired = Object.assign(new Error("expired"), { name: "RefreshTokenExpiredError" });
  let firstRead = true;
  const { gateway, containers } = makeGateway((index) => ({
    openOrdersError:
      index === 0 && firstRead
        ? (firstRead = false, expired)
        : undefined,
    openOrders: [{ id: `orders-${index}` }],
  }));
  const result = await gateway.call("fetch_open_orders", {});
  assert.deepEqual(result, [{ id: "orders-1" }]);
  assert.equal(containers.length, 2);
  assert.equal(containers[0].balance.unlistenCalls, 1);
  assert.equal(containers[0].closeCalls, 1);
});

test("mutations are never retried and consume budget before failed dispatch", async () => {
  const expired = Object.assign(new Error("expired"), { name: "RefreshTokenExpiredError" });
  let remainingAtDispatch;
  const { gateway, containers } = makeGateway(() => ({
    mutationError: expired,
    onMutationDispatch(remaining) {
      remainingAtDispatch = remaining;
    },
  }));
  await assert.rejects(
    gateway.call("place_limit", {
      client_order_id: "offline-order",
      instrument: "BTCUSD:DEV",
      side: "BUY",
      leverage: 1,
      quantity: 1,
      limit_price: 100,
    }),
    (error) => error === expired,
  );
  assert.equal(remainingAtDispatch, 29);
  assert.equal(gateway.mutationBudget.remaining(), 29);
  assert.equal(containers.length, 1);
});

test("listener events are buffered, drained in order, and closed", async () => {
  const { gateway, containers } = makeGateway(() => ({
    eventsOnListen: {
      ACCOUNT: { n: 1 },
      POSITION: { n: 2 },
      ORDER: { n: 3 },
    },
  }));
  const first = await gateway.call("drain_events", { limit: 2 });
  assert.deepEqual(first.events.map(({ sequence, type }) => [sequence, type]), [
    [1, "ACCOUNT"],
    [2, "POSITION"],
  ]);
  const second = await gateway.call("drain_events", { limit: 2 });
  assert.deepEqual(second.events.map(({ sequence, type }) => [sequence, type]), [[3, "ORDER"]]);

  await gateway.close();
  assert.equal(containers[0].balance.unlistenCalls, 1);
  assert.equal(containers[0].closeCalls, 1);
});

test("live callbacks after authentication enter the event queue", async () => {
  const { gateway, containers } = makeGateway();
  await gateway.ensureAccounts();

  containers[0].balance.emit("FILL", { id: "live-fill" });
  assert.deepEqual(gateway.events, [
    { sequence: 1, type: "FILL", payload: { id: "live-fill" } },
  ]);
});

test("reauth preserves queued events and fences callbacks from the old session", async () => {
  const { gateway, containers } = makeGateway((index) =>
    index === 0
      ? { eventsOnListen: { ACCOUNT: { id: "old-account-event" } } }
      : { eventsOnListen: { POSITION: { id: "new-position-event" } } },
  );
  await gateway.ensureAccounts();
  const oldBalance = containers[0].balance;
  await gateway.ensureAccounts({ force: true });

  oldBalance.emit("FILL", { id: "stale-fill" });
  containers[1].balance.emit("ORDER", { id: "live-order" });
  assert.deepEqual(gateway.events.map(({ sequence, type, payload }) => [sequence, type, payload.id]), [
    [1, "ACCOUNT", "old-account-event"],
    [2, "POSITION", "new-position-event"],
    [3, "ORDER", "live-order"],
  ]);
});

test("tentative event overflow fails closed without a hidden event gap", async () => {
  const eventCount = 10_005;
  const { gateway, containers } = makeGateway(() => ({
    emitDuringListen(emit) {
      for (let n = 0; n < eventCount; n += 1) emit("ORDER", { n });
    },
  }));
  await assert.rejects(gateway.ensureAccounts(), /tentative event buffer exceeded/);

  assert.equal(gateway.eventSequence, 0);
  assert.deepEqual(gateway.events, []);
  assert.equal(gateway.walletAccount, undefined);
  assert.equal(containers[0].balance.unlistenCalls, 1);
  assert.equal(containers[0].closeCalls, 1);
  containers[0].balance.emit("ORDER", { n: eventCount });
  assert.deepEqual(gateway.events, []);
});

test("closing invalidates cached accounts and fences late callbacks", async () => {
  const { gateway, containers } = makeGateway();
  await gateway.ensureAccounts();
  containers[0].balance.emit("ORDER", { n: 1 });
  await gateway.close();
  containers[0].balance.emit("FILL", { n: 2 });
  assert.equal(gateway.walletAccount, undefined);
  assert.equal(gateway.readAccount, undefined);
  assert.deepEqual(gateway.events.map(({ payload }) => payload.n), [1]);
});

test("closing during pending listen prevents candidate admission", async () => {
  let releaseListen;
  const listening = new Promise((resolve) => { releaseListen = resolve; });
  let signalListen;
  const started = new Promise((resolve) => { signalListen = resolve; });
  const { gateway, containers } = makeGateway(() => ({
    listen: async () => {
      signalListen();
      await listening;
    },
  }));
  const authentication = gateway.ensureAccounts();
  const rejected = assert.rejects(authentication, /invalidated before admission/);
  await started;
  await gateway.close();
  releaseListen();
  await rejected;
  assert.equal(gateway.walletAccount, undefined);
  assert.equal(containers[0].balance.unlistenCalls, 1);
  assert.equal(containers[0].closeCalls, 1);
});

test("a second read expiry is reported without a second retry", async () => {
  const expired = Object.assign(new Error("expired twice"), { name: "RefreshTokenExpiredError" });
  const { gateway, containers } = makeGateway(() => ({ openOrdersError: expired }));
  await assert.rejects(gateway.call("fetch_open_orders", {}), (error) => error === expired);
  assert.equal(containers.length, 2);
});
