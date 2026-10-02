import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import test from "node:test";

test("the unchanged SDK resolves the exact patched Axios override", () => {
  const manifest = JSON.parse(
    readFileSync(new URL("../package.json", import.meta.url), "utf8"),
  );
  const lock = JSON.parse(
    readFileSync(new URL("../package-lock.json", import.meta.url), "utf8"),
  );
  const sdk = "@evedex/exchange-bot-sdk";
  const require = createRequire(import.meta.url);
  const sdkRequire = createRequire(require.resolve(sdk));
  assert.equal(manifest.dependencies[sdk], "1.2.11");
  assert.equal(lock.packages[`node_modules/${sdk}`].dependencies.axios, "^1.8.1");
  assert.equal(manifest.overrides[sdk].axios, "1.20.0");
  assert.equal(lock.packages["node_modules/axios"].version, "1.20.0");
  assert.match(lock.packages["node_modules/axios"].integrity, /^sha512-/);
  assert.equal(sdkRequire("axios").VERSION, "1.20.0");
});
