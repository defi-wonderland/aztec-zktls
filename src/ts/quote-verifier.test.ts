import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createAztecNodeClient } from "@aztec/aztec.js/node";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { Barretenberg } from "@aztec/bb.js";
import { getInitialTestAccountsData } from "@aztec/accounts/testing";
import type { AccountManager } from "@aztec/aztec.js/wallet";
import path from "node:path";
import {
  NODE_URL,
  findLatestWitness,
  loadWitness,
  deployAndVerify,
  fetchQuoteVerifiedEvents,
} from "./utils.js";

// Default: load the committed fixture so this suite is fully offline.
// Override with WITNESS_FILE (full path) or WITNESS_PROVIDER (e.g. "binance-")
// to load from attestations/ instead.
const FIXTURE_PATH = path.resolve(__dirname, "fixtures/binance-ETHUSDT.witness.json");
const WITNESS_FILE = process.env.WITNESS_FILE;
const WITNESS_PROVIDER = process.env.WITNESS_PROVIDER;

describe("QuoteVerifier (cached witness)", () => {
  let wallet: EmbeddedWallet;
  let bb: Barretenberg;
  let account: AccountManager;

  beforeAll(async () => {
    const node = createAztecNodeClient(NODE_URL);
    await node.getNodeInfo();

    wallet = await EmbeddedWallet.create(NODE_URL, { ephemeral: true });
    bb = await Barretenberg.new();

    const [first] = await getInitialTestAccountsData();
    if (!first) throw new Error("No initial test accounts on the local network");
    account = await wallet.createSchnorrAccount(first.secret, first.salt);
  }, 120_000);

  afterAll(async () => {
    await bb?.destroy();
  });

  it("deploys, verifies, and emits QuoteVerified", async () => {
    const witnessPath = WITNESS_FILE
      ?? (WITNESS_PROVIDER ? findLatestWitness(WITNESS_PROVIDER) : FIXTURE_PATH);
    console.log(`[test] witness: ${witnessPath}`);
    const w = loadWitness(witnessPath);

    const { contract, receipt } = await deployAndVerify(wallet, bb, account, w);

    console.log(`[test] tx status: ${receipt.status}, block: ${receipt.blockNumber}`);
    // Aztec 4.2.0 progresses tx state through "pending" -> "proposed" ->
    // "proven" -> "checkpointed". Any of the last three means the tx made it
    // onto a block proposal and the contract's verification logic executed
    // successfully. A revert would have thrown before reaching this point.
    expect(["proposed", "proven", "checkpointed"]).toContain(receipt.status);
    expect(receipt.blockNumber).toBeGreaterThan(0);

    const events = await fetchQuoteVerifiedEvents(contract, receipt.txHash);
    console.log(`[test] QuoteVerified events emitted: ${events.length}`);
    expect(events.length).toBeGreaterThan(0);
    expect(events[0]!.event.provider_url_hash).toBeTypeOf("bigint");
  }, 600_000);
});
