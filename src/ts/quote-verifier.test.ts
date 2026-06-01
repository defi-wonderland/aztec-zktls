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
  readQuoteAt,
} from "./utils.js";

// Default: load the committed fixture so this suite is fully offline.
// Override with WITNESS_FILE (full path) or WITNESS_PROVIDER (e.g. "binance-")
// to load from attestations/ instead.
const FIXTURE_PATH = path.resolve(
  import.meta.dirname,
  "fixtures/binance-ETHUSDT.witness.json",
);
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
    if (!first)
      throw new Error("No initial test accounts on the local network");
    account = await wallet.createSchnorrAccount(first.secret, first.salt);
  }, 120_000);

  afterAll(async () => {
    await bb?.destroy();
  });

  it("deploys, verifies, and records the quote", async () => {
    const witnessPath =
      WITNESS_FILE ??
      (WITNESS_PROVIDER ? findLatestWitness(WITNESS_PROVIDER) : FIXTURE_PATH);
    console.log(`[test] witness: ${witnessPath}`);
    const w = loadWitness(witnessPath);

    const { contract, receipt } = await deployAndVerify(wallet, bb, account, w);

    console.log(
      `[test] tx status: ${receipt.status}, block: ${receipt.blockNumber}`,
    );
    // Aztec progresses tx state through "pending" -> "proposed" ->
    // "proven" -> "checkpointed". Any of the last three means the tx made it
    // onto a block proposal and the contract's verification logic executed
    // successfully. A revert would have thrown before reaching this point.
    expect(["proposed", "proven", "checkpointed"]).toContain(receipt.status);
    expect(receipt.blockNumber).toBeGreaterThan(0);

    // The witness carries `envelope.timestamp` as the attestor-signed unix
    // timestamp; the contract records it alongside the normalized price.
    // historical_quotes[timestamp] is readable immediately after verify().
    const expectedTimestamp = BigInt(w.timestamp);
    const quote = await readQuoteAt(contract, account, expectedTimestamp);
    console.log(
      `[test] historical_quote @${expectedTimestamp}: price=${quote.price}`,
    );
    expect(quote.price).toBeGreaterThan(0n);
    expect(quote.timestamp).toBe(expectedTimestamp);
  }, 600_000);
});
