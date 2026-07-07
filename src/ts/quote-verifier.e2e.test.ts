import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { createAztecNodeClient } from "@aztec/aztec.js/node";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { Barretenberg } from "@aztec/bb.js";
import { getInitialTestAccountsData } from "@aztec/accounts/testing";
import type { AccountManager } from "@aztec/aztec.js/wallet";
import {
  NODE_URL,
  findLatestWitness,
  loadWitness,
  deployAndVerify,
  readQuoteAt,
  fetchQuoteRecordedEvents,
} from "./utils.js";

// Live end-to-end: spawn `yarn attest` against Primus DVC (real network call,
// costs Base Sepolia gas), then verify the fresh witness on Aztec.
//
// Two cases, each picking a (provider, mode) pair we've empirically confirmed
// the attestor accepts:
//   - Binance + mpctls   (private MPC-TLS handshake)
//   - Coinbase + proxytls (attestor as TLS proxy)
// Primus's attestor refuses some (provider, mode) combinations - notably
// proxytls against Binance and mpctls against OKX. Both envelopes are
// verified identically by the same QuoteVerifier contract.
//
// Gated by RUN_E2E=1 so the default `yarn test` stays cheap and offline.
// Requires:
//   - .env with a funded PRIVATE_KEY (Base Sepolia)
//   - `aztec start --local-network` running on localhost:8080
const RUN_E2E = process.env.RUN_E2E === "1";

const REPO_ROOT = path.resolve(import.meta.dirname, "../../");

type AttMode = "mpctls" | "proxytls";

type E2ECase = {
  label: string;
  provider: string;
  symbol: string;
  mode: AttMode;
};

const CASES: E2ECase[] = [
  {
    label: "binance + mpctls",
    provider: "binance",
    symbol: "ETHUSDT",
    mode: "mpctls",
  },
  {
    label: "coinbase + proxytls",
    provider: "coinbase",
    symbol: "ETH-USD",
    mode: "proxytls",
  },
];

describe("QuoteVerifier E2E (live Primus attestation)", () => {
  let wallet: EmbeddedWallet;
  let bb: Barretenberg;
  let account: AccountManager;

  beforeAll(async () => {
    if (!RUN_E2E) return;

    // Sanity: PRIVATE_KEY must be in .env or the attest subprocess errors out.
    const envPath = path.join(REPO_ROOT, ".env");
    if (
      !fs.existsSync(envPath) ||
      !/^PRIVATE_KEY=\S+/m.test(fs.readFileSync(envPath, "utf8"))
    ) {
      throw new Error(`E2E test needs PRIVATE_KEY in ${envPath}`);
    }

    const node = createAztecNodeClient(NODE_URL);
    await node.getNodeInfo();

    wallet = await EmbeddedWallet.create(NODE_URL, { ephemeral: true });
    bb = await Barretenberg.new();

    const [first] = await getInitialTestAccountsData();
    if (!first)
      throw new Error("No initial test accounts on the local network");
    account = await wallet.createSchnorrAccount(
      first.secret,
      first.salt,
      first.signingKey,
    );
  }, 120_000);

  afterAll(async () => {
    await bb?.destroy();
  });

  async function runE2E(c: E2ECase): Promise<void> {
    const tag = `[e2e ${c.label}]`;
    console.log(
      `${tag} requesting fresh ${c.provider}/${c.symbol} attestation from Primus...`,
    );
    const attest = spawnSync(
      "yarn",
      ["attest", c.provider, `symbol=${c.symbol}`, `mode=${c.mode}`],
      { cwd: REPO_ROOT, stdio: "inherit" },
    );
    if (attest.status !== 0) {
      throw new Error(
        `yarn attest ${c.provider} symbol=${c.symbol} mode=${c.mode} failed (exit ${attest.status})`,
      );
    }

    const witnessPath = findLatestWitness(`${c.provider}-`);
    console.log(`${tag} fresh witness: ${witnessPath}`);
    const w = loadWitness(witnessPath);

    const { contract, receipt } = await deployAndVerify(wallet, bb, account, w);
    console.log(
      `${tag} tx status: ${receipt.status}, block: ${receipt.blockNumber}`,
    );
    expect(["proposed", "proven", "checkpointed"]).toContain(receipt.status);
    expect(receipt.blockNumber).toBeGreaterThan(0);

    const expectedTimestamp = BigInt(w.timestamp);
    const quote = await readQuoteAt(contract, account, expectedTimestamp);
    console.log(
      `${tag} historical_quote @${expectedTimestamp}: price=${quote.price}`,
    );
    expect(quote.price).toBeGreaterThan(0n);
    expect(quote.timestamp).toBe(expectedTimestamp);

    const events = await fetchQuoteRecordedEvents(contract, receipt.txHash);
    console.log(`${tag} QuoteRecorded events: ${events.length}`);
    expect(events.length).toBe(1);
    expect(events[0]!.event.price).toBe(quote.price);
    expect(events[0]!.event.timestamp).toBe(expectedTimestamp);
  }

  for (const c of CASES) {
    it.skipIf(!RUN_E2E)(
      `${c.label}: fetches fresh attestation, deploys, verifies, records quote`,
      async () => {
        await runE2E(c);
      },
      600_000,
    );
  }
});
