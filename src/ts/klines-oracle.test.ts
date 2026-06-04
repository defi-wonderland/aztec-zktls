import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createAztecNodeClient } from "@aztec/aztec.js/node";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { getInitialTestAccountsData } from "@aztec/accounts/testing";
import type { AccountManager } from "@aztec/aztec.js/wallet";

import { KlinesOracleContract } from "../artifacts/KlinesOracle.js";
import {
  buildSyntheticKlinesWitness,
  priceTo8dpU64,
} from "./synthetic-klines-witness.js";

const NODE_URL = process.env.AZTEC_NODE_URL ?? "http://localhost:8080";

// Deterministic test signing key — ephemeral, only used for these tests.
const TEST_PRIVATE_KEY =
  0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefn;

const TEST_INPUTS = {
  privateKey: TEST_PRIVATE_KEY,
  recipient: "0x70a0DA282002021ff34A8AFe7749179A3066F749",
  baseUrl: "https://api.binance.com/api/v3/klines",
  symbol: "ETHUSDT",
  interval: "1m",
  startTime: 1704067200000n,
  endTime: 1704067259999n,
  candle: {
    openTime: 1704067200000n,
    open: "2281.87000000",
    high: "2284.60000000",
    low: "2281.27000000",
    close: "2284.39000000",
    closeTime: 1704067259999n,
  },
  envelopeTimestamp: 1704067260000n,
};

const DEPLOY_TIMEOUT = 300_000;

describe("KlinesOracle", () => {
  let wallet: EmbeddedWallet;
  let account: AccountManager;

  beforeAll(async () => {
    const node = createAztecNodeClient(NODE_URL);
    await node.getNodeInfo();
    wallet = await EmbeddedWallet.create(NODE_URL, { ephemeral: true });
    const [first] = await getInitialTestAccountsData();
    if (!first) {
      throw new Error("No initial test accounts on the local network");
    }
    account = await wallet.createSchnorrAccount(
      first.secret,
      first.salt,
      first.signingKey,
    );
  }, 120_000);

  it("verifies a synthetic klines attestation and returns the parsed candle", async () => {
    const w = buildSyntheticKlinesWitness(TEST_INPUTS);

    const { contract } = await KlinesOracleContract.deploy(
      wallet,
      { x: w.publicKeyX, y: w.publicKeyY },
      w.baseUrlPrefix,
    ).send({
      from: account.address,
      wait: { timeout: DEPLOY_TIMEOUT },
    });

    const sim = await contract.methods
      .verify_klines_attestation(
        w.signature,
        w.envelope,
        w.contents,
        w.dataHashOffsets,
        w.queryPrefix,
      )
      .simulate({ from: account.address });

    const candle = sim.result as {
      open_time: bigint;
      open_price: bigint;
      high_price: bigint;
      low_price: bigint;
      close_price: bigint;
      close_time: bigint;
    };

    expect(candle.open_time).toBe(TEST_INPUTS.candle.openTime);
    expect(candle.close_time).toBe(TEST_INPUTS.candle.closeTime);
    expect(candle.open_price).toBe(priceTo8dpU64(TEST_INPUTS.candle.open));
    expect(candle.high_price).toBe(priceTo8dpU64(TEST_INPUTS.candle.high));
    expect(candle.low_price).toBe(priceTo8dpU64(TEST_INPUTS.candle.low));
    expect(candle.close_price).toBe(priceTo8dpU64(TEST_INPUTS.candle.close));
  }, 600_000);

  it("rejects when signature is from a different attestor", async () => {
    // Deploy with the canonical attestor's pubkey, then submit a witness
    // signed by a DIFFERENT key. The ECDSA check inside the lib should fail.
    const correct = buildSyntheticKlinesWitness(TEST_INPUTS);
    const impostor = buildSyntheticKlinesWitness({
      ...TEST_INPUTS,
      privateKey:
        0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefn,
    });

    const { contract } = await KlinesOracleContract.deploy(
      wallet,
      { x: correct.publicKeyX, y: correct.publicKeyY },
      correct.baseUrlPrefix,
    ).send({
      from: account.address,
      wait: { timeout: DEPLOY_TIMEOUT },
    });

    await expect(
      contract.methods
        .verify_klines_attestation(
          impostor.signature, // wrong key signed this
          impostor.envelope,
          impostor.contents,
          impostor.dataHashOffsets,
          impostor.queryPrefix,
        )
        .simulate({ from: account.address }),
    ).rejects.toThrow(/ECDSA verification failed/);
  }, 600_000);

  it("rejects when request URL doesn't start with the pinned base prefix", async () => {
    // Deploy with one base URL, then submit a witness for a different one.
    const correct = buildSyntheticKlinesWitness(TEST_INPUTS);
    const wrongBase = buildSyntheticKlinesWitness({
      ...TEST_INPUTS,
      baseUrl: "https://api.example.com/wrong/path",
    });

    const { contract } = await KlinesOracleContract.deploy(
      wallet,
      { x: correct.publicKeyX, y: correct.publicKeyY },
      correct.baseUrlPrefix,
    ).send({
      from: account.address,
      wait: { timeout: DEPLOY_TIMEOUT },
    });

    await expect(
      contract.methods
        .verify_klines_attestation(
          wrongBase.signature,
          wrongBase.envelope,
          wrongBase.contents,
          wrongBase.dataHashOffsets,
          wrongBase.queryPrefix,
        )
        .simulate({ from: account.address }),
    ).rejects.toThrow(/base prefix mismatch/);
  }, 600_000);

  afterAll(async () => {
    // Tear down (no global resources to clean up explicitly).
  });
});
