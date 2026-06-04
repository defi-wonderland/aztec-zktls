/**
 * OptionEscrowLogic lifecycle tests.
 *
 * Multi-contract setup: deploys 2 Token contracts (base + quote), a
 * KlinesOracle, and the OptionEscrowLogic. Then walks through one or more
 * lifecycle paths using two test accounts (alice = buyer, bob = seller).
 *
 * Prerequisites:
 *   - `aztec start --local-network` on localhost:8080
 *   - `yarn ccc` (so artifacts/{KlinesOracle,OptionEscrowLogic}.ts exist)
 *
 * Uses synthetic klines attestations (see synthetic-klines-witness.ts);
 * no real Primus call is made.
 */
import { describe, it, expect, beforeAll } from "vitest";
import { createAztecNodeClient } from "@aztec/aztec.js/node";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { getInitialTestAccountsData } from "@aztec/accounts/testing";
import type { AccountManager } from "@aztec/aztec.js/wallet";
import { Fr } from "@aztec/aztec.js/fields";
import { poseidon2Hash } from "@aztec/foundation/crypto/poseidon";

import { KlinesOracleContract } from "../artifacts/KlinesOracle.js";
import { OptionEscrowLogicContract } from "../artifacts/OptionEscrowLogic.js";
import { buildSyntheticKlinesWitness } from "./synthetic-klines-witness.js";
import {
  deployTokenWithMinter,
  getEscrowClassId,
  setPrivateAuthWit,
  randomNonce,
  randomSecretKey,
} from "./option-escrow-helpers.js";

const NODE_URL = process.env.AZTEC_NODE_URL ?? "http://localhost:8080";

const TEST_PRIVATE_KEY =
  0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefn;

const BASE_URL = "https://api.binance.com/api/v3/klines";
const SYMBOL = "ETHUSDT";
const INTERVAL = "1m";

const ROLE_BUYER = 0;
const ROLE_SELLER = 1;

// Token amounts (18 dp).
const PREMIUM_AMOUNT = 100_000000000000000000n; // 100 quote
const BASE_AMOUNT = 1_000000000000000000n; // 1 base
const QUOTE_AMOUNT = 2300_000000000000000000n; // 2300 quote — strike-equivalent

const STRIKE_8DP = 2_280_00000000n; // $2280, 8-decimal-scaled
const DEADLINE_OFFSET_S = 60n * 60n; // option exercise allowed up to 1h from `now`

const MAX_QUERY_PREFIX_LEN = 96;

const DEPLOY_TIMEOUT = 300_000;
const TX_TIMEOUT = 120_000;

/** Poseidon2 hash of the query-prefix bytes zero-padded to MAX_QUERY_PREFIX_LEN.
 *  Mirrors the in-circuit `_hash_query_prefix` so we can pin the expected
 *  hash inside `OptionTerms.pinned_query_prefix_hash` at offer time. */
async function hashQueryPrefix(prefix: string): Promise<Fr> {
  const bytes = new TextEncoder().encode(prefix);
  if (bytes.length > MAX_QUERY_PREFIX_LEN) {
    throw new Error("query_prefix too long");
  }
  const padded = new Array(MAX_QUERY_PREFIX_LEN).fill(0n);
  for (let i = 0; i < bytes.length; i++) {
    padded[i] = BigInt(bytes[i]!);
  }
  return await poseidon2Hash(padded.map((b) => new Fr(b)));
}

describe("OptionEscrowLogic", () => {
  let wallet: EmbeddedWallet;
  let alice: AccountManager;
  let bob: AccountManager;

  beforeAll(async () => {
    const node = createAztecNodeClient(NODE_URL);
    await node.getNodeInfo();
    wallet = await EmbeddedWallet.create(NODE_URL, { ephemeral: true });

    const accountsData = await getInitialTestAccountsData();
    if (accountsData.length < 2) {
      throw new Error("Need at least 2 initial test accounts");
    }
    alice = await wallet.createSchnorrAccount(
      accountsData[0]!.secret,
      accountsData[0]!.salt,
      accountsData[0]!.signingKey,
    );
    bob = await wallet.createSchnorrAccount(
      accountsData[1]!.secret,
      accountsData[1]!.salt,
      accountsData[1]!.signingKey,
    );
  }, 120_000);

  it("happy path: call option offered by buyer, subscribed by seller, exercised in the money", async () => {
    // ─── Setup contracts ──────────────────────────────────────────────
    const baseToken = await deployTokenWithMinter(
      wallet,
      alice.address,
      "BaseTok",
      "B",
    );
    const quoteToken = await deployTokenWithMinter(
      wallet,
      alice.address,
      "QuoteTok",
      "Q",
    );

    // Mint buyer's premium (quote_token) and seller's collateral (base_token).
    // The deployer (alice) is the minter for both; mint to the right party.
    await baseToken.methods
      .mint_to_private(bob.address, BASE_AMOUNT)
      .send({ from: alice.address, wait: { timeout: TX_TIMEOUT } });
    await quoteToken.methods
      .mint_to_private(alice.address, PREMIUM_AMOUNT)
      .send({ from: alice.address, wait: { timeout: TX_TIMEOUT } });

    const synthetic = buildSyntheticKlinesWitness({
      privateKey: TEST_PRIVATE_KEY,
      recipient: "0x70a0DA282002021ff34A8AFe7749179A3066F749",
      baseUrl: BASE_URL,
      symbol: SYMBOL,
      interval: INTERVAL,
      startTime: 1n,
      endTime: 1n + 60_000n - 1n,
      candle: {
        // ITM-for-call midpoint: (2300+2300)/2 = 2300 >= strike 2280
        openTime: 1n,
        open: "2300.00000000",
        high: "2310.00000000",
        low: "2290.00000000",
        close: "2300.00000000",
        closeTime: 1n + 60_000n - 1n,
      },
      envelopeTimestamp: 60_000n,
    });

    const oracle = (
      await KlinesOracleContract.deploy(
        wallet,
        { x: synthetic.publicKeyX, y: synthetic.publicKeyY },
        synthetic.baseUrlPrefix,
      ).send({ from: alice.address, wait: { timeout: DEPLOY_TIMEOUT } })
    ).contract;

    const escrowClassId = await getEscrowClassId();

    const escrowLogic = (
      await OptionEscrowLogicContract.deploy(
        wallet,
        escrowClassId,
        oracle.address,
      ).send({ from: alice.address, wait: { timeout: DEPLOY_TIMEOUT } })
    ).contract;

    // ─── Build option terms ───────────────────────────────────────────
    // Use a far-future deadline so american exercise window passes.
    const nowMs = BigInt(Date.now());
    const deadline = nowMs / 1000n + DEADLINE_OFFSET_S;
    const queryPrefix = `?symbol=${SYMBOL}&interval=${INTERVAL}&`;
    const pinnedQueryPrefixHash = await hashQueryPrefix(queryPrefix);

    const terms = {
      deadline,
      base_token: baseToken.address,
      base_amount: BASE_AMOUNT,
      quote_token: quoteToken.address,
      quote_amount: QUOTE_AMOUNT,
      premium_amount: PREMIUM_AMOUNT,
      strike: STRIKE_8DP,
      is_call: true,
      is_american: true,
      pinned_query_prefix_hash: pinnedQueryPrefixHash.toBigInt(),
    };

    // ─── Alice (buyer) offers ─────────────────────────────────────────
    const secretKey = randomSecretKey();
    const offerNonce = randomNonce();

    // Authwit so the escrow logic can pull alice's premium into the escrow.
    const offerDepositAction = quoteToken.methods.transfer_private_to_private(
      alice.address,
      // The escrow address — we can pre-compute by simulating get_escrow,
      // but `_get_escrow` derives it from class_id + secret_key on the fly.
      // For now grab it via a view call.
      (
        await escrowLogic.methods
          .get_escrow(secretKey)
          .simulate({ from: alice.address })
      ).result as never,
      PREMIUM_AMOUNT,
      offerNonce,
    );
    await setPrivateAuthWit(
      escrowLogic.address,
      offerDepositAction,
      alice.address,
      wallet,
    );

    await escrowLogic.methods
      .offer(ROLE_BUYER, bob.address, terms, secretKey, offerNonce)
      .send({ from: alice.address, wait: { timeout: TX_TIMEOUT } });

    // ─── Bob (seller) subscribes ──────────────────────────────────────
    const escrowAddress = (
      await escrowLogic.methods
        .get_escrow(secretKey)
        .simulate({ from: bob.address })
    ).result as never;
    const subscribeNonce = randomNonce();

    const subscribeDepositAction =
      baseToken.methods.transfer_private_to_private(
        bob.address,
        escrowAddress,
        BASE_AMOUNT,
        subscribeNonce,
      );
    await setPrivateAuthWit(
      escrowLogic.address,
      subscribeDepositAction,
      bob.address,
      wallet,
    );

    await escrowLogic.methods
      .subscribe(escrowAddress, subscribeNonce)
      .send({ from: bob.address, wait: { timeout: TX_TIMEOUT } });

    // ─── Alice exercises (in the money) ───────────────────────────────
    const settlementNonce = randomNonce();
    const settlementAction = quoteToken.methods.transfer_private_to_private(
      alice.address,
      bob.address,
      QUOTE_AMOUNT,
      settlementNonce,
    );
    await setPrivateAuthWit(
      escrowLogic.address,
      settlementAction,
      alice.address,
      wallet,
    );

    await escrowLogic.methods
      .exercise(
        escrowAddress,
        synthetic.signature,
        synthetic.envelope,
        synthetic.contents,
        synthetic.dataHashOffsets,
        synthetic.queryPrefix,
        settlementNonce,
      )
      .send({ from: alice.address, wait: { timeout: TX_TIMEOUT } });

    // ─── Verify final balances ────────────────────────────────────────
    // Alice (buyer, call) ended up with: -PREMIUM_AMOUNT (spent), +BASE_AMOUNT (received), -QUOTE_AMOUNT (settled)
    // Bob   (seller, call) ended up with: -BASE_AMOUNT (collateral, now alice's), +PREMIUM_AMOUNT (received), +QUOTE_AMOUNT (settled)
    const aliceBase = (
      await baseToken.methods
        .balance_of_private(alice.address)
        .simulate({ from: alice.address })
    ).result as bigint;
    const aliceQuote = (
      await quoteToken.methods
        .balance_of_private(alice.address)
        .simulate({ from: alice.address })
    ).result as bigint;
    const bobBase = (
      await baseToken.methods
        .balance_of_private(bob.address)
        .simulate({ from: bob.address })
    ).result as bigint;
    const bobQuote = (
      await quoteToken.methods
        .balance_of_private(bob.address)
        .simulate({ from: bob.address })
    ).result as bigint;

    expect(aliceBase).toBe(BASE_AMOUNT); // received base on exercise
    expect(aliceQuote).toBe(0n); // paid premium + settlement
    expect(bobBase).toBe(0n); // posted collateral
    expect(bobQuote).toBe(PREMIUM_AMOUNT + QUOTE_AMOUNT);
  }, 600_000);
});
