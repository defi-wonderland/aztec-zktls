/**
 * OptionEscrowLogic lifecycle tests.
 *
 * Walks the call/put happy paths, cancel + reclaim, and a handful of negative
 * cases. Uses synthetic Primus klines attestations (see synthetic-klines-witness.ts);
 * no real Primus call is made. Chain time is controlled via `chain-time.ts`
 * (EthCheatCodes + nodeDebug.mineBlock).
 *
 * Prerequisites:
 *   - `aztec start --local-network` on localhost:8080 (exposes nodeDebug)
 *   - `yarn ccc` (artifacts/{KlinesOracle,OptionEscrowLogic}.ts present)
 */
import { describe, it, expect, beforeAll } from "vitest";
import { createAztecNodeClient } from "@aztec/aztec.js/node";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { getInitialTestAccountsData } from "@aztec/accounts/testing";
import type { AccountManager } from "@aztec/aztec.js/wallet";
import { AztecAddress } from "@aztec/aztec.js/addresses";

import {
  buildSyntheticKlinesWitness,
  type KlinesWitness,
  type KlinesCandlePlaintexts,
} from "./synthetic-klines-witness.js";
import {
  deployOptionEscrowStack,
  setPrivateAuthWit,
  randomNonce,
  randomSecretKey,
  syncPXE,
  deployAndRegisterEscrowFor,
  hashQueryPrefix,
  KLINES_BASE_URL,
  KLINES_SYMBOL,
  KLINES_INTERVAL,
  TEST_ATTESTATION_RECIPIENT,
  TEST_ATTESTOR_PRIVATE_KEY,
  type OptionStack,
} from "./option-escrow-helpers.js";
import { createChainTime, type ChainTime } from "./chain-time.js";

const NODE_URL = process.env.AZTEC_NODE_URL ?? "http://localhost:8080";

const ROLE_BUYER = 0;
const ROLE_SELLER = 1;

// Token amounts (18 dp).
const PREMIUM_AMOUNT = 100_000000000000000000n; // 100 quote
const BASE_AMOUNT = 1_000000000000000000n; // 1 base
const QUOTE_AMOUNT = 2300_000000000000000000n; // 2300 quote — strike-equivalent

const STRIKE_8DP = 2_280_00000000n; // $2280, 8-decimal-scaled
const DEADLINE_OFFSET_S = 60n * 60n; // 1h
// LATE_EXERCISE_GRACE_S in the contract is 24h.
const EUROPEAN_GRACE_S = 24n * 60n * 60n;

const TX_TIMEOUT = 120_000;
const TEST_TIMEOUT = 600_000;

const QUERY_PREFIX = `?symbol=${KLINES_SYMBOL}&interval=${KLINES_INTERVAL}&`;

/** Build a fresh "live" candle witness anchored to `candleOpenSec`. The
 *  caller is responsible for ensuring `block.timestamp` is inside the
 *  contract's recency window `[candleOpenSec + 60, candleOpenSec + 600]`
 *  for american exercise, or the corresponding european window. */
function buildCandleWitness(opts: {
  candleOpenSec: bigint;
  candle: KlinesCandlePlaintexts;
  baseUrl?: string;
  symbol?: string;
  interval?: string;
}): KlinesWitness {
  const candleOpenMs = opts.candleOpenSec * 1000n;
  const candleCloseMs = candleOpenMs + 60_000n - 1n;
  return buildSyntheticKlinesWitness({
    privateKey: TEST_ATTESTOR_PRIVATE_KEY,
    recipient: TEST_ATTESTATION_RECIPIENT,
    baseUrl: opts.baseUrl ?? KLINES_BASE_URL,
    symbol: opts.symbol ?? KLINES_SYMBOL,
    interval: opts.interval ?? KLINES_INTERVAL,
    startTime: candleOpenMs,
    endTime: candleCloseMs,
    candle: {
      ...opts.candle,
      openTime: candleOpenMs,
      closeTime: candleCloseMs,
    },
    envelopeTimestamp: candleCloseMs + 1n,
  });
}

type OfferRole = typeof ROLE_BUYER | typeof ROLE_SELLER;

type Scenario = {
  stack: OptionStack;
  escrowAddress: AztecAddress;
  secretKey: ReturnType<typeof randomSecretKey>;
  terms: {
    deadline: bigint;
    base_token: AztecAddress;
    base_amount: bigint;
    quote_token: AztecAddress;
    quote_amount: bigint;
    premium_amount: bigint;
    strike: bigint;
    is_call: boolean;
    is_american: boolean;
    pinned_query_prefix_hash: bigint;
  };
};

async function prepareScenario(opts: {
  wallet: EmbeddedWallet;
  node: ReturnType<typeof createAztecNodeClient>;
  chainTime: ChainTime;
  deployer: AccountManager;
  isCall: boolean;
  isAmerican: boolean;
  deadline: bigint;
}): Promise<Scenario> {
  const stack = await deployOptionEscrowStack(
    opts.wallet,
    opts.deployer.address,
    opts.chainTime,
  );

  const pinnedQueryPrefixHash = await hashQueryPrefix(QUERY_PREFIX);
  const secretKey = randomSecretKey();
  const escrow = await deployAndRegisterEscrowFor(
    opts.wallet,
    opts.node,
    stack.escrowLogic.address,
    opts.deployer.address,
    secretKey,
    opts.chainTime,
  );

  // Sanity-check: contract-derived address matches our pre-deployed one.
  const derived = (
    await stack.escrowLogic.methods
      .get_escrow(secretKey)
      .simulate({ from: opts.deployer.address })
  ).result as AztecAddress;
  if (!derived.equals(escrow.address)) {
    throw new Error(
      `escrow address mismatch: derived=${derived.toString()} predeployed=${escrow.address.toString()}`,
    );
  }

  return {
    stack,
    escrowAddress: escrow.address,
    secretKey,
    terms: {
      deadline: opts.deadline,
      base_token: stack.baseToken.address,
      base_amount: BASE_AMOUNT,
      quote_token: stack.quoteToken.address,
      quote_amount: QUOTE_AMOUNT,
      premium_amount: PREMIUM_AMOUNT,
      strike: STRIKE_8DP,
      is_call: opts.isCall,
      is_american: opts.isAmerican,
      pinned_query_prefix_hash: pinnedQueryPrefixHash.toBigInt(),
    },
  };
}

/** Call `offer` from `proposer`, doing the authwit dance for the proposer's
 *  deposit transfer first. */
async function doOffer(opts: {
  wallet: EmbeddedWallet;
  scenario: Scenario;
  chainTime: ChainTime;
  proposer: AccountManager;
  counterparty: AccountManager;
  proposerRole: OfferRole;
}): Promise<void> {
  const { stack, terms, secretKey, escrowAddress } = opts.scenario;
  const offerNonce = randomNonce();

  // Determine which token + amount the proposer deposits at offer time.
  let depositToken;
  let depositAmount: bigint;
  if (opts.proposerRole === ROLE_BUYER) {
    depositToken = stack.quoteToken;
    depositAmount = terms.premium_amount;
  } else if (terms.is_call) {
    depositToken = stack.baseToken;
    depositAmount = terms.base_amount;
  } else {
    depositToken = stack.quoteToken;
    depositAmount = terms.quote_amount;
  }

  const action = depositToken.methods.transfer_private_to_private(
    opts.proposer.address,
    escrowAddress,
    depositAmount,
    offerNonce,
  );
  await setPrivateAuthWit(
    stack.escrowLogic.address,
    action,
    opts.proposer.address,
    opts.wallet,
  );

  await opts.chainTime.withMine(
    stack.escrowLogic.methods
      .offer(
        opts.proposerRole,
        opts.counterparty.address,
        terms,
        secretKey,
        offerNonce,
      )
      .send({
        from: opts.proposer.address,
        additionalScopes: [escrowAddress],
        wait: { timeout: TX_TIMEOUT },
      }),
  );

  await syncPXE(opts.wallet);
}

async function doSubscribe(opts: {
  wallet: EmbeddedWallet;
  scenario: Scenario;
  chainTime: ChainTime;
  subscriber: AccountManager;
  subscriberRole: OfferRole;
}): Promise<void> {
  const { stack, terms, escrowAddress } = opts.scenario;
  const subscribeNonce = randomNonce();

  let depositToken;
  let depositAmount: bigint;
  if (opts.subscriberRole === ROLE_BUYER) {
    depositToken = stack.quoteToken;
    depositAmount = terms.premium_amount;
  } else if (terms.is_call) {
    depositToken = stack.baseToken;
    depositAmount = terms.base_amount;
  } else {
    depositToken = stack.quoteToken;
    depositAmount = terms.quote_amount;
  }

  const action = depositToken.methods.transfer_private_to_private(
    opts.subscriber.address,
    escrowAddress,
    depositAmount,
    subscribeNonce,
  );
  await setPrivateAuthWit(
    stack.escrowLogic.address,
    action,
    opts.subscriber.address,
    opts.wallet,
  );

  await opts.chainTime.withMine(
    stack.escrowLogic.methods.subscribe(escrowAddress, subscribeNonce).send({
      from: opts.subscriber.address,
      additionalScopes: [escrowAddress],
      wait: { timeout: TX_TIMEOUT },
    }),
  );

  await syncPXE(opts.wallet);
}

/** Authwit + send `exercise`. The caller already produced the candle witness. */
async function doExercise(opts: {
  wallet: EmbeddedWallet;
  scenario: Scenario;
  chainTime: ChainTime;
  buyer: AccountManager;
  seller: AccountManager;
  witness: KlinesWitness;
}): Promise<void> {
  const { stack, terms, escrowAddress } = opts.scenario;
  const settlementNonce = randomNonce();

  // Settlement movement direction depends on call vs put.
  const settlementToken = terms.is_call ? stack.quoteToken : stack.baseToken;
  const settlementAmount = terms.is_call
    ? terms.quote_amount
    : terms.base_amount;

  const action = settlementToken.methods.transfer_private_to_private(
    opts.buyer.address,
    opts.seller.address,
    settlementAmount,
    settlementNonce,
  );
  await setPrivateAuthWit(
    stack.escrowLogic.address,
    action,
    opts.buyer.address,
    opts.wallet,
  );

  await opts.chainTime.withMine(
    stack.escrowLogic.methods
      .exercise(
        escrowAddress,
        opts.witness.signature,
        opts.witness.envelope,
        opts.witness.contents,
        opts.witness.dataHashOffsets,
        opts.witness.queryPrefix,
        settlementNonce,
      )
      .send({
        from: opts.buyer.address,
        additionalScopes: [escrowAddress],
        wait: { timeout: TX_TIMEOUT },
      }),
  );
}

/** Warp L2 chain time so block.timestamp is at least `targetSec`. */
async function warpTo(
  chainTime: ChainTime,
  targetSec: bigint,
): Promise<bigint> {
  const l1 = await chainTime.currentL1TimestampSec();
  const target = targetSec > l1 ? targetSec : l1 + 1n;
  await chainTime.warpL2TimeAtLeastTo(target);
  return chainTime.currentL2TimestampSec();
}

async function balances(opts: {
  scenario: Scenario;
  who: AccountManager;
}): Promise<{ base: bigint; quote: bigint }> {
  const { stack } = opts.scenario;
  const base = (
    await stack.baseToken.methods
      .balance_of_private(opts.who.address)
      .simulate({ from: opts.who.address })
  ).result as bigint;
  const quote = (
    await stack.quoteToken.methods
      .balance_of_private(opts.who.address)
      .simulate({ from: opts.who.address })
  ).result as bigint;
  return { base, quote };
}

async function mint(
  token: OptionStack["baseToken"],
  to: AztecAddress,
  amount: bigint,
  from: AztecAddress,
  chainTime: ChainTime,
): Promise<void> {
  await chainTime.withMine(
    token.methods
      .mint_to_private(to, amount)
      .send({ from, wait: { timeout: TX_TIMEOUT } }),
  );
}

describe("OptionEscrowLogic", () => {
  let wallet: EmbeddedWallet;
  let alice: AccountManager; // buyer in most scenarios; deployer
  let bob: AccountManager; // seller in most scenarios
  let node: ReturnType<typeof createAztecNodeClient>;
  let chainTime: ChainTime;

  beforeAll(async () => {
    node = createAztecNodeClient(NODE_URL);
    await node.getNodeInfo();
    chainTime = await createChainTime(node, { nodeUrl: NODE_URL });
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

  // ─── Happy paths ───────────────────────────────────────────────────

  it(
    "call: alice (buyer) offers, bob (seller) subscribes, alice exercises ITM",
    async () => {
      const deadline =
        (await chainTime.currentL1TimestampSec()) + DEADLINE_OFFSET_S;
      const scenario = await prepareScenario({
        chainTime,
        wallet,
        node,
        deployer: alice,
        isCall: true,
        isAmerican: true,
        deadline,
      });

      // Alice needs premium + settlement; Bob needs base collateral.
      await mint(
        scenario.stack.quoteToken,
        alice.address,
        PREMIUM_AMOUNT + QUOTE_AMOUNT,
        alice.address,
        chainTime,
      );
      await mint(
        scenario.stack.baseToken,
        bob.address,
        BASE_AMOUNT,
        alice.address,
        chainTime,
      );

      await doOffer({
        chainTime,
        wallet,
        scenario,
        proposer: alice,
        counterparty: bob,
        proposerRole: ROLE_BUYER,
      });
      await doSubscribe({
        chainTime,
        wallet,
        scenario,
        subscriber: bob,
        subscriberRole: ROLE_SELLER,
      });

      // Warp into the recency window and build the witness.
      const exerciseL2 = await warpTo(
        chainTime,
        (await chainTime.currentL1TimestampSec()) + 1n,
      );
      const witness = buildCandleWitness({
        candleOpenSec: exerciseL2 - 120n,
        candle: {
          openTime: 0n,
          open: "2300.00000000",
          high: "2310.00000000",
          low: "2290.00000000",
          close: "2300.00000000",
          closeTime: 0n,
        },
      });

      await doExercise({
        wallet,
        scenario,
        chainTime,
        buyer: alice,
        seller: bob,
        witness,
      });

      const a = await balances({ scenario, who: alice });
      const b = await balances({ scenario, who: bob });
      expect(a.base).toBe(BASE_AMOUNT);
      expect(a.quote).toBe(0n);
      expect(b.base).toBe(0n);
      expect(b.quote).toBe(PREMIUM_AMOUNT + QUOTE_AMOUNT);
    },
    TEST_TIMEOUT,
  );

  it(
    "put: alice (buyer) offers, bob (seller) subscribes, alice exercises ITM",
    async () => {
      const deadline =
        (await chainTime.currentL1TimestampSec()) + DEADLINE_OFFSET_S;
      const scenario = await prepareScenario({
        chainTime,
        wallet,
        node,
        deployer: alice,
        isCall: false,
        isAmerican: true,
        deadline,
      });

      // Put: buyer holds the right to SELL base at strike.
      // Alice (buyer) needs premium (quote) + base for settlement.
      // Bob (seller) needs quote_amount as collateral.
      await mint(
        scenario.stack.quoteToken,
        alice.address,
        PREMIUM_AMOUNT,
        alice.address,
        chainTime,
      );
      await mint(
        scenario.stack.baseToken,
        alice.address,
        BASE_AMOUNT,
        alice.address,
        chainTime,
      );
      await mint(
        scenario.stack.quoteToken,
        bob.address,
        QUOTE_AMOUNT,
        alice.address,
        chainTime,
      );

      await doOffer({
        chainTime,
        wallet,
        scenario,
        proposer: alice,
        counterparty: bob,
        proposerRole: ROLE_BUYER,
      });
      await doSubscribe({
        chainTime,
        wallet,
        scenario,
        subscriber: bob,
        subscriberRole: ROLE_SELLER,
      });

      // ITM put: price ≤ strike. Use 2260 ≤ 2280.
      const exerciseL2 = await warpTo(
        chainTime,
        (await chainTime.currentL1TimestampSec()) + 1n,
      );
      const witness = buildCandleWitness({
        candleOpenSec: exerciseL2 - 120n,
        candle: {
          openTime: 0n,
          open: "2260.00000000",
          high: "2265.00000000",
          low: "2255.00000000",
          close: "2260.00000000",
          closeTime: 0n,
        },
      });

      await doExercise({
        wallet,
        scenario,
        chainTime,
        buyer: alice,
        seller: bob,
        witness,
      });

      const a = await balances({ scenario, who: alice });
      const b = await balances({ scenario, who: bob });
      // Alice: -PREMIUM (paid), -BASE (settlement to bob), +QUOTE_AMOUNT (withdrawn from escrow)
      expect(a.base).toBe(0n);
      expect(a.quote).toBe(QUOTE_AMOUNT);
      // Bob: -QUOTE_AMOUNT deposited at subscribe (sent to alice on exercise),
      //       +PREMIUM released at subscribe, +BASE settlement.
      expect(b.base).toBe(BASE_AMOUNT);
      expect(b.quote).toBe(PREMIUM_AMOUNT);
    },
    TEST_TIMEOUT,
  );

  // ─── Cancel + reclaim ──────────────────────────────────────────────

  it(
    "cancel: buyer-proposer cancels before subscribe, premium refunded",
    async () => {
      const deadline =
        (await chainTime.currentL1TimestampSec()) + DEADLINE_OFFSET_S;
      const scenario = await prepareScenario({
        chainTime,
        wallet,
        node,
        deployer: alice,
        isCall: true,
        isAmerican: true,
        deadline,
      });

      await mint(
        scenario.stack.quoteToken,
        alice.address,
        PREMIUM_AMOUNT,
        alice.address,
        chainTime,
      );

      await doOffer({
        chainTime,
        wallet,
        scenario,
        proposer: alice,
        counterparty: bob,
        proposerRole: ROLE_BUYER,
      });

      // Premium is now sitting in the escrow.
      const before = await balances({ scenario, who: alice });
      expect(before.quote).toBe(0n);

      await chainTime.withMine(
        scenario.stack.escrowLogic.methods.cancel(scenario.escrowAddress).send({
          from: alice.address,
          additionalScopes: [scenario.escrowAddress],
          wait: { timeout: TX_TIMEOUT },
        }),
      );

      const after = await balances({ scenario, who: alice });
      expect(after.quote).toBe(PREMIUM_AMOUNT);
    },
    TEST_TIMEOUT,
  );

  it(
    "reclaim (american): seller reclaims collateral past deadline",
    async () => {
      // Use a short deadline so we can warp past it without huge time jumps.
      const SHORT_DEADLINE_S = 120n;
      const deadline =
        (await chainTime.currentL1TimestampSec()) + SHORT_DEADLINE_S;
      const scenario = await prepareScenario({
        chainTime,
        wallet,
        node,
        deployer: alice,
        isCall: true,
        isAmerican: true,
        deadline,
      });

      await mint(
        scenario.stack.quoteToken,
        alice.address,
        PREMIUM_AMOUNT,
        alice.address,
        chainTime,
      );
      await mint(
        scenario.stack.baseToken,
        bob.address,
        BASE_AMOUNT,
        alice.address,
        chainTime,
      );

      await doOffer({
        chainTime,
        wallet,
        scenario,
        proposer: alice,
        counterparty: bob,
        proposerRole: ROLE_BUYER,
      });
      await doSubscribe({
        chainTime,
        wallet,
        scenario,
        subscriber: bob,
        subscriberRole: ROLE_SELLER,
      });

      // Warp past the deadline.
      await warpTo(chainTime, deadline + 10n);

      await chainTime.withMine(
        scenario.stack.escrowLogic.methods
          .reclaim(scenario.escrowAddress)
          .send({
            from: bob.address,
            additionalScopes: [scenario.escrowAddress],
            wait: { timeout: TX_TIMEOUT },
          }),
      );

      const b = await balances({ scenario, who: bob });
      // Bob got the premium at subscribe, then the base collateral back via reclaim.
      expect(b.base).toBe(BASE_AMOUNT);
      expect(b.quote).toBe(PREMIUM_AMOUNT);
    },
    TEST_TIMEOUT,
  );

  // ─── Negative cases ────────────────────────────────────────────────

  it(
    "negative: only buyer can exercise",
    async () => {
      const deadline =
        (await chainTime.currentL1TimestampSec()) + DEADLINE_OFFSET_S;
      const scenario = await prepareScenario({
        chainTime,
        wallet,
        node,
        deployer: alice,
        isCall: true,
        isAmerican: true,
        deadline,
      });

      await mint(
        scenario.stack.quoteToken,
        alice.address,
        PREMIUM_AMOUNT + QUOTE_AMOUNT,
        alice.address,
        chainTime,
      );
      await mint(
        scenario.stack.baseToken,
        bob.address,
        BASE_AMOUNT,
        alice.address,
        chainTime,
      );

      await doOffer({
        chainTime,
        wallet,
        scenario,
        proposer: alice,
        counterparty: bob,
        proposerRole: ROLE_BUYER,
      });
      await doSubscribe({
        chainTime,
        wallet,
        scenario,
        subscriber: bob,
        subscriberRole: ROLE_SELLER,
      });

      const exerciseL2 = await warpTo(
        chainTime,
        (await chainTime.currentL1TimestampSec()) + 1n,
      );
      const witness = buildCandleWitness({
        candleOpenSec: exerciseL2 - 120n,
        candle: {
          openTime: 0n,
          open: "2300.00000000",
          high: "2310.00000000",
          low: "2290.00000000",
          close: "2300.00000000",
          closeTime: 0n,
        },
      });

      // Bob (seller) tries to exercise. Authwit is from bob since we use
      // his address as `from`; the contract should reject before the
      // transfer ever runs.
      const settlementNonce = randomNonce();
      const action =
        scenario.stack.quoteToken.methods.transfer_private_to_private(
          bob.address,
          alice.address,
          QUOTE_AMOUNT,
          settlementNonce,
        );
      await setPrivateAuthWit(
        scenario.stack.escrowLogic.address,
        action,
        bob.address,
        wallet,
      );

      await expect(
        scenario.stack.escrowLogic.methods
          .exercise(
            scenario.escrowAddress,
            witness.signature,
            witness.envelope,
            witness.contents,
            witness.dataHashOffsets,
            witness.queryPrefix,
            settlementNonce,
          )
          .send({
            from: bob.address,
            additionalScopes: [scenario.escrowAddress],
            wait: { timeout: TX_TIMEOUT },
          }),
      ).rejects.toThrow(/only buyer can exercise/);
    },
    TEST_TIMEOUT,
  );

  it(
    "negative: query_prefix mismatch reverts",
    async () => {
      const deadline =
        (await chainTime.currentL1TimestampSec()) + DEADLINE_OFFSET_S;
      const scenario = await prepareScenario({
        chainTime,
        wallet,
        node,
        deployer: alice,
        isCall: true,
        isAmerican: true,
        deadline,
      });

      await mint(
        scenario.stack.quoteToken,
        alice.address,
        PREMIUM_AMOUNT + QUOTE_AMOUNT,
        alice.address,
        chainTime,
      );
      await mint(
        scenario.stack.baseToken,
        bob.address,
        BASE_AMOUNT,
        alice.address,
        chainTime,
      );

      await doOffer({
        chainTime,
        wallet,
        scenario,
        proposer: alice,
        counterparty: bob,
        proposerRole: ROLE_BUYER,
      });
      await doSubscribe({
        chainTime,
        wallet,
        scenario,
        subscriber: bob,
        subscriberRole: ROLE_SELLER,
      });

      const exerciseL2 = await warpTo(
        chainTime,
        (await chainTime.currentL1TimestampSec()) + 1n,
      );
      // Build with a different symbol → query_prefix won't match the pin.
      const witness = buildCandleWitness({
        candleOpenSec: exerciseL2 - 120n,
        candle: {
          openTime: 0n,
          open: "2300.00000000",
          high: "2310.00000000",
          low: "2290.00000000",
          close: "2300.00000000",
          closeTime: 0n,
        },
        symbol: "BTCUSDT",
      });

      await expect(
        doExercise({
          wallet,
          scenario,
          chainTime,
          buyer: alice,
          seller: bob,
          witness,
        }),
      ).rejects.toThrow(/query_prefix mismatch/);
    },
    TEST_TIMEOUT,
  );

  it(
    "negative: call not in the money reverts",
    async () => {
      const deadline =
        (await chainTime.currentL1TimestampSec()) + DEADLINE_OFFSET_S;
      const scenario = await prepareScenario({
        chainTime,
        wallet,
        node,
        deployer: alice,
        isCall: true,
        isAmerican: true,
        deadline,
      });

      await mint(
        scenario.stack.quoteToken,
        alice.address,
        PREMIUM_AMOUNT + QUOTE_AMOUNT,
        alice.address,
        chainTime,
      );
      await mint(
        scenario.stack.baseToken,
        bob.address,
        BASE_AMOUNT,
        alice.address,
        chainTime,
      );

      await doOffer({
        chainTime,
        wallet,
        scenario,
        proposer: alice,
        counterparty: bob,
        proposerRole: ROLE_BUYER,
      });
      await doSubscribe({
        chainTime,
        wallet,
        scenario,
        subscriber: bob,
        subscriberRole: ROLE_SELLER,
      });

      const exerciseL2 = await warpTo(
        chainTime,
        (await chainTime.currentL1TimestampSec()) + 1n,
      );
      // Price 2270 < strike 2280 → OTM for a call.
      const witness = buildCandleWitness({
        candleOpenSec: exerciseL2 - 120n,
        candle: {
          openTime: 0n,
          open: "2270.00000000",
          high: "2275.00000000",
          low: "2265.00000000",
          close: "2270.00000000",
          closeTime: 0n,
        },
      });

      await expect(
        doExercise({
          wallet,
          scenario,
          chainTime,
          buyer: alice,
          seller: bob,
          witness,
        }),
      ).rejects.toThrow(/call not in the money/);
    },
    TEST_TIMEOUT,
  );

  it(
    "negative: american exercise blocked past deadline",
    async () => {
      const SHORT_DEADLINE_S = 120n;
      const deadline =
        (await chainTime.currentL1TimestampSec()) + SHORT_DEADLINE_S;
      const scenario = await prepareScenario({
        chainTime,
        wallet,
        node,
        deployer: alice,
        isCall: true,
        isAmerican: true,
        deadline,
      });

      await mint(
        scenario.stack.quoteToken,
        alice.address,
        PREMIUM_AMOUNT + QUOTE_AMOUNT,
        alice.address,
        chainTime,
      );
      await mint(
        scenario.stack.baseToken,
        bob.address,
        BASE_AMOUNT,
        alice.address,
        chainTime,
      );

      await doOffer({
        chainTime,
        wallet,
        scenario,
        proposer: alice,
        counterparty: bob,
        proposerRole: ROLE_BUYER,
      });
      await doSubscribe({
        chainTime,
        wallet,
        scenario,
        subscriber: bob,
        subscriberRole: ROLE_SELLER,
      });

      // Warp PAST the deadline.
      const exerciseL2 = await warpTo(chainTime, deadline + 30n);

      const witness = buildCandleWitness({
        candleOpenSec: exerciseL2 - 120n,
        candle: {
          openTime: 0n,
          open: "2300.00000000",
          high: "2310.00000000",
          low: "2290.00000000",
          close: "2300.00000000",
          closeTime: 0n,
        },
      });

      // Timestamp checks fail with the protocol's "Timestamp mismatch" string.
      await expect(
        doExercise({
          wallet,
          scenario,
          chainTime,
          buyer: alice,
          seller: bob,
          witness,
        }),
      ).rejects.toThrow(/Timestamp mismatch/);
    },
    TEST_TIMEOUT,
  );

  it(
    "european: alice exercises inside [deadline, deadline + grace]",
    async () => {
      // Short deadline so we can warp past it cheaply, then exercise inside
      // the 24h grace window.
      const SHORT_DEADLINE_S = 60n;
      const deadline =
        (await chainTime.currentL1TimestampSec()) + SHORT_DEADLINE_S;
      const scenario = await prepareScenario({
        chainTime,
        wallet,
        node,
        deployer: alice,
        isCall: true,
        isAmerican: false,
        deadline,
      });

      await mint(
        scenario.stack.quoteToken,
        alice.address,
        PREMIUM_AMOUNT + QUOTE_AMOUNT,
        alice.address,
        chainTime,
      );
      await mint(
        scenario.stack.baseToken,
        bob.address,
        BASE_AMOUNT,
        alice.address,
        chainTime,
      );

      await doOffer({
        chainTime,
        wallet,
        scenario,
        proposer: alice,
        counterparty: bob,
        proposerRole: ROLE_BUYER,
      });
      await doSubscribe({
        chainTime,
        wallet,
        scenario,
        subscriber: bob,
        subscriberRole: ROLE_SELLER,
      });

      // Warp into the grace window (just past the deadline).
      const exerciseL2 = await warpTo(chainTime, deadline + 60n);

      // Candle must straddle the deadline:
      //   candle_open_s + 60 >= deadline (finalises at/after deadline)
      //   candle_open_s <= deadline + 5min (settlement window)
      // Pick candle_open == deadline - 30s so close_time ≈ deadline + 30s.
      const candleOpenSec = deadline - 30n;
      // Sanity: block.timestamp at exercise must be in [deadline, deadline+grace].
      expect(exerciseL2).toBeGreaterThanOrEqual(deadline);
      const witness = buildCandleWitness({
        candleOpenSec,
        candle: {
          openTime: 0n,
          open: "2300.00000000",
          high: "2310.00000000",
          low: "2290.00000000",
          close: "2300.00000000",
          closeTime: 0n,
        },
      });

      await doExercise({
        chainTime,
        wallet,
        scenario,
        buyer: alice,
        seller: bob,
        witness,
      });

      const a = await balances({ scenario, who: alice });
      const b = await balances({ scenario, who: bob });
      expect(a.base).toBe(BASE_AMOUNT);
      expect(a.quote).toBe(0n);
      expect(b.base).toBe(0n);
      expect(b.quote).toBe(PREMIUM_AMOUNT + QUOTE_AMOUNT);
    },
    TEST_TIMEOUT,
  );

  it(
    "reclaim (european): seller reclaims after deadline + 24h grace",
    async () => {
      const SHORT_DEADLINE_S = 60n;
      const deadline =
        (await chainTime.currentL1TimestampSec()) + SHORT_DEADLINE_S;
      const scenario = await prepareScenario({
        chainTime,
        wallet,
        node,
        deployer: alice,
        isCall: true,
        isAmerican: false,
        deadline,
      });

      await mint(
        scenario.stack.quoteToken,
        alice.address,
        PREMIUM_AMOUNT,
        alice.address,
        chainTime,
      );
      await mint(
        scenario.stack.baseToken,
        bob.address,
        BASE_AMOUNT,
        alice.address,
        chainTime,
      );

      await doOffer({
        chainTime,
        wallet,
        scenario,
        proposer: alice,
        counterparty: bob,
        proposerRole: ROLE_BUYER,
      });
      await doSubscribe({
        chainTime,
        wallet,
        scenario,
        subscriber: bob,
        subscriberRole: ROLE_SELLER,
      });

      // Warp past deadline + the 24h late-exercise grace window. After such
      // a large jump the PXE needs a sync so bob's simulation can see the
      // proposal-note nullification from his own subscribe (without it the
      // anchor block predates the subscribe and reclaim trips on
      // "option still pending").
      await warpTo(chainTime, deadline + EUROPEAN_GRACE_S + 10n);
      await syncPXE(wallet);

      await chainTime.withMine(
        scenario.stack.escrowLogic.methods
          .reclaim(scenario.escrowAddress)
          .send({
            from: bob.address,
            additionalScopes: [scenario.escrowAddress],
            wait: { timeout: TX_TIMEOUT },
          }),
      );

      const b = await balances({ scenario, who: bob });
      expect(b.base).toBe(BASE_AMOUNT);
      expect(b.quote).toBe(PREMIUM_AMOUNT);
    },
    TEST_TIMEOUT,
  );

  it(
    "cancel: seller-proposer cancels before subscribe, collateral refunded",
    async () => {
      const deadline =
        (await chainTime.currentL1TimestampSec()) + DEADLINE_OFFSET_S;
      const scenario = await prepareScenario({
        chainTime,
        wallet,
        node,
        deployer: alice,
        isCall: true,
        isAmerican: true,
        deadline,
      });

      // Bob will offer as seller, so HE needs the base collateral.
      await mint(
        scenario.stack.baseToken,
        bob.address,
        BASE_AMOUNT,
        alice.address,
        chainTime,
      );

      await doOffer({
        chainTime,
        wallet,
        scenario,
        proposer: bob,
        counterparty: alice,
        proposerRole: ROLE_SELLER,
      });

      // Collateral sitting in escrow.
      const before = await balances({ scenario, who: bob });
      expect(before.base).toBe(0n);

      await chainTime.withMine(
        scenario.stack.escrowLogic.methods.cancel(scenario.escrowAddress).send({
          from: bob.address,
          additionalScopes: [scenario.escrowAddress],
          wait: { timeout: TX_TIMEOUT },
        }),
      );

      const after = await balances({ scenario, who: bob });
      expect(after.base).toBe(BASE_AMOUNT);
    },
    TEST_TIMEOUT,
  );

  it(
    "negative: put not in the money reverts",
    async () => {
      const deadline =
        (await chainTime.currentL1TimestampSec()) + DEADLINE_OFFSET_S;
      const scenario = await prepareScenario({
        chainTime,
        wallet,
        node,
        deployer: alice,
        isCall: false,
        isAmerican: true,
        deadline,
      });

      await mint(
        scenario.stack.quoteToken,
        alice.address,
        PREMIUM_AMOUNT,
        alice.address,
        chainTime,
      );
      await mint(
        scenario.stack.baseToken,
        alice.address,
        BASE_AMOUNT,
        alice.address,
        chainTime,
      );
      await mint(
        scenario.stack.quoteToken,
        bob.address,
        QUOTE_AMOUNT,
        alice.address,
        chainTime,
      );

      await doOffer({
        chainTime,
        wallet,
        scenario,
        proposer: alice,
        counterparty: bob,
        proposerRole: ROLE_BUYER,
      });
      await doSubscribe({
        chainTime,
        wallet,
        scenario,
        subscriber: bob,
        subscriberRole: ROLE_SELLER,
      });

      const exerciseL2 = await warpTo(
        chainTime,
        (await chainTime.currentL1TimestampSec()) + 1n,
      );
      // Price 2300 > strike 2280 → OTM for a put.
      const witness = buildCandleWitness({
        candleOpenSec: exerciseL2 - 120n,
        candle: {
          openTime: 0n,
          open: "2300.00000000",
          high: "2310.00000000",
          low: "2290.00000000",
          close: "2300.00000000",
          closeTime: 0n,
        },
      });

      await expect(
        doExercise({
          chainTime,
          wallet,
          scenario,
          buyer: alice,
          seller: bob,
          witness,
        }),
      ).rejects.toThrow(/put not in the money/);
    },
    TEST_TIMEOUT,
  );

  it(
    "negative: wrong attestor signature is rejected by the oracle",
    async () => {
      const deadline =
        (await chainTime.currentL1TimestampSec()) + DEADLINE_OFFSET_S;
      const scenario = await prepareScenario({
        chainTime,
        wallet,
        node,
        deployer: alice,
        isCall: true,
        isAmerican: true,
        deadline,
      });

      await mint(
        scenario.stack.quoteToken,
        alice.address,
        PREMIUM_AMOUNT + QUOTE_AMOUNT,
        alice.address,
        chainTime,
      );
      await mint(
        scenario.stack.baseToken,
        bob.address,
        BASE_AMOUNT,
        alice.address,
        chainTime,
      );

      await doOffer({
        chainTime,
        wallet,
        scenario,
        proposer: alice,
        counterparty: bob,
        proposerRole: ROLE_BUYER,
      });
      await doSubscribe({
        chainTime,
        wallet,
        scenario,
        subscriber: bob,
        subscriberRole: ROLE_SELLER,
      });

      const exerciseL2 = await warpTo(
        chainTime,
        (await chainTime.currentL1TimestampSec()) + 1n,
      );
      // Build a witness signed by a DIFFERENT key. The oracle was deployed
      // pinning the canonical attestor's pubkey, so verification should fail.
      const candleOpenMs = (exerciseL2 - 120n) * 1000n;
      const candleCloseMs = candleOpenMs + 60_000n - 1n;
      const witness = buildSyntheticKlinesWitness({
        privateKey:
          0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefn,
        recipient: TEST_ATTESTATION_RECIPIENT,
        baseUrl: KLINES_BASE_URL,
        symbol: KLINES_SYMBOL,
        interval: KLINES_INTERVAL,
        startTime: candleOpenMs,
        endTime: candleCloseMs,
        candle: {
          openTime: candleOpenMs,
          open: "2300.00000000",
          high: "2310.00000000",
          low: "2290.00000000",
          close: "2300.00000000",
          closeTime: candleCloseMs,
        },
        envelopeTimestamp: candleCloseMs + 1n,
      });

      await expect(
        doExercise({
          chainTime,
          wallet,
          scenario,
          buyer: alice,
          seller: bob,
          witness,
        }),
      ).rejects.toThrow(/ECDSA verification failed/);
    },
    TEST_TIMEOUT,
  );

  // ─── State-machine negatives ───────────────────────────────────────

  it(
    "negative: exercise before subscribe reverts (option not yet active)",
    async () => {
      const deadline =
        (await chainTime.currentL1TimestampSec()) + DEADLINE_OFFSET_S;
      const scenario = await prepareScenario({
        chainTime,
        wallet,
        node,
        deployer: alice,
        isCall: true,
        isAmerican: true,
        deadline,
      });

      await mint(
        scenario.stack.quoteToken,
        alice.address,
        PREMIUM_AMOUNT + QUOTE_AMOUNT,
        alice.address,
        chainTime,
      );

      // Offer only — no subscribe. The proposal note is still alive, so
      // exercise must reject with "option not yet active".
      await doOffer({
        chainTime,
        wallet,
        scenario,
        proposer: alice,
        counterparty: bob,
        proposerRole: ROLE_BUYER,
      });

      const exerciseL2 = await warpTo(
        chainTime,
        (await chainTime.currentL1TimestampSec()) + 1n,
      );
      const witness = buildCandleWitness({
        candleOpenSec: exerciseL2 - 120n,
        candle: {
          openTime: 0n,
          open: "2300.00000000",
          high: "2310.00000000",
          low: "2290.00000000",
          close: "2300.00000000",
          closeTime: 0n,
        },
      });

      await expect(
        doExercise({
          chainTime,
          wallet,
          scenario,
          buyer: alice,
          seller: bob,
          witness,
        }),
      ).rejects.toThrow(/option not yet active/);
    },
    TEST_TIMEOUT,
  );

  it(
    "negative: cancel after subscribe reverts (proposal note already nullified)",
    async () => {
      const deadline =
        (await chainTime.currentL1TimestampSec()) + DEADLINE_OFFSET_S;
      const scenario = await prepareScenario({
        chainTime,
        wallet,
        node,
        deployer: alice,
        isCall: true,
        isAmerican: true,
        deadline,
      });

      await mint(
        scenario.stack.quoteToken,
        alice.address,
        PREMIUM_AMOUNT,
        alice.address,
        chainTime,
      );
      await mint(
        scenario.stack.baseToken,
        bob.address,
        BASE_AMOUNT,
        alice.address,
        chainTime,
      );

      await doOffer({
        chainTime,
        wallet,
        scenario,
        proposer: alice,
        counterparty: bob,
        proposerRole: ROLE_BUYER,
      });
      await doSubscribe({
        chainTime,
        wallet,
        scenario,
        subscriber: bob,
        subscriberRole: ROLE_SELLER,
      });

      // Subscribe consumed the proposal note; cancel must now fail.
      await expect(
        chainTime.withMine(
          scenario.stack.escrowLogic.methods
            .cancel(scenario.escrowAddress)
            .send({
              from: alice.address,
              additionalScopes: [scenario.escrowAddress],
              wait: { timeout: TX_TIMEOUT },
            }),
        ),
      ).rejects.toThrow(/proposal note not found/);
    },
    TEST_TIMEOUT,
  );

  it(
    "negative: reclaim while still pending reverts (use cancel instead)",
    async () => {
      const SHORT_DEADLINE_S = 60n;
      const deadline =
        (await chainTime.currentL1TimestampSec()) + SHORT_DEADLINE_S;
      const scenario = await prepareScenario({
        chainTime,
        wallet,
        node,
        deployer: alice,
        isCall: true,
        isAmerican: true,
        deadline,
      });

      await mint(
        scenario.stack.quoteToken,
        alice.address,
        PREMIUM_AMOUNT,
        alice.address,
        chainTime,
      );

      // Offer only — proposal note still alive.
      await doOffer({
        chainTime,
        wallet,
        scenario,
        proposer: alice,
        counterparty: bob,
        proposerRole: ROLE_BUYER,
      });

      // Warp past deadline so the timing check would pass.
      await warpTo(chainTime, deadline + 10n);

      // Reclaim should still fail because the option never reached active state.
      await expect(
        chainTime.withMine(
          scenario.stack.escrowLogic.methods
            .reclaim(scenario.escrowAddress)
            .send({
              from: bob.address,
              additionalScopes: [scenario.escrowAddress],
              wait: { timeout: TX_TIMEOUT },
            }),
        ),
      ).rejects.toThrow(/option still pending; use cancel/);
    },
    TEST_TIMEOUT,
  );

  it(
    "negative: reclaim before deadline reverts",
    async () => {
      const deadline =
        (await chainTime.currentL1TimestampSec()) + DEADLINE_OFFSET_S;
      const scenario = await prepareScenario({
        chainTime,
        wallet,
        node,
        deployer: alice,
        isCall: true,
        isAmerican: true,
        deadline,
      });

      await mint(
        scenario.stack.quoteToken,
        alice.address,
        PREMIUM_AMOUNT,
        alice.address,
        chainTime,
      );
      await mint(
        scenario.stack.baseToken,
        bob.address,
        BASE_AMOUNT,
        alice.address,
        chainTime,
      );

      await doOffer({
        chainTime,
        wallet,
        scenario,
        proposer: alice,
        counterparty: bob,
        proposerRole: ROLE_BUYER,
      });
      await doSubscribe({
        chainTime,
        wallet,
        scenario,
        subscriber: bob,
        subscriberRole: ROLE_SELLER,
      });

      // Do NOT warp — deadline is still ~an hour in the future.
      await expect(
        chainTime.withMine(
          scenario.stack.escrowLogic.methods
            .reclaim(scenario.escrowAddress)
            .send({
              from: bob.address,
              additionalScopes: [scenario.escrowAddress],
              wait: { timeout: TX_TIMEOUT },
            }),
        ),
      ).rejects.toThrow(/Timestamp mismatch/);
    },
    TEST_TIMEOUT,
  );

  it(
    "negative: invalid sender_role reverts",
    async () => {
      const deadline =
        (await chainTime.currentL1TimestampSec()) + DEADLINE_OFFSET_S;
      const scenario = await prepareScenario({
        chainTime,
        wallet,
        node,
        deployer: alice,
        isCall: true,
        isAmerican: true,
        deadline,
      });

      await mint(
        scenario.stack.quoteToken,
        alice.address,
        PREMIUM_AMOUNT,
        alice.address,
        chainTime,
      );

      // Build authwit anyway so the failure is the role-check, not the authwit.
      const offerNonce = randomNonce();
      const action =
        scenario.stack.quoteToken.methods.transfer_private_to_private(
          alice.address,
          scenario.escrowAddress,
          PREMIUM_AMOUNT,
          offerNonce,
        );
      await setPrivateAuthWit(
        scenario.stack.escrowLogic.address,
        action,
        alice.address,
        wallet,
      );

      // sender_role = 2 (neither buyer=0 nor seller=1).
      await expect(
        scenario.stack.escrowLogic.methods
          .offer(2, bob.address, scenario.terms, scenario.secretKey, offerNonce)
          .send({
            from: alice.address,
            additionalScopes: [scenario.escrowAddress],
            wait: { timeout: TX_TIMEOUT },
          }),
      ).rejects.toThrow(/invalid role/);
    },
    TEST_TIMEOUT,
  );

  // ─── European timing boundaries ────────────────────────────────────

  it(
    "negative: european exercise before deadline reverts",
    async () => {
      const deadline =
        (await chainTime.currentL1TimestampSec()) + DEADLINE_OFFSET_S;
      const scenario = await prepareScenario({
        chainTime,
        wallet,
        node,
        deployer: alice,
        isCall: true,
        isAmerican: false,
        deadline,
      });

      await mint(
        scenario.stack.quoteToken,
        alice.address,
        PREMIUM_AMOUNT + QUOTE_AMOUNT,
        alice.address,
        chainTime,
      );
      await mint(
        scenario.stack.baseToken,
        bob.address,
        BASE_AMOUNT,
        alice.address,
        chainTime,
      );

      await doOffer({
        chainTime,
        wallet,
        scenario,
        proposer: alice,
        counterparty: bob,
        proposerRole: ROLE_BUYER,
      });
      await doSubscribe({
        chainTime,
        wallet,
        scenario,
        subscriber: bob,
        subscriberRole: ROLE_SELLER,
      });

      // Build the candle positioned at the deadline (so the candle-window
      // checks pass) but DON'T warp past the deadline — block.timestamp
      // must remain below it so the GTE-deadline check fires.
      const exerciseL2 = await warpTo(
        chainTime,
        (await chainTime.currentL1TimestampSec()) + 1n,
      );
      expect(exerciseL2).toBeLessThan(deadline);
      const witness = buildCandleWitness({
        candleOpenSec: deadline - 30n,
        candle: {
          openTime: 0n,
          open: "2300.00000000",
          high: "2310.00000000",
          low: "2290.00000000",
          close: "2300.00000000",
          closeTime: 0n,
        },
      });

      await expect(
        doExercise({
          chainTime,
          wallet,
          scenario,
          buyer: alice,
          seller: bob,
          witness,
        }),
      ).rejects.toThrow(/Timestamp mismatch/);
    },
    TEST_TIMEOUT,
  );

  // NOTE: "european exercise AFTER deadline + grace" is not exercised here
  // because the 24h warp it requires confuses the local PXE — alice's view
  // of bob's subscribe nullifier doesn't refresh after such a large jump,
  // so the simulation reports "option not yet active" instead of the
  // timestamp failure we want to assert. The contract path itself is
  // exercised symmetrically by `american exercise blocked past deadline`
  // (american's `LTE deadline` mirrors european's `LTE deadline + grace`).
  // If you want this coverage, run it as a Noir TXE test.

  // ─── Wrong subscriber ──────────────────────────────────────────────

  it(
    "negative: only the named counterparty can subscribe",
    async () => {
      const deadline =
        (await chainTime.currentL1TimestampSec()) + DEADLINE_OFFSET_S;
      const scenario = await prepareScenario({
        chainTime,
        wallet,
        node,
        deployer: alice,
        isCall: true,
        isAmerican: true,
        deadline,
      });

      await mint(
        scenario.stack.quoteToken,
        alice.address,
        PREMIUM_AMOUNT,
        alice.address,
        chainTime,
      );

      // Alice offers as buyer with bob as the named counterparty. The
      // proposal note says `missing_side == SELLER` ⇒ only bob may subscribe.
      // Alice (the proposer) tries to subscribe — expected to fail.
      await doOffer({
        chainTime,
        wallet,
        scenario,
        proposer: alice,
        counterparty: bob,
        proposerRole: ROLE_BUYER,
      });

      const subscribeNonce = randomNonce();
      const action =
        scenario.stack.baseToken.methods.transfer_private_to_private(
          alice.address,
          scenario.escrowAddress,
          BASE_AMOUNT,
          subscribeNonce,
        );
      await setPrivateAuthWit(
        scenario.stack.escrowLogic.address,
        action,
        alice.address,
        wallet,
      );

      await expect(
        scenario.stack.escrowLogic.methods
          .subscribe(scenario.escrowAddress, subscribeNonce)
          .send({
            from: alice.address,
            additionalScopes: [scenario.escrowAddress],
            wait: { timeout: TX_TIMEOUT },
          }),
      ).rejects.toThrow(/caller must be seller/);
    },
    TEST_TIMEOUT,
  );
});
