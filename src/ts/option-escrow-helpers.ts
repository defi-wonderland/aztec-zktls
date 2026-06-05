/**
 * Multi-contract setup helpers for OptionEscrowLogic tests.
 *
 * Mirrors patterns from aztec-escrow-extensions/src/ts/utils.ts but trimmed
 * to what the option_escrow tests actually need: Token deployment with a
 * minter, Escrow class id lookup, and authwit creation.
 */
import { Contract } from "@aztec/aztec.js/contracts";
import { Fr } from "@aztec/aztec.js/fields";
import type { AuthWitness } from "@aztec/stdlib/auth-witness";
import { AztecAddress } from "@aztec/aztec.js/addresses";
import type { Wallet } from "@aztec/aztec.js/wallet";
import type { ContractFunctionInteraction } from "@aztec/aztec.js/contracts";
import {
  getContractClassFromArtifact,
  type ContractInstanceWithAddress,
} from "@aztec/stdlib/contract";
import { deriveKeys } from "@aztec/stdlib/keys";
import type { EmbeddedWallet } from "@aztec/wallets/embedded";
import type { AztecNode } from "@aztec/aztec.js/node";

import {
  TokenContract,
  TokenContractArtifact,
} from "@defi-wonderland/aztec-standards/dist/src/artifacts/Token.js";
import {
  EscrowContract,
  EscrowContractArtifact,
} from "@defi-wonderland/aztec-standards/dist/src/artifacts/Escrow.js";

import { KlinesOracleContract } from "../artifacts/KlinesOracle.js";
import { OptionEscrowLogicContract } from "../artifacts/OptionEscrowLogic.js";
import { buildSyntheticKlinesWitness } from "./synthetic-klines-witness.js";
import { poseidon2Hash } from "@aztec/foundation/crypto/poseidon";
import type { ChainTime } from "./chain-time.js";

/**
 * Deploy a Token contract with the specified minter (typically the deployer).
 * The deployer can then mint balances to test accounts.
 */
export async function deployTokenWithMinter(
  wallet: Wallet,
  deployer: AztecAddress,
  chainTime: ChainTime,
  name = "TestToken",
  symbol = "TT",
): Promise<TokenContract> {
  const result = await chainTime.withMine(
    Contract.deploy(
      wallet,
      TokenContractArtifact,
      [name, symbol, 18, deployer],
      "constructor_with_minter",
    ).send({ from: deployer }),
  );
  return result.contract as TokenContract;
}

/** Class id of the aztec-standards Escrow contract — needed by the
 *  OptionEscrowLogic constructor as `escrow_class_id`. */
export async function getEscrowClassId(): Promise<Fr> {
  const cls = await getContractClassFromArtifact(EscrowContractArtifact);
  return cls.id;
}

/**
 * Create a private authwit so a calling contract can move `authorizer`'s
 * tokens via Token::transfer_private_to_private inside a private call.
 * The wallet adds the witness to its in-memory pool — it isn't published.
 */
export async function setPrivateAuthWit(
  caller: AztecAddress,
  action: ContractFunctionInteraction,
  authorizer: AztecAddress,
  wallet: EmbeddedWallet,
): Promise<AuthWitness> {
  return wallet.createAuthWit(authorizer, {
    caller,
    call: await action.getFunctionCall(),
  });
}

/** Random Fr nonce — used to disambiguate concurrent transfers in authwits. */
export function randomNonce(): Fr {
  return Fr.random();
}

/** Random Fr secret — used to derive a per-option Escrow address. */
export function randomSecretKey(): Fr {
  return Fr.random();
}

/** Force the PXE to scan recent on-chain logs and decrypt notes for accounts
 *  registered with the wallet. Required between txs when one account inserts
 *  a note that another account needs to read (e.g., alice offers → bob
 *  subscribes). v4 forbids `sync_state()` via simulate, so we poke the
 *  debug API directly. */
export async function syncPXE(wallet: EmbeddedWallet): Promise<void> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await (wallet as any).pxe.debug.sync();
}

/**
 * Pre-deploy the aztec-standards Escrow contract at the address the
 * OptionEscrowLogic's `_get_escrow(secretKey)` will derive — and register it
 * with the wallet so the PXE has the keys to encrypt/decrypt the option +
 * proposal notes (which are owned by the escrow).
 *
 * Mirrors the clawback test setup: salt = logic-contract address,
 * publicKeys = derived from secretKey, universalDeploy=true (deployer=0),
 * no constructor (init_hash=0).
 */
/** Shared constants for option-escrow tests. */
export const TEST_ATTESTOR_PRIVATE_KEY =
  0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefn;
export const TEST_ATTESTATION_RECIPIENT =
  "0x70a0DA282002021ff34A8AFe7749179A3066F749";
export const KLINES_BASE_URL = "https://api.binance.com/api/v3/klines";
export const KLINES_SYMBOL = "ETHUSDT";
export const KLINES_INTERVAL = "1m";
export const MAX_QUERY_PREFIX_LEN = 96;

/** Poseidon2 hash of the query-prefix bytes zero-padded to MAX_QUERY_PREFIX_LEN.
 *  Mirrors the in-circuit `_hash_query_prefix` so we can pin the expected
 *  hash inside `OptionTerms.pinned_query_prefix_hash` at offer time. */
export async function hashQueryPrefix(prefix: string): Promise<Fr> {
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

export type OptionStack = {
  baseToken: TokenContract;
  quoteToken: TokenContract;
  oracle: KlinesOracleContract;
  escrowLogic: OptionEscrowLogicContract;
  escrowClassId: Fr;
};

const DEPLOY_TIMEOUT = 300_000;

/**
 * Deploy the full option-escrow stack: BaseTok, QuoteTok, KlinesOracle (pinned
 * to our synthetic attestor's pubkey), and OptionEscrowLogic. Returns the
 * deployed contracts plus the Escrow class id needed to compute per-option
 * escrow addresses.
 */
export async function deployOptionEscrowStack(
  wallet: Wallet,
  deployer: AztecAddress,
  chainTime: ChainTime,
): Promise<OptionStack> {
  const baseToken = await deployTokenWithMinter(
    wallet,
    deployer,
    chainTime,
    "BaseTok",
    "B",
  );
  const quoteToken = await deployTokenWithMinter(
    wallet,
    deployer,
    chainTime,
    "QuoteTok",
    "Q",
  );

  // Build a placeholder witness just to extract the attestor pubkey + base-URL
  // prefix needed by the oracle constructor. The real candle witnesses (one
  // per exercise) are built later by the tests.
  const setup = buildSyntheticKlinesWitness({
    privateKey: TEST_ATTESTOR_PRIVATE_KEY,
    recipient: TEST_ATTESTATION_RECIPIENT,
    baseUrl: KLINES_BASE_URL,
    symbol: KLINES_SYMBOL,
    interval: KLINES_INTERVAL,
    startTime: 0n,
    endTime: 0n,
    candle: {
      openTime: 0n,
      open: "0.00000000",
      high: "0.00000000",
      low: "0.00000000",
      close: "0.00000000",
      closeTime: 0n,
    },
    envelopeTimestamp: 0n,
  });

  const oracle = (
    await chainTime.withMine(
      KlinesOracleContract.deploy(
        wallet,
        { x: setup.publicKeyX, y: setup.publicKeyY },
        setup.baseUrlPrefix,
      ).send({ from: deployer, wait: { timeout: DEPLOY_TIMEOUT } }),
    )
  ).contract;

  const escrowClassId = await getEscrowClassId();

  const escrowLogic = (
    await chainTime.withMine(
      OptionEscrowLogicContract.deploy(
        wallet,
        escrowClassId,
        oracle.address,
      ).send({ from: deployer, wait: { timeout: DEPLOY_TIMEOUT } }),
    )
  ).contract;

  return { baseToken, quoteToken, oracle, escrowLogic, escrowClassId };
}

export async function deployAndRegisterEscrowFor(
  wallet: EmbeddedWallet,
  node: AztecNode,
  logicAddress: AztecAddress,
  deployer: AztecAddress,
  secretKey: Fr,
  chainTime: ChainTime,
): Promise<EscrowContract> {
  const escrowKeys = await deriveKeys(secretKey);
  const salt = new Fr(logicAddress.toBigInt());
  const result = await chainTime.withMine(
    Contract.deploy(wallet, EscrowContractArtifact, [], undefined, {
      publicKeys: escrowKeys.publicKeys,
      salt,
      universalDeploy: true,
    }).send({ from: deployer }),
  );
  const escrow = result.contract as EscrowContract;

  const escrowInstance = (await node.getContract(
    escrow.address,
  )) as ContractInstanceWithAddress;
  if (escrowInstance) {
    await wallet.registerContract(
      escrowInstance,
      EscrowContractArtifact,
      secretKey,
    );
  }
  return escrow;
}
