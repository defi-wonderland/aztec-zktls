import fs from "node:fs";
import path from "node:path";
import { Barretenberg } from "@aztec/bb.js";
import { Fr } from "@aztec/aztec.js/fields";
import { createAztecNodeClient } from "@aztec/aztec.js/node";
import { getPublicEvents } from "@aztec/aztec.js/events";
import type { EmbeddedWallet } from "@aztec/wallets/embedded";
import type { AccountManager } from "@aztec/aztec.js/wallet";
import type { TxHash } from "@aztec/stdlib/tx";
import { QuoteVerifierContract } from "../artifacts/QuoteVerifier.js";

export const NODE_URL = process.env.AZTEC_NODE_URL ?? "http://localhost:8080";

/** Match the `MAX_URL_LEN` global in `src/nr/examples/quote_verifier/src/main.nr`. */
export const MAX_URL_LEN = 96;

/**
 * Poseidon2 hash of a UTF-8 URL, zero-padded to `maxLen` bytes per byte.
 * Mirrors the URL hashing the QuoteVerifier contract does in-circuit
 * over the request URL bytes (zero-padded to maxLen). Storage hashes we
 * commit at deploy must match what the circuit computes at verify time,
 * or the contract's `allowed_url_hashes` map lookup misses.
 */
export async function poseidon2HashUrl(
  bb: Barretenberg,
  url: string,
  maxLen: number,
): Promise<bigint> {
  const bytes = Array.from(new TextEncoder().encode(url));
  while (bytes.length < maxLen) bytes.push(0);
  const inputs = bytes.map((b) => new Fr(BigInt(b)).toBuffer());
  const hashFr = await bb.poseidon2Hash({ inputs });
  return BigInt(Fr.fromBuffer(Buffer.from(hashFr.hash)).toString());
}

export async function hashAllowedUrls(
  bb: Barretenberg,
  urls: string[],
  maxLen: number,
): Promise<bigint[]> {
  const hashes: bigint[] = [];
  for (const url of urls) hashes.push(await poseidon2HashUrl(bb, url, maxLen));
  return hashes;
}

/**
 * Poseidon2 hash of raw URL bytes (as the witness stores them), zero-padded.
 * Used to derive contract storage allowed_url_hashes directly from a witness,
 * so the test doesn't have to hardcode the URL strings.
 */
export async function poseidon2HashUrlBytes(
  bb: Barretenberg,
  bytes: number[],
  maxLen: number,
): Promise<bigint> {
  const padded = bytes.slice();
  while (padded.length < maxLen) padded.push(0);
  const inputs = padded.map((b) => new Fr(BigInt(b)).toBuffer());
  const hashFr = await bb.poseidon2Hash({ inputs });
  return BigInt(Fr.fromBuffer(Buffer.from(hashFr.hash)).toString());
}

export async function hashAllowedUrlsFromWitness(
  bb: Barretenberg,
  allowedUrls: number[][],
  maxLen: number,
): Promise<bigint[]> {
  const hashes: bigint[] = [];
  for (const bytes of allowedUrls)
    hashes.push(await poseidon2HashUrlBytes(bb, bytes, maxLen));
  return hashes;
}

export type Witness = {
  publicKeyX: number[]; // deploy-only (seeds allowed_attestor); not passed to verify()
  publicKeyY: number[]; // same
  signature: number[];
  requestUrls: number[][];
  allowedUrls: number[][];
  plainJsonResponses: number[][];
  // Envelope fields (see attestation_verifier::verify_attestation).
  recipient: number[];
  requestHmb: number[];
  responseResolves: number[][];
  data: number[];
  attConditions: number[];
  timestamp: string;
  additionParams: number[];
  dataHashOffsets: number[];
};

/**
 * Locate the most recent `.witness.json` under attestations/ matching the
 * given provider prefix (e.g. "binance-", "okx-", "coinbase-"). Pass undefined
 * to take the latest witness across all providers.
 */
export function findLatestWitness(prefix?: string): string {
  const dir = path.resolve(import.meta.dirname, "../../attestations");
  if (!fs.existsSync(dir)) {
    throw new Error(
      `No attestations directory at ${dir}. Run \`yarn attest <provider> symbol=...\` first.`,
    );
  }
  const files = fs
    .readdirSync(dir)
    .filter(
      (f) =>
        f.endsWith(".witness.json") && (prefix ? f.startsWith(prefix) : true),
    )
    .sort()
    .reverse();
  if (files.length === 0) {
    const hint = prefix ? `matching '${prefix}*'` : "";
    throw new Error(
      `No witnesses ${hint}in ${dir}. Run \`yarn attest <provider> symbol=...\` first.`,
    );
  }
  return path.join(dir, files[0]!);
}

export function loadWitness(p: string): Witness {
  return JSON.parse(fs.readFileSync(p, "utf8")) as Witness;
}

const DEPLOY_TIMEOUT = 300_000;
const TX_TIMEOUT = 120_000;

/**
 * Deploy a fresh QuoteVerifier (seeded with the witness's own pubkey as the
 * allowed attestor) and call `verify(...)` with the witness inputs. Returns
 * the deployed contract and the tx receipt for downstream assertions.
 */
export async function deployAndVerify(
  wallet: EmbeddedWallet,
  bb: Barretenberg,
  account: AccountManager,
  witness: Witness,
): Promise<{
  contract: QuoteVerifierContract;
  receipt: { status: string; blockNumber?: number; txHash: TxHash };
}> {
  const allowedUrlHashes = await hashAllowedUrlsFromWitness(
    bb,
    witness.allowedUrls,
    MAX_URL_LEN,
  );
  const initialAttestor = { x: witness.publicKeyX, y: witness.publicKeyY };

  const { contract } = await QuoteVerifierContract.deploy(
    wallet,
    allowedUrlHashes,
    initialAttestor,
  ).send({ from: account.address, wait: { timeout: DEPLOY_TIMEOUT } });

  const envelope = {
    recipient: witness.recipient,
    request_url: witness.requestUrls[0]!,
    request_hmb: witness.requestHmb,
    response_resolves: witness.responseResolves,
    data: witness.data,
    att_conditions: witness.attConditions,
    timestamp: BigInt(witness.timestamp),
    addition_params: witness.additionParams,
  };

  const { receipt } = await contract.methods
    .verify(
      witness.signature,
      envelope,
      witness.plainJsonResponses,
      witness.dataHashOffsets,
    )
    .send({ from: account.address, wait: { timeout: TX_TIMEOUT } });

  return {
    contract,
    receipt: receipt as {
      status: string;
      blockNumber?: number;
      txHash: TxHash;
    },
  };
}

/**
 * Fetch the QuoteVerified events emitted by a transaction. Returns the parsed
 * event records so the test can assert presence and contents.
 */
export async function fetchQuoteVerifiedEvents(
  contract: QuoteVerifierContract,
  txHash: TxHash,
): Promise<Array<{ event: { sender: unknown; provider_url_hash: bigint } }>> {
  const node = createAztecNodeClient(NODE_URL);
  const { events } = await getPublicEvents<{
    sender: unknown;
    provider_url_hash: bigint;
  }>(node, QuoteVerifierContract.events.QuoteVerified, {
    txHash,
    contractAddress: contract.address,
  });
  return events;
}
