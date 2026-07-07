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

/** Match the `MAX_RR_LEN` global in `src/nr/examples/quote_verifier/src/main.nr`. */
export const MAX_RR_LEN = 48;

/** Poseidon2 hash of a UTF-8 URL, zero-padded to `maxLen`. Mirrors the
 *  in-circuit hashing — see `poseidon2HashAttestationPair`. */
export async function poseidon2HashUrl(
  bb: Barretenberg,
  url: string,
  maxLen: number,
): Promise<bigint> {
  const bytes = Array.from(new TextEncoder().encode(url));
  if (bytes.length > maxLen) {
    throw new Error(
      `URL byte length (${bytes.length}) exceeds maxLen=${maxLen}: '${url}'`,
    );
  }
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

/** Poseidon2 hash of raw bytes, zero-padded to `maxLen`. Mirrors the
 *  circuit's `[Field; maxLen]` absorption so off-chain and in-circuit
 *  hashes match. */
export async function poseidon2HashBytes(
  bb: Barretenberg,
  bytes: number[],
  maxLen: number,
): Promise<bigint> {
  if (bytes.length > maxLen) {
    throw new Error(`byte length (${bytes.length}) exceeds maxLen=${maxLen}`);
  }
  const padded = bytes.slice();
  while (padded.length < maxLen) padded.push(0);
  const inputs = padded.map((b) => new Fr(BigInt(b)).toBuffer());
  const hashFr = await bb.poseidon2Hash({ inputs });
  return BigInt(Fr.fromBuffer(Buffer.from(hashFr.hash)).toString());
}

/** Allow-list slot key for a (url, response_resolve) pair:
 *  poseidon2_hash([poseidon2_hash(url), poseidon2_hash(rr)]). */
export async function poseidon2HashAttestationPair(
  bb: Barretenberg,
  urlBytes: number[],
  rrBytes: number[],
  maxUrlLen: number,
  maxRRLen: number,
): Promise<bigint> {
  const urlHash = await poseidon2HashBytes(bb, urlBytes, maxUrlLen);
  const rrHash = await poseidon2HashBytes(bb, rrBytes, maxRRLen);
  const inputs = [new Fr(urlHash).toBuffer(), new Fr(rrHash).toBuffer()];
  const hashFr = await bb.poseidon2Hash({ inputs });
  return BigInt(Fr.fromBuffer(Buffer.from(hashFr.hash)).toString());
}

export async function hashAllowedAttestationsFromWitness(
  bb: Barretenberg,
  allowedUrls: number[][],
  allowedResponseResolves: number[][],
  maxUrlLen: number,
  maxRRLen: number,
): Promise<bigint[]> {
  if (allowedUrls.length !== allowedResponseResolves.length) {
    throw new Error(
      `allowedUrls (${allowedUrls.length}) and allowedResponseResolves (${allowedResponseResolves.length}) must be the same length`,
    );
  }
  const hashes: bigint[] = [];
  for (let i = 0; i < allowedUrls.length; i++) {
    hashes.push(
      await poseidon2HashAttestationPair(
        bb,
        allowedUrls[i]!,
        allowedResponseResolves[i]!,
        maxUrlLen,
        maxRRLen,
      ),
    );
  }
  return hashes;
}

export type Witness = {
  publicKeyX: number[]; // deploy-only (seeds allowed_attestor); not passed to verify()
  publicKeyY: number[]; // same
  signature: number[];
  requestUrls: number[][];
  allowedUrls: number[][];
  allowedResponseResolves: number[][]; // parallel to allowedUrls
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

/** Most recent `.witness.json` under attestations/ matching `prefix`
 *  (e.g. "binance-"). Undefined → latest across providers. */
export function findLatestWitness(prefix?: string): string {
  const dir = path.resolve(import.meta.dirname, "../../attestations");
  if (!fs.existsSync(dir)) {
    throw new Error(
      `No attestations directory at ${dir}. Run \`yarn attest <provider> symbol=...\` first.`,
    );
  }
  // mtime-sort: filenames sort alphabetically by provider, not date.
  const files = fs
    .readdirSync(dir)
    .filter(
      (f) =>
        f.endsWith(".witness.json") && (prefix ? f.startsWith(prefix) : true),
    )
    .map((name) => ({
      name,
      mtime: fs.statSync(path.join(dir, name)).mtimeMs,
    }))
    .sort((a, b) => b.mtime - a.mtime);
  if (files.length === 0) {
    const hint = prefix ? `matching '${prefix}*'` : "";
    throw new Error(
      `No witnesses ${hint}in ${dir}. Run \`yarn attest <provider> symbol=...\` first.`,
    );
  }
  return path.join(dir, files[0]!.name);
}

export function loadWitness(p: string): Witness {
  return JSON.parse(fs.readFileSync(p, "utf8")) as Witness;
}

const DEPLOY_TIMEOUT = 300_000;
const TX_TIMEOUT = 120_000;

/** Deploy a fresh QuoteVerifier (seeded with the witness's pubkey + allow-list)
 *  and call `verify(...)`. Returns contract + tx receipt. */
export async function deployAndVerify(
  wallet: EmbeddedWallet,
  bb: Barretenberg,
  account: AccountManager,
  witness: Witness,
): Promise<{
  contract: QuoteVerifierContract;
  receipt: { status: string; blockNumber?: number; txHash: TxHash };
}> {
  const allowedAttestationHashes = await hashAllowedAttestationsFromWitness(
    bb,
    witness.allowedUrls,
    witness.allowedResponseResolves,
    MAX_URL_LEN,
    MAX_RR_LEN,
  );
  const initialAttestor = { x: witness.publicKeyX, y: witness.publicKeyY };

  const { contract } = await QuoteVerifierContract.deploy(
    wallet,
    allowedAttestationHashes,
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

/** Read `historical_quotes[timestamp]` via the public view. Reverts if no
 *  quote was recorded at that timestamp. */
export async function readQuoteAt(
  contract: QuoteVerifierContract,
  caller: AccountManager,
  timestamp: bigint,
): Promise<{ price: bigint; timestamp: bigint }> {
  const sim = await contract.methods
    .get_quote_at(timestamp)
    .simulate({ from: caller.address });
  return sim.result as { price: bigint; timestamp: bigint };
}

/** Fetch QuoteRecorded events from a tx. One per new slot init; duplicates
 *  don't re-emit. */
export async function fetchQuoteRecordedEvents(
  contract: QuoteVerifierContract,
  txHash: TxHash,
): Promise<Array<{ event: { price: bigint; timestamp: bigint } }>> {
  const node = createAztecNodeClient(NODE_URL);
  const { events } = await getPublicEvents<{
    price: bigint;
    timestamp: bigint;
  }>(node, QuoteVerifierContract.events.QuoteRecorded, {
    txHash,
    contractAddress: contract.address,
  });
  return events;
}
