/**
 * Builds a synthetic Primus klines attestation: constructs a well-formed
 * envelope, computes encodePacked → keccak256, signs with an ephemeral
 * secp256k1 keypair. The output matches what `KlinesOracle.verify_klines_attestation`
 * expects, so tests don't need real Primus calls.
 *
 * NOT for use against the deployed contract on Base Sepolia — that contract
 * pins Primus's real attestor pubkey. This is for local-network tests only.
 */
import { keccak_256 } from "@noble/hashes/sha3";
import { sha256 } from "@noble/hashes/sha2";
import { secp256k1 } from "@noble/curves/secp256k1";

import { encodePacked } from "./attestation-verifier-parsing/utils.js";
import type { AttestationData } from "./attestation-verifier-parsing/types.js";

/** Same as klines_oracle/src/types/base_url_prefix.nr::MAX_BASE_URL_LEN. */
const MAX_BASE_URL_LEN = 64;

/** keyName / parseType / parsePath per attested field. Matches the inputs the
 *  oracle would see from a real Primus klines attestation. parseType is empty
 *  because Primus's attestor emits empty parseType in the signed envelope. */
const KLINES_FIELDS = [
  { keyName: "openTime", parseType: "", parsePath: "$.[0][0]" },
  { keyName: "open", parseType: "", parsePath: "$.[0][1]" },
  { keyName: "high", parseType: "", parsePath: "$.[0][2]" },
  { keyName: "low", parseType: "", parsePath: "$.[0][3]" },
  { keyName: "close", parseType: "", parsePath: "$.[0][4]" },
  { keyName: "closeTime", parseType: "", parsePath: "$.[0][6]" },
] as const;

export type KlinesCandlePlaintexts = {
  openTime: bigint; // ms
  open: string; // decimal-string, ≤8 fractional digits
  high: string;
  low: string;
  close: string;
  closeTime: bigint; // ms
};

export type SyntheticInputs = {
  /** Hex (`0x...`) or bigint. Ephemeral secp256k1 signing key for the
   *  test attestor. */
  privateKey: bigint;
  /** 20-byte recipient address, `0x...` hex. Bytes get hashed into the
   *  envelope; value is unconstrained by the contract. */
  recipient: string;
  /** e.g. "https://api.binance.com/api/v3/klines". Stored at deploy as
   *  `base_url_prefix`; the constructed request_url is `baseUrl + query_prefix
   *  + startTime/endTime suffixes`. */
  baseUrl: string;
  symbol: string;
  interval: string;
  startTime: bigint;
  endTime: bigint;
  candle: KlinesCandlePlaintexts;
  /** envelope.timestamp signed by the attestor (ms in Primus's convention). */
  envelopeTimestamp: bigint;
};

export type KlinesWitness = {
  // Deploy-time
  publicKeyX: number[];
  publicKeyY: number[];
  baseUrlPrefix: { bytes: number[]; len: number };

  // Verify-call inputs
  signature: number[]; // 64 bytes, compact r||s
  envelope: {
    recipient: number[];
    request_url: number[];
    request_hmb: number[];
    response_resolves: number[][];
    data: number[];
    att_conditions: number[];
    timestamp: bigint;
    addition_params: number[];
  };
  contents: number[][];
  dataHashOffsets: number[];
  queryPrefix: number[];

  // Useful for assertions
  candlePlaintexts: KlinesCandlePlaintexts;
};

export function buildSyntheticKlinesWitness(
  inputs: SyntheticInputs,
): KlinesWitness {
  // 1. Construct URLs.
  const queryPrefix = `?symbol=${inputs.symbol}&interval=${inputs.interval}&`;
  const requestUrl = `${inputs.baseUrl}${queryPrefix}startTime=${inputs.startTime}&endTime=${inputs.endTime}`;

  // 2. The six attested plaintexts in canonical order.
  const contentStrings = [
    inputs.candle.openTime.toString(),
    inputs.candle.open,
    inputs.candle.high,
    inputs.candle.low,
    inputs.candle.close,
    inputs.candle.closeTime.toString(),
  ];

  // 3. SHA256 each content; stamp the hex into the `data` JSON keyed by keyName.
  const contentHexes = contentStrings.map((c) =>
    Buffer.from(sha256(new TextEncoder().encode(c))).toString("hex"),
  );
  const dataObj: Record<string, string> = {};
  KLINES_FIELDS.forEach((f, i) => {
    dataObj[f.keyName] = contentHexes[i]!;
  });
  const dataStr = JSON.stringify(dataObj);

  // 4. Locate each "<keyName>":"<hex>" in the serialised JSON so the contract
  //    can index past the leading quote to the start of the hex.
  const dataBytes = new TextEncoder().encode(dataStr);
  const dataHashOffsets = KLINES_FIELDS.map((f) => {
    const needle = new TextEncoder().encode(`"${f.keyName}":"`);
    const idx = findSubarray(dataBytes, needle);
    if (idx < 0) {
      throw new Error(`needle for '${f.keyName}' not in data JSON`);
    }
    return idx + needle.length;
  });

  // 5. Constant envelope side-fields.
  const attConditions = "[]";
  const additionParams = '{"algorithmType":"mpctls"}';

  // 6. Build the AttestationData (shape required by encodePacked).
  const attestation: AttestationData = {
    recipient: inputs.recipient,
    request: {
      url: requestUrl,
      header: "",
      method: "GET",
      body: "",
    },
    responseResolves: {
      oneUrlResponseResolve: KLINES_FIELDS.map((f) => ({
        keyName: f.keyName,
        parseType: f.parseType,
        parsePath: f.parsePath,
      })),
    },
    data: dataStr,
    attConditions,
    timestamp: Number(inputs.envelopeTimestamp),
    additionParams,
  };

  // 7. Pack and sign.
  const packed = encodePacked(attestation);
  const msgHash = keccak_256(new Uint8Array(packed));
  const sig = secp256k1.sign(msgHash, inputs.privateKey);
  const signature = Array.from(sig.toCompactRawBytes()); // 64 bytes (r||s)

  // 8. Derive public-key bytes for the contract constructor.
  const pubkey = secp256k1.getPublicKey(inputs.privateKey, false); // uncompressed
  if (pubkey[0] !== 0x04) {
    throw new Error("expected uncompressed pubkey (0x04 prefix)");
  }
  const publicKeyX = Array.from(pubkey.slice(1, 33));
  const publicKeyY = Array.from(pubkey.slice(33, 65));

  // 9. Witness byte buffers as the contract sees them.
  const recipientBytes = Array.from(
    Buffer.from(inputs.recipient.replace(/^0x/, ""), "hex"),
  );
  if (recipientBytes.length !== 20) {
    throw new Error(`recipient must be 20 bytes, got ${recipientBytes.length}`);
  }

  // request_hmb is the request's header + method + body concat. For klines
  // it's "" + "GET" + "" = "GET" (3 bytes).
  const requestHmb = Array.from(new TextEncoder().encode("GET"));

  const responseResolves = KLINES_FIELDS.map((f) =>
    Array.from(new TextEncoder().encode(f.keyName + f.parseType + f.parsePath)),
  );

  const envelope = {
    recipient: recipientBytes,
    request_url: Array.from(new TextEncoder().encode(requestUrl)),
    request_hmb: requestHmb,
    response_resolves: responseResolves,
    data: Array.from(dataBytes),
    att_conditions: Array.from(new TextEncoder().encode(attConditions)),
    timestamp: inputs.envelopeTimestamp,
    addition_params: Array.from(new TextEncoder().encode(additionParams)),
  };

  const contents = contentStrings.map((c) =>
    Array.from(new TextEncoder().encode(c)),
  );

  // 10. BaseUrlPrefix: fixed-length byte buffer + length.
  const baseUrlBytes = new TextEncoder().encode(inputs.baseUrl);
  if (baseUrlBytes.length > MAX_BASE_URL_LEN) {
    throw new Error(
      `baseUrl too long: ${baseUrlBytes.length} > ${MAX_BASE_URL_LEN}`,
    );
  }
  const baseBytes = new Array(MAX_BASE_URL_LEN).fill(0);
  for (let i = 0; i < baseUrlBytes.length; i++) {
    baseBytes[i] = baseUrlBytes[i]!;
  }

  return {
    publicKeyX,
    publicKeyY,
    baseUrlPrefix: { bytes: baseBytes, len: baseUrlBytes.length },
    signature,
    envelope,
    contents,
    dataHashOffsets,
    queryPrefix: Array.from(new TextEncoder().encode(queryPrefix)),
    candlePlaintexts: inputs.candle,
  };
}

function findSubarray(haystack: Uint8Array, needle: Uint8Array): number {
  if (needle.length === 0 || haystack.length < needle.length) return -1;
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

/** Convenience: 8dp-scaled u64 for the price strings, for test assertions. */
export function priceTo8dpU64(decimalString: string): bigint {
  const [intPart, fracPart = ""] = decimalString.split(".");
  if (fracPart.length > 8) {
    throw new Error(`>8 fractional digits in '${decimalString}'`);
  }
  const padded = fracPart.padEnd(8, "0");
  return BigInt(intPart!) * 100_000_000n + BigInt(padded);
}
