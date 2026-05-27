import { keccak_256 } from "@noble/hashes/sha3";
import { secp256k1 } from "@noble/curves/secp256k1";
import type { AttestationData, AttestationRequest, PrivateDataEntry } from "./types";

export function encodePacked(publicData: AttestationData): number[] {
  const out: number[] = [];

  out.push(...Buffer.from(publicData.recipient.slice(2), "hex"));

  if (Array.isArray(publicData.request)) {
    const requestConcat = publicData.request
      .map((req) => req.url + req.header + req.method + req.body)
      .join("");
    out.push(...keccak_256(Buffer.from(requestConcat, "utf8")));
  } else {
    const req = publicData.request;
    out.push(...keccak_256(Buffer.from(req.url + req.header + req.method + req.body, "utf8")));
  }

  if (Array.isArray(publicData.responseResolves)) {
    const responseConcat = publicData.responseResolves
      .flatMap((r) => r.oneUrlResponseResolve)
      .map((rr) => rr.keyName + rr.parseType + rr.parsePath)
      .join("");
    out.push(...keccak_256(Buffer.from(responseConcat, "utf8")));
  } else {
    const rr = publicData.responseResolves.oneUrlResponseResolve[0]!;
    out.push(...keccak_256(Buffer.from(rr.keyName + rr.parseType + rr.parsePath, "utf8")));
  }

  out.push(...Buffer.from(publicData.data, "utf8"));
  out.push(...Buffer.from(publicData.attConditions, "utf8"));

  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(publicData.timestamp));
  out.push(...buf);

  out.push(...Buffer.from(publicData.additionParams, "utf8"));

  return out;
}

export function parseSignature(signatureHex: string) {
  const sigHex = signatureHex.startsWith("0x") ? signatureHex.slice(2) : signatureHex;
  const sigBytes = Buffer.from(sigHex, "hex");

  if (sigBytes.length !== 65) {
    throw new Error(`Invalid signature length: expected 65 bytes, got ${sigBytes.length}`);
  }

  const r = BigInt("0x" + sigBytes.slice(0, 32).toString("hex"));
  const s = BigInt("0x" + sigBytes.slice(32, 64).toString("hex"));
  let v = sigBytes[64]!;

  if (v === 27 || v === 28) v -= 27;

  const sig = new secp256k1.Signature(r, s).addRecoveryBit(v);
  return { sig, compactBytes: Array.from(sig.toCompactRawBytes()) };
}

export function recoverPublicKey(
  sig: InstanceType<typeof secp256k1.Signature>,
  messageHash: Uint8Array,
): { x: number[]; y: number[] } {
  const pubkey = sig.recoverPublicKey(messageHash);
  const pubBytes = pubkey.toRawBytes(false);

  if (pubBytes[0] !== 0x04) {
    throw new Error("Expected uncompressed public key format");
  }

  return {
    x: Array.from(pubBytes.slice(1, 33)),
    y: Array.from(pubBytes.slice(33, 65)),
  };
}

export function parseRequestUrls(
  requests: AttestationRequest | AttestationRequest[],
  maxResponseNum: number,
): number[][] {
  const requestArray = Array.isArray(requests) ? requests : [requests];

  if (requestArray.length > maxResponseNum) {
    throw new Error(`Request length (${requestArray.length}) exceeds maxResponseNum (${maxResponseNum})`);
  }

  const requestUrls: number[][] = [];
  for (const req of requestArray) {
    const urlBytes = Array.from(new TextEncoder().encode(req.url));
    requestUrls.push(urlBytes);
  }

  const lastElement = requestUrls[requestUrls.length - 1]!;
  while (requestUrls.length < maxResponseNum) {
    requestUrls.push([...lastElement]);
  }

  return requestUrls;
}

export function parseAllowedUrls(allowedUrls: string[]): number[][] {
  return allowedUrls.map((url) => Array.from(new TextEncoder().encode(url)));
}

export function padUrl(url: number[], targetLength: number): number[] {
  const paddedUrl = [...url];
  while (paddedUrl.length < targetLength) {
    paddedUrl.push(0);
  }
  return paddedUrl;
}

export function parseDataHashes(
  attestationDataStr: string,
  privateData: PrivateDataEntry[],
): number[][] {
  const attData = JSON.parse(attestationDataStr);
  return privateData.map((entry) => {
    const hexValue = attData[entry.id];
    if (typeof hexValue !== "string" || hexValue.length !== 64) {
      throw new Error(`Expected 64-char hex for key '${entry.id}', got: ${JSON.stringify(hexValue)}`);
    }
    return Array.from(Buffer.from(hexValue, "hex"));
  });
}

export function parsePlainJsonResponses(privateData: PrivateDataEntry[]): number[][] {
  return privateData.map((entry) => Array.from(new TextEncoder().encode(entry.content)));
}

export function bytesToBigInt(bytes: Uint8Array): bigint {
  return BigInt("0x" + Buffer.from(bytes).toString("hex"));
}

// ---------------------------------------------------------------------------
// Envelope-field extraction (for in-circuit keccak reconstruction).
// Mirrors the byte layout of `encodePacked` above.
// ---------------------------------------------------------------------------

export function parseRecipient(recipientHex: string): number[] {
  const stripped = recipientHex.startsWith("0x") ? recipientHex.slice(2) : recipientHex;
  if (stripped.length !== 40) {
    throw new Error(`Expected 20-byte hex recipient, got ${stripped.length / 2} bytes`);
  }
  return Array.from(Buffer.from(stripped, "hex"));
}

/** `header + method + body` concat for the (single) request. */
export function parseRequestHmb(
  requests: AttestationRequest | AttestationRequest[],
): number[] {
  const requestArray = Array.isArray(requests) ? requests : [requests];
  if (requestArray.length !== 1) {
    throw new Error(`Expected exactly 1 request, got ${requestArray.length}`);
  }
  const req = requestArray[0]!;
  const headerStr = typeof req.header === "string" ? req.header : JSON.stringify(req.header);
  const concat = headerStr + req.method + req.body;
  return Array.from(new TextEncoder().encode(concat));
}

/** `keyName + parseType + parsePath` bytes per response resolve, flat-mapped. */
export function parseResponseResolveStrings(
  responseResolves: AttestationData["responseResolves"],
): number[][] {
  const resolves = Array.isArray(responseResolves) ? responseResolves : [responseResolves];
  return resolves
    .flatMap((r) => r.oneUrlResponseResolve)
    .map((rr) => Array.from(new TextEncoder().encode(rr.keyName + rr.parseType + rr.parsePath)));
}

/** Locate the byte offset in `data` where each entry's 64-char SHA256 hex begins. */
export function parseDataHashOffsets(
  attestationDataStr: string,
  privateData: PrivateDataEntry[],
): number[] {
  const dataBytes = new TextEncoder().encode(attestationDataStr);
  const offsets: number[] = [];
  for (const entry of privateData) {
    // The `data` JSON has shape {"<keyName>":"<64hex>", ...}. Find the keyName's
    // value-quote and take the offset just past it.
    const needle = `"${entry.id}":"`;
    const needleBytes = new TextEncoder().encode(needle);
    const idx = indexOfSubarray(dataBytes, needleBytes);
    if (idx < 0) {
      throw new Error(`Could not locate hash for keyName '${entry.id}' inside envelope data`);
    }
    offsets.push(idx + needleBytes.length);
  }
  return offsets;
}

function indexOfSubarray(haystack: Uint8Array, needle: Uint8Array): number {
  if (needle.length === 0 || haystack.length < needle.length) return -1;
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}
