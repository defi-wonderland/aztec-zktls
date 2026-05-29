import {
  parseSignature,
  recoverPublicKey,
  parseRequestUrls,
  parseAllowedUrls,
  parsePlainJsonResponses,
  parseRecipient,
  parseRequestHmb,
  parseResponseResolveStrings,
  parseDataHashOffsets,
  encodePacked,
} from "./utils";
import { keccak_256 } from "@noble/hashes/sha3";
import type { AttestationFile, ParseConfig, ParsedHashingData } from "./types";

export function parseHashingData(
  attestationData: AttestationFile,
  config: ParseConfig,
): ParsedHashingData {
  const publicData = attestationData.public_data[0]!;
  const publicAttestation = publicData.attestation;

  // We still keccak the envelope off-circuit to recover the attestor's pubkey
  // from the signature. The on-chain circuit re-derives this hash independently
  // (that's the soundness fix); we don't pass it as a witness.
  const packedArr = encodePacked(publicAttestation);
  const msgHash = keccak_256(new Uint8Array(packedArr));

  const { sig, compactBytes } = parseSignature(publicData.signature);
  const pubKey = recoverPublicKey(sig, msgHash);

  const requestUrls = parseRequestUrls(
    publicAttestation.request,
    config.maxResponseNum,
  );
  const allowedUrls = parseAllowedUrls(config.allowedUrls);
  const plainJsonResponses = parsePlainJsonResponses(
    attestationData.private_data,
  );

  // Envelope fields for in-circuit keccak reconstruction.
  const recipient = parseRecipient(publicAttestation.recipient);
  const requestHmb = parseRequestHmb(publicAttestation.request);
  const responseResolves = parseResponseResolveStrings(
    publicAttestation.responseResolves,
  );
  const data = Array.from(new TextEncoder().encode(publicAttestation.data));
  const attConditions = Array.from(
    new TextEncoder().encode(publicAttestation.attConditions),
  );
  const timestamp = String(publicAttestation.timestamp);
  const additionParams = Array.from(
    new TextEncoder().encode(publicAttestation.additionParams),
  );
  const dataHashOffsets = parseDataHashOffsets(
    publicAttestation.data,
    attestationData.private_data,
  );

  return {
    publicKeyX: pubKey.x,
    publicKeyY: pubKey.y,
    signature: compactBytes,
    requestUrls,
    allowedUrls,
    plainJsonResponses,
    recipient,
    requestHmb,
    responseResolves,
    data,
    attConditions,
    timestamp,
    additionParams,
    dataHashOffsets,
    attestationData: JSON.parse(publicAttestation.data),
  };
}

export * from "./types";
export * from "./utils";
