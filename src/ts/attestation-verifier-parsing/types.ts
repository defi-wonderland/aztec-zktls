/**
 * Types for attestation data structures
 * Vendored from primus-labs/zktls-verification-noir/att_verifier_parsing
 */

export interface AttestationRequest {
  url: string;
  header: string | Record<string, string>;
  method: string;
  body: string;
}

export interface ResponseResolve {
  keyName: string;
  parseType: string;
  parsePath: string;
}

export interface OneUrlResponseResolves {
  oneUrlResponseResolve: ResponseResolve[];
}

export interface AttestationData {
  recipient: string;
  request: AttestationRequest | AttestationRequest[];
  responseResolves: OneUrlResponseResolves | OneUrlResponseResolves[];
  data: string;
  attConditions: string;
  timestamp: number | string;
  additionParams: string;
}

export interface PublicData {
  attestation: AttestationData;
  signature: string;
}

export interface PrivateDataEntry {
  id: string;
  random?: string[];
  content: string;
}

export interface AttestationFile {
  verification_type: string | string[];
  public_data: PublicData[];
  private_data: PrivateDataEntry[];
}

export interface ParseConfig {
  maxResponseNum: number;
  allowedUrls: string[];
  // Expected `keyName + parseType + parsePath` bytes per allowed URL, parallel
  // to `allowedUrls`. The contract binds (url, response_resolve) pairs in the
  // allow-list so a submitter can't request a different parsePath from the
  // same allow-listed URL and have it recorded as the canonical price.
  allowedResponseResolves: string[];
  maxUrlLen: number;
}

export interface ParsedHashingData {
  publicKeyX: number[]; // used only at deploy to seed allowed_attestor
  publicKeyY: number[]; // same
  signature: number[];
  requestUrls: number[][];
  allowedUrls: number[][];
  allowedResponseResolves: number[][];
  plainJsonResponses: number[][];
  // Envelope fields - the circuit recomputes keccak256(envelope) from these and
  // binds them to the signature. Closes the soundness gap that the upstream lib
  // (which takes `hash` as an opaque witness) leaves open. See
  // primus-labs/zktls-verification-noir#9.
  recipient: number[]; // 20 bytes
  requestHmb: number[]; // header + method + body, for the one request
  responseResolves: number[][]; // keyName + parseType + parsePath bytes, per resolve
  data: number[]; // raw envelope.data utf-8 bytes
  attConditions: number[]; // raw envelope.attConditions utf-8 bytes
  timestamp: string; // u64 as decimal string
  additionParams: number[]; // raw envelope.additionParams utf-8 bytes
  dataHashOffsets: number[]; // offset inside `data` where each content's sha256 hex begins
  attestationData: unknown;
}
