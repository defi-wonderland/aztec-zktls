import fs from "node:fs";
import path from "node:path";
import type {
  AttestRequest,
  ResponseResolve,
} from "@primuslabs/network-core-sdk";

const HERE = import.meta.dirname;

export type { AttestRequest, ResponseResolve };

export type ClaimVerifier = {
  maxResponseNum: number;
  maxUrlLen: number;
  allowedUrls: string[];
  allowedResponseResolves: string[];
};

export type Claim = {
  name: string;
  requests: AttestRequest[];
  responseResolves: ResponseResolve[][];
  attMode?: { algorithmType: "mpctls" | "proxytls" };
  verifier: ClaimVerifier;
};

/** Walk a parsed JSON value and substitute `{key}` placeholders inside any
 *  string leaf with `params[key]`. Operating on the parsed structure (not the
 *  raw JSON text) means a value containing `"`, `\`, or newlines can't escape
 *  its string slot and inject extra fields. */
function deepInterpolate<T>(value: T, params: Record<string, string>): T {
  if (typeof value === "string") {
    return value.replace(/\{(\w+)\}/g, (_, k) => {
      if (!(k in params)) {
        throw new Error(
          `Missing param '${k}'. Pass it on the CLI as ${k}=<value>.`,
        );
      }
      return params[k]!;
    }) as T;
  }
  if (Array.isArray(value)) {
    return value.map((v) => deepInterpolate(v, params)) as T;
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, deepInterpolate(v, params)]),
    ) as T;
  }
  return value;
}

/**
 * Read the provider's claim file + the shared verifier config, interpolate
 * `{key}` placeholders from `params`, and merge the verifier into the claim.
 */
export function loadClaim(
  providerName: string,
  params: Record<string, string>,
): Claim {
  const claimPath = path.join(HERE, "providers", providerName, "claim.json");
  if (!fs.existsSync(claimPath)) {
    throw new Error(
      `No claim found for provider '${providerName}'. Expected: ${path.relative(process.cwd(), claimPath)}`,
    );
  }
  const verifierPath = path.join(HERE, "providers", "verifier.json");
  if (!fs.existsSync(verifierPath)) {
    throw new Error(
      `Shared verifier config missing at ${path.relative(process.cwd(), verifierPath)}`,
    );
  }

  const claimRaw = fs.readFileSync(claimPath, "utf8");
  const verifierRaw = fs.readFileSync(verifierPath, "utf8");

  const claimBody = deepInterpolate(JSON.parse(claimRaw), params) as Omit<
    Claim,
    "verifier"
  >;
  const verifier = deepInterpolate(
    JSON.parse(verifierRaw),
    params,
  ) as ClaimVerifier & { _comment?: string };
  delete verifier._comment;

  return { ...claimBody, verifier };
}
