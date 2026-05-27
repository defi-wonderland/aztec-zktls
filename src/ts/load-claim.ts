import fs from "node:fs";
import path from "node:path";
import type { AttestRequest, ResponseResolve } from "@primuslabs/network-core-sdk";

const ROOT = path.resolve(__dirname, "..");

export type { AttestRequest, ResponseResolve };

export type ClaimVerifier = {
  maxResponseNum: number;
  maxUrlLen: number;
  allowedUrls: string[];
};

export type Claim = {
  name: string;
  requests: AttestRequest[];
  responseResolves: ResponseResolve[][];
  attMode?: { algorithmType: "mpctls" | "proxytls" };
  verifier: ClaimVerifier;
};

function interpolate(template: string, params: Record<string, string>): string {
  return template.replace(/\{(\w+)\}/g, (_, k) => {
    if (!(k in params)) {
      throw new Error(`Missing param '${k}'. Pass it on the CLI as ${k}=<value>.`);
    }
    return params[k]!;
  });
}

/**
 * Read the provider's claim file + the shared verifier config, interpolate
 * `{key}` placeholders from `params`, and merge the verifier into the claim.
 */
export function loadClaim(providerName: string, params: Record<string, string>): Claim {
  const claimPath = path.join(ROOT, "src", "providers", providerName, "claim.json");
  if (!fs.existsSync(claimPath)) {
    throw new Error(`No claim found for provider '${providerName}'. Expected: ${path.relative(ROOT, claimPath)}`);
  }
  const verifierPath = path.join(ROOT, "src", "providers", "verifier.json");
  if (!fs.existsSync(verifierPath)) {
    throw new Error(`Shared verifier config missing at ${path.relative(ROOT, verifierPath)}`);
  }

  const claimRaw = fs.readFileSync(claimPath, "utf8");
  const verifierRaw = fs.readFileSync(verifierPath, "utf8");

  const claimBody = JSON.parse(interpolate(claimRaw, params)) as Omit<Claim, "verifier">;
  const verifier = JSON.parse(interpolate(verifierRaw, params)) as ClaimVerifier & { _comment?: string };
  delete verifier._comment;

  return { ...claimBody, verifier };
}
