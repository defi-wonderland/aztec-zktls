import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseHashingData } from "./attestation-verifier-parsing";
import type {
  AttestationFile,
  ParsedHashingData,
} from "./attestation-verifier-parsing/types";
import { loadClaim, type Claim } from "./load-claim";

const ROOT = path.resolve(import.meta.dirname, "..", "..");

function loadJson<T>(p: string): T {
  return JSON.parse(fs.readFileSync(p, "utf8")) as T;
}

function bigintReplacer(_key: string, value: unknown) {
  return typeof value === "bigint" ? value.toString() : value;
}

/**
 * Pretty-print with collapsed inner number arrays (so 32-byte hash arrays etc.
 * stay on one line). Keeps the witness file readable without blowing it up
 * vertically.
 */
export function formatWitnessJson(obj: unknown): string {
  const pretty = JSON.stringify(obj, bigintReplacer, 2);
  // Matches a JSON array containing only numbers (possibly multi-line from
  // pretty-print). Requires a comma between consecutive numbers, which removes
  // the ambiguity that made the previous greedy form ReDoS-prone.
  return pretty.replace(/\[\s*(?:-?\d+(?:\s*,\s*-?\d+)*\s*)?\]/g, (match) => {
    const nums = match.match(/-?\d+/g) ?? [];
    return `[${nums.join(", ")}]`;
  });
}

function resolveAttestationFile(input: unknown): AttestationFile {
  if (
    input &&
    typeof input === "object" &&
    "public_data" in (input as Record<string, unknown>) &&
    "private_data" in (input as Record<string, unknown>)
  ) {
    return input as AttestationFile;
  }
  throw new Error(
    "Could not find AttestationFile shape (expected fields: public_data[], private_data). " +
      "Pass the .raw.json file produced by generate-proof, not the .full.json wrapper.",
  );
}

export function prepareWitness(
  rawAttestationPath: string,
  claim: Claim,
): ParsedHashingData {
  const attestation = loadJson<AttestationFile>(rawAttestationPath);
  resolveAttestationFile(attestation);

  return parseHashingData(attestation, {
    maxResponseNum: claim.verifier.maxResponseNum,
    maxUrlLen: claim.verifier.maxUrlLen,
    allowedUrls: claim.verifier.allowedUrls,
    allowedResponseResolves: claim.verifier.allowedResponseResolves,
  });
}

/**
 * Filename pattern: "<provider>-<symbol>-<ISO-timestamp>.raw.json", e.g.
 * "okx-ETH-USDT-2026-06-01T12-53-43-147Z.raw.json". Split on `-` doesn't work
 * for hyphenated symbols ("ETH-USDT", "ETH-USD"); the ISO timestamp always
 * starts with a 4-digit year, so anchor the symbol capture there.
 */
function parseRawFilename(
  basename: string,
): { provider: string; symbol: string } | null {
  const m = basename.match(/^([^-]+)-(.+)-(\d{4}-\d{2}-\d{2}T.+)\.raw\.json$/);
  if (!m) return null;
  return { provider: m[1]!, symbol: m[2]! };
}

function main() {
  const rawPath = process.argv[2];
  if (!rawPath) {
    throw new Error(
      "Usage: prepare-witness <path-to-.raw.json> [provider] [key=value ...]",
    );
  }
  const absRaw = path.isAbsolute(rawPath)
    ? rawPath
    : path.join(process.cwd(), rawPath);
  if (!absRaw.endsWith(".raw.json")) {
    throw new Error(`Expected input file ending in .raw.json, got: ${rawPath}`);
  }

  const parsed = parseRawFilename(path.basename(rawPath));
  const rest = process.argv.slice(3);
  const providerName =
    rest.length > 0 && !rest[0]!.includes("=")
      ? rest.shift()!
      : (parsed?.provider ?? "");
  if (!providerName) {
    throw new Error(
      `Could not infer provider from filename '${path.basename(rawPath)}'; pass it as the second arg.`,
    );
  }

  const params: Record<string, string> = {};
  for (const kv of rest) {
    const [k, ...v] = kv.split("=");
    if (!k || v.length === 0) throw new Error(`Bad key=value arg: ${kv}`);
    params[k] = v.join("=");
  }
  if (!params.symbol && parsed?.symbol) params.symbol = parsed.symbol;

  const claim = loadClaim(providerName, params);

  console.log(`[prepare-witness] claim:    ${claim.name}`);
  console.log(`[prepare-witness] provider: ${providerName}`);
  console.log(`[prepare-witness] input:    ${path.relative(ROOT, absRaw)}`);

  const witness = prepareWitness(absRaw, claim);

  const witnessPath = absRaw.replace(/\.raw\.json$/, ".witness.json");
  fs.writeFileSync(witnessPath, formatWitnessJson(witness));
  console.log(`[prepare-witness] saved -> ${path.relative(ROOT, witnessPath)}`);
}

if (process.argv[1] && process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
}
