import { PrimusNetwork, type ResponseResolve } from "@primuslabs/network-core-sdk";
import { ethers } from "ethers";
import fs from "node:fs";
import path from "node:path";
import "dotenv/config";
import { prepareWitness, formatWitnessJson } from "./prepare-witness";
import { loadClaim } from "./load-claim";

type NetworkConfig = { chainId: number; rpcUrl: string };

const ROOT = path.resolve(__dirname, "..");

function requireEnv(name: string): string {
  const v = process.env[name]?.trim();
  if (!v) throw new Error(`Missing ${name} in .env`);
  return v;
}

function loadJson<T>(p: string): T {
  return JSON.parse(fs.readFileSync(p, "utf8")) as T;
}

function buildAttestationFile(
  attestEntry: import("@primuslabs/network-core-sdk").AttestEntry,
  privateData: Array<{ id: string; content: string }>,
) {
  return {
    verification_type: ["HASH_COMPARISON"],
    public_data: [
      {
        attestation: attestEntry.attestation,
        signature: attestEntry.signature,
      },
    ],
    private_data: privateData,
  };
}

function parseParams(args: string[]): Record<string, string> {
  const params: Record<string, string> = {};
  for (const arg of args) {
    const eq = arg.indexOf("=");
    if (eq <= 0) throw new Error(`Bad arg '${arg}'. Use key=value.`);
    params[arg.slice(0, eq)] = arg.slice(eq + 1);
  }
  return params;
}

const VALID_MODES = ["proxytls", "mpctls"] as const;
type AttMode = (typeof VALID_MODES)[number];

async function main() {
  const providerName = process.argv[2] ?? "okx";
  const allParams = parseParams(process.argv.slice(3));

  // `mode` is a flag, not a template param — pluck it out before interpolation.
  const { mode: modeOverride, ...templateParams } = allParams;
  if (modeOverride && !VALID_MODES.includes(modeOverride as AttMode)) {
    throw new Error(`Invalid mode '${modeOverride}'. Use one of: ${VALID_MODES.join(", ")}`);
  }

  const networkName = process.env.NETWORK?.trim() ?? "baseSepolia";
  const privateKey = requireEnv("PRIVATE_KEY");

  const networks = loadJson<Record<string, NetworkConfig>>(path.join(ROOT, "config.json"));
  const net = networks[networkName];
  if (!net) {
    throw new Error(`Unknown NETWORK '${networkName}'. Available: ${Object.keys(networks).join(", ")}`);
  }

  const claim = loadClaim(providerName, templateParams);

  const attMode: { algorithmType: AttMode } = modeOverride
    ? { algorithmType: modeOverride as AttMode }
    : (claim.attMode as { algorithmType: AttMode } | undefined) ?? { algorithmType: "mpctls" };

  const provider = new ethers.providers.JsonRpcProvider(net.rpcUrl);
  const wallet = new ethers.Wallet(privateKey, provider);
  const address = wallet.address;

  console.log(`[zktls] claim:   ${claim.name}`);
  console.log(`[zktls] network: ${networkName} (chainId=${net.chainId})`);
  console.log(`[zktls] address: ${address}`);
  console.log(`[zktls] mode:    ${attMode.algorithmType}${modeOverride ? " (cli override)" : ""}`);

  const primus = new PrimusNetwork();
  await primus.init(wallet, net.chainId);

  const submitParams = { address };
  const submitResult = await primus.submitTask(submitParams);
  console.log("[zktls] submitTask:", submitResult);

  const attestResult = await primus.attest({
    ...submitParams,
    ...submitResult,
    requests: claim.requests,
    responseResolves: claim.responseResolves,
    attMode,
    getAllJsonResponse: "true",
  });
  console.log("[zktls] attest:", JSON.stringify(attestResult, null, 2));

  const first = attestResult[0];
  if (!first) throw new Error("attest returned no entries");

  const taskResult = await primus.verifyAndPollTaskResult({
    taskId: first.taskId,
    reportTxHash: first.reportTxHash,
  });
  console.log("[zktls] task result:", JSON.stringify(taskResult, null, 2));

  const allJsonResponse = primus.getAllJsonResponse(first.taskId);
  console.log("[zktls] allJsonResponse:", JSON.stringify(allJsonResponse, null, 2));

  const attData = JSON.parse(first.attestation.data) as Record<string, string>;
  const dataKeys = Object.keys(attData);

  const flatResolves: Array<{ rr: ResponseResolve; urlIdx: number }> = [];
  claim.responseResolves.forEach((urlResolves, urlIdx) => {
    urlResolves.forEach((rr) => flatResolves.push({ rr, urlIdx }));
  });

  if (dataKeys.length !== flatResolves.length) {
    throw new Error(
      `Mismatch: attestation.data has ${dataKeys.length} keys (${dataKeys.join(", ")}), ` +
        `claim has ${flatResolves.length} responseResolves.`,
    );
  }

  const privateData = dataKeys.map((dataKey, i) => {
    const { rr, urlIdx } = flatResolves[i]!;
    const content = primus.getPlainResponse(first.taskId, urlIdx, rr.parsePath);
    return { id: dataKey, content };
  });
  console.log("[zktls] private_data:", JSON.stringify(privateData, null, 2));

  const outDir = path.join(ROOT, "attestations");
  fs.mkdirSync(outDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const base = path.join(outDir, `${claim.name}-${stamp}`);

  const fullPath = `${base}.full.json`;
  fs.writeFileSync(
    fullPath,
    JSON.stringify(
      {
        claim: claim.name,
        network: networkName,
        chainId: net.chainId,
        submitResult,
        attestResult,
        taskResult,
        allJsonResponse,
      },
      null,
      2,
    ),
  );
  console.log(`[zktls] saved full -> ${path.relative(ROOT, fullPath)}`);

  const attestationFile = buildAttestationFile(first, privateData);
  const rawPath = `${base}.raw.json`;
  fs.writeFileSync(rawPath, JSON.stringify(attestationFile, null, 2));
  console.log(`[zktls] saved raw  -> ${path.relative(ROOT, rawPath)}`);

  try {
    const witness = prepareWitness(rawPath, claim);
    const witnessPath = `${base}.witness.json`;
    fs.writeFileSync(witnessPath, formatWitnessJson(witness));
    console.log(`[zktls] saved witness -> ${path.relative(ROOT, witnessPath)}`);
  } catch (err) {
    console.warn("[zktls] WARN: prepareWitness failed. Raw attestation saved; re-run prepare-witness after inspecting.");
    console.warn(err);
  }
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
