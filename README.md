# aztec-zktls-poc — Primus zkTLS quote PoC on Aztec

End-to-end demo of consuming an off-chain HTTPS data point inside an Aztec contract:

```
exchange ticker URL → Primus attestor (MPC-TLS or proxy-TLS) → signed envelope
        → off-chain Noir witness prep → Aztec contract verify → on-chain event
```

The Aztec contract verifies an ECDSA secp256k1 signature over the envelope and a SHA256 binding to the attested price plaintext, then records the normalized price into on-chain storage (readable from both public and private contracts).

This README covers prerequisites, setup, the available scripts, and the repo layout. For the *why* behind the design:

- **Verifier lib internals, divergences from upstream Primus lib, the splice-attack closure** → [`src/nr/attestation_verifier/README.md`](./src/nr/attestation_verifier/README.md)
- **QuoteVerifier example: provider table, data-model choices, trust model** → [`src/nr/examples/README.md`](./src/nr/examples/README.md)

## Prerequisites

- Node ≥ 22, yarn
- Aztec CLI 4.3.0 (`.aztecrc` pins it; `aztec-up install 4.3.0` if missing)
- A Base Sepolia wallet with a small amount of ETH for `submitTask` gas

### Getting Base Sepolia ETH

1. Claim Sepolia ETH on L1 from the pk910 PoW faucet: <https://sepolia-faucet.pk910.de/>
2. Bridge it to Base Sepolia: <https://superbridge.app/base-sepolia>

Pace yourself — one Primus task costs only a few cents in gas, but the faucet rate-limits.

## Setup

```bash
cp .env.example .env       # paste PRIVATE_KEY of your Base Sepolia wallet
yarn install
yarn ccc                   # clean + compile Noir + codegen TS bindings
```

## Generate a quote attestation

```bash
yarn attest binance  symbol=ETHUSDT                # uses claim's mode (mpctls)
yarn attest okx      symbol=ETH-USDT               # uses claim's mode (proxytls — mpctls rejected)
yarn attest coinbase symbol=ETH-USD                # uses claim's mode (mpctls)

# Override the TLS mode per-call (handy when one provider's mpctls handshake fails):
yarn attest binance  symbol=ETHUSDT mode=proxytls
yarn attest okx      symbol=ETH-USDT  mode=mpctls
```

Each run writes three files to `attestations/<claim>-<timestamp>.{full,raw,witness}.json`:

- `full.json` — everything the SDK gave us (submitTask + attest + verifyAndPollTaskResult + raw response)
- `raw.json` — the `AttestationFile` shape the parser consumes (`public_data` + `private_data` + `signature`)
- `witness.json` — Noir witness inputs ready to feed into the Aztec contract

The three supported providers and their TLS-mode quirks are documented in the [examples README](./src/nr/examples/README.md#providers).

## Verify on-chain

```bash
# Terminal A: start a local Aztec network (do NOT confuse with --sandbox)
aztec start --local-network

# Terminal B (at repo root):
yarn test:js       # cached-witness suite (fast, no Primus call)
yarn test:e2e      # also runs the live E2E suite (real Primus attestation)
```

### `yarn test:js` — cached-witness suite

Defaults to the committed fixture at `src/ts/fixtures/binance-ETHUSDT.witness.json`. Override with `WITNESS_FILE=<path>` (specific witness) or `WITNESS_PROVIDER=binance-` (latest matching from `attestations/`). For each run, the test:

1. connects to `localhost:8080`
2. loads the chosen witness
3. derives `allowed_url_hashes` directly from `witness.allowedUrls` — the same 3 URLs across every claim because of the shared `verifier.json`
4. extracts the attestor's secp256k1 pubkey from `witness.publicKeyX/Y` (the same key Primus signed with)
5. deploys `QuoteVerifier` with the 3 URL hashes + the attestor pubkey (both `PublicImmutable`)
6. calls `verify(...)` with the witness
7. asserts the receipt is successful **and** calls `get_latest_quote()` to read the recorded `Quote { price, timestamp }` back from storage

Because the storage hashes are the same for every provider's witness (they all reference the same shared allow-list), one deployed contract instance verifies attestations from any of the 3 providers.

### `yarn test:e2e` — live attestation suite

Same flow as above, but step 2 is replaced by **spawning `yarn attest <provider> symbol=<sym> mode=<mpctls|proxytls>` as a subprocess** to request a fresh Primus attestation right before the test runs. Two cases run back-to-back, each pairing a provider with the TLS mode its attestor accepts:

| Case | Provider | Symbol | Mode |
|---|---|---|---|
| 1 | Binance | `ETHUSDT` | `mpctls` (private MPC-TLS handshake) |
| 2 | Coinbase | `ETH-USD` | `proxytls` (attestor as TLS proxy) |

Primus's attestor refuses some `(provider, mode)` combinations in practice — notably `proxytls` against Binance and `mpctls` against OKX. The two cases here are ones we've empirically confirmed work. Both produce envelopes the same `QuoteVerifier` contract verifies identically; the difference is only in what the off-chain attestor sees of the request.

Requires:

- `.env` with a funded Base Sepolia `PRIVATE_KEY` (the attest subprocesses pay gas, twice)
- `aztec start --local-network` running on `localhost:8080`

The e2e suite is gated by `RUN_E2E=1` so default `yarn test:js` stays cheap and offline. `yarn test:e2e` sets that env var for you.

## Benchmarks

```bash
yarn bench                  # runs Noir circuit benchmarks via aztec-benchmark
```

Cached results are committed at `benchmarks/quote_verifier_base.benchmark.json`.

## Layout

```
.
├── README.md                                   you are here — setup, scripts, layout
├── package.json                                all scripts (attest, ccc, test:js, test:e2e, bench, …)
├── tsconfig.json
├── vitest.config.ts
├── .aztecrc                                    pins aztec CLI 4.3.0
├── Nargo.toml                                  Noir workspace
├── config.json                                 Base Sepolia + Base mainnet RPC config
├── benchmarks/                                 aztec-benchmark suite + cached results
└── src/
    ├── nr/                                     Noir source
    │   ├── attestation_verifier/               lib: Primus zkTLS verifier (modified from primus-labs/zktls-verification-noir)
    │   │   └── README.md                       lib design + divergences from upstream
    │   └── examples/
    │       ├── README.md                       per-example design notes + trust model
    │       └── quote_verifier/                 example Aztec contract using the lib
    └── ts/
        ├── attest.ts                           runs Primus pipeline, writes 3 JSONs
        ├── prepare-witness.ts                  rebuilds witness.json from raw.json
        ├── load-claim.ts                       merges per-provider claim + shared verifier
        ├── attestation-verifier-parsing/       local copy of Primus's TS parser (vendored from upstream's att_verifier_parsing/)
        ├── providers/
        │   ├── verifier.json                   ← shared: mode/maxes/allowedUrls (all 3 providers)
        │   ├── binance/claim.json
        │   ├── okx/claim.json
        │   └── coinbase/claim.json
        ├── utils.ts                            hashing helpers + deploy/verify/event helpers
        ├── fixtures/                           committed witness for offline `yarn test:js`
        ├── quote-verifier.test.ts              cached-witness suite
        └── quote-verifier.e2e.test.ts          live Primus attestation suite (RUN_E2E=1)
```
