# aztec-zktls — Primus zkTLS quote PoC on Aztec

End-to-end demo of consuming an off-chain HTTPS data point inside an Aztec contract:

```
exchange ticker URL → Primus attestor (MPC-TLS or proxy-TLS) → signed envelope
        → off-chain Noir witness prep → Aztec contract verify → on-chain storage
```

The contract verifies an ECDSA signature over the envelope and a SHA256 binding to the attested price, then records the normalized `Quote { price, timestamp }` to storage (readable from public AND private context).

For design rationale:
- Lib internals + divergences from upstream Primus lib → [`src/nr/attestation_verifier/README.md`](./src/nr/attestation_verifier/README.md)
- QuoteVerifier example (allow-list, parsing, trust model, limitations) → [`src/nr/examples/README.md`](./src/nr/examples/README.md)

## Prerequisites

- Node ≥ 22, yarn
- Aztec CLI 4.3.0 (`.aztecrc` pins it; `aztec-up install 4.3.0` if missing)
- Base Sepolia wallet with a few cents of ETH for `submitTask` gas

Faucet → Bridge: [pk910 PoW faucet](https://sepolia-faucet.pk910.de/) → [Superbridge](https://superbridge.app/base-sepolia).

## Setup

```bash
cp .env.example .env       # paste PRIVATE_KEY of your Base Sepolia wallet
yarn install
yarn ccc                   # clean + compile Noir + codegen TS bindings
```

## Generate an attestation

```bash
yarn attest binance  symbol=ETHUSDT             # uses claim's default mode (mpctls)
yarn attest okx      symbol=ETH-USDT            # default proxytls (OKX rejects mpctls)
yarn attest coinbase symbol=ETH-USD             # default mpctls

# Override per-call:
yarn attest binance  symbol=ETHUSDT mode=proxytls
```

Each run writes `attestations/<claim>-<ts>.{full,raw,witness}.json`:

- `full.json` — entire SDK output (submitTask + attest + verifyAndPollTaskResult)
- `raw.json` — `AttestationFile` shape the parser consumes
- `witness.json` — Noir witness inputs ready for the contract

Provider details in the [examples README](./src/nr/examples/README.md#providers).

## Verify on-chain

```bash
# Terminal A:
aztec start --local-network

# Terminal B:
yarn test:js       # cached-witness suite (offline, no Primus call)
yarn test:e2e      # cached + live E2E (real Primus attestation, costs gas)
```

`yarn test:js` uses the committed fixture at `src/ts/fixtures/binance-ETHUSDT.witness.json` by default. Override with `WITNESS_FILE=<path>` or `WITNESS_PROVIDER=binance-` (picks the most recent matching file in `attestations/`).

`yarn test:e2e` (gated by `RUN_E2E=1`) spawns `yarn attest` for two empirically-working cases — Binance+mpctls and Coinbase+proxytls — then verifies each. Requires a funded `PRIVATE_KEY` in `.env` and the local network running.

## Benchmarks

```bash
yarn bench
```

Cached baseline: `benchmarks/quote_verifier_base.benchmark.json`.

## Layout

```
.
├── README.md
├── package.json                                all scripts (attest, ccc, test:*, bench)
├── .aztecrc                                    pins aztec CLI 4.3.0
├── Nargo.toml                                  Noir workspace
├── config.json                                 Base Sepolia + Base mainnet RPCs
├── benchmarks/                                 aztec-benchmark suite + cached baseline
└── src/
    ├── nr/
    │   ├── attestation_verifier/               lib (modified from primus-labs/zktls-verification-noir)
    │   └── examples/
    │       ├── quote_verifier/                 ticker price verifier (Binance/OKX/Coinbase)
    │       ├── zktls_klines_oracle/            Binance klines oracle (admin-managed)
    │       └── zktls_option_escrow/            option escrow gated by the klines oracle
    └── ts/
        ├── attest.ts                           Primus pipeline → 3 JSONs
        ├── prepare-witness.ts                  raw.json → witness.json
        ├── load-claim.ts
        ├── attestation-verifier-parsing/       vendored Primus TS parser
        ├── providers/                          shared verifier.json + per-provider claims
        ├── utils.ts                            hashing + deploy/verify helpers
        ├── fixtures/                           committed witness for offline tests
        ├── quote-verifier.test.ts              cached-witness suite
        └── quote-verifier.e2e.test.ts          live Primus suite (RUN_E2E=1)
```
