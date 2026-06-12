# aztec-zktls

> Verifying and consuming [Primus Labs](https://primuslabs.xyz) zkTLS attestations inside an Aztec private circuit.

TEE-backed Primus attestors observe HTTPS traffic and sign a structured envelope binding the request URL to a SHA256 hash of the extracted response field. This repo verifies that envelope inside an Aztec contract — secp256k1 over an in-circuit-reconstructed `keccak256(envelope)`, an allow-listed `(URL, parsePath)` pair, the SHA256 binding of each attested field — and exposes the verified result on-chain for downstream consumers.

## Scope

Two parallel workstreams, sharing the same attestation primitives.

### Library — `attestation_verifier`

Adapted from [primus-labs/zktls-verification-noir](https://github.com/primus-labs/zktls-verification-noir) with documented divergences. Exposes three primitives consumers compose:

- `derive_envelope_hash(envelope)` — in-circuit `keccak256` reconstruction from raw envelope fields
- `verify_ecdsa_over_hash(pk_x, pk_y, sig, hash)` — secp256k1 against a storage-pinned attestor pubkey
- `bind_content_hashes(data, contents, offsets)` — asserts each `sha256(content)` hex appears at the witnessed offset inside the signed `data` string

Closes the upstream splice attack ([issue #9](https://github.com/primus-labs/zktls-verification-noir/issues/9)) by binding the hash to the envelope contents in-circuit instead of accepting it as a free witness.

### Spot-price verifier — `quote_verifier`

A generic ticker-price verifier for Binance, OKX, and Coinbase. One deployed contract accepts attestations from all three providers; the (URL, parsePath) allow-list is pinned at deploy as Poseidon2 pair-hashes. Each successful verification parses the attested decimal price into a `u128` (scaled by `PRICE_DECIMALS = 8`) and writes a `Quote { price, timestamp }` to a public `historical_quotes` map readable from both public and private context.

```
exchange ticker URL → Primus attestor (MPC-TLS or proxy-TLS) → signed envelope
       → off-chain Noir witness prep → Aztec private circuit
       → on-chain `historical_quotes` write + `QuoteRecorded` event
```

### Option escrow — `option_escrow` + `klines_oracle`

An American/European option escrow that gates exercise on a zkTLS-attested price. The writer locks the underlying in a per-option escrow address; the buyer pays a premium up front and gets the right to exercise inside the option's window if the attested price hits the strike. Both call and put directions are supported; after the deadline (+ grace for european), the writer reclaims via clawback.

The escrow reads its price feed from a `klines_oracle` contract — a sister verifier specialised for Binance 1-minute OHLC candles with in-circuit timing-window checks. Exercise calls into the oracle directly inside the escrow's `exercise` function — no separate verifier deployment, no event-log scan.

## Setup

```bash
# Install Aztec — https://docs.aztec.network/developers/getting_started
yarn install
yarn ccc   # clean + compile noir + codegen TS bindings
```

## Tests

Each workstream has its own suite. The tests auto-start a local sandbox where applicable; end-to-end tests against `aztec start --local-network` need that running separately.

```bash
yarn test       # noir + ts
yarn test:nr    # noir only
yarn test:js    # ts only (some suites need `aztec start --local-network`)
yarn test:e2e   # ts e2e — gated by RUN_E2E=1, hits Base Sepolia via Primus
```

E2E runs cost a few cents in Base Sepolia testnet gas per attestation.

## Benchmarks

```bash
yarn bench
```

Cached baselines live under `benchmarks/`. CI auto-benchmarks every PR against `dev` and posts a comparison comment.

## Layout (target)

```
src/
├── nr/
│   ├── attestation_verifier/         lib (modified from primus-labs/zktls-verification-noir)
│   └── examples/
│       ├── quote_verifier/           spot-price verifier (Binance/OKX/Coinbase)
│       └── options/
│           ├── klines_oracle/        Binance 1-minute candle oracle
│           └── option_escrow/        american/european option escrow gated on klines_oracle
└── ts/
    ├── attest.ts                     drives the Primus SDK → witness JSON
    ├── prepare-witness.ts            raw.json → witness.json (no Primus call)
    ├── attestation-verifier-parsing/ vendored Primus TS parser
    ├── providers/                    per-provider claim + shared verifier config
    └── *.test.ts                     unit + integration + e2e suites
```
