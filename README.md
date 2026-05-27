# aztec-zktls-poc — Primus zkTLS quote PoC on Aztec

End-to-end demo of consuming an off-chain HTTPS data point inside an Aztec contract:

```
exchange ticker URL → Primus attestor (MPC-TLS or proxy-TLS) → signed envelope
        → off-chain Noir witness prep → Aztec contract verify → on-chain event
```

The Aztec contract verifies an ECDSA secp256k1 signature over the envelope and a SHA256 binding to the attested price plaintext, then emits a `QuoteVerified` event.

## Providers

Three exchange ticker endpoints, all attest a single `price` field. **One deployed `QuoteVerifier` accepts attestations from any of the three providers** — the shared allow-list (`src/ts/providers/verifier.json`) lists all 3 provider+symbol URLs as the contract's `allowed_url_hashes`.

| Provider | Request URL template | Path | Default mode |
|---|---|---|---|
| Binance  | `api.binance.com/api/v3/ticker/price?symbol={symbol}` | `$.price` | mpctls |
| OKX      | `www.okx.com/api/v5/market/ticker?instId={symbol}` | `$.data[0].last` | mpctls (proxytls if rejected) |
| Coinbase | `api.coinbase.com/v2/prices/{symbol}/spot` | `$.data.amount` | mpctls |

To switch the supported asset (e.g. BTC instead of ETH), edit `src/ts/providers/verifier.json` so all 3 allowed URLs reflect the new symbol, then redeploy. The contract pins URL hashes and the attestor pubkey as `PublicImmutable` — there are no admin update functions; it's a fresh deploy each time.

## Design choices

Why each knob is set to what it is. Some constants are hard constraints from `att_verifier_lib`'s function signature ([primus-labs/zktls-verification-noir](https://github.com/primus-labs/zktls-verification-noir)) — you cannot change them without forking the lib. The rest is judgement.

### Hard constraints (set by the Primus lib)

| Constant | Value | Why |
|---|---|---|
| `NUM_REQUEST_URLS` | **1** | Hardcoded in the signature of `verify_attestation_hashing`. Upstream pins it at 2 (designed for multi-URL fan-out); our local copy drops it to 1 since we only ever make one HTTP request per attestation. |
| `NUM_ALLOWED_URLS` | **3** | Hardcoded same way. Conveniently matches our 3-provider PoC: one URL slot per provider. To support N>3 providers you'd need to fork the lib. |

### Our choices

| Constant | Value | Why |
|---|---|---|
| `MAX_URL_LEN` | 96 | Longest ticker URL we hit is ~65 chars (Binance + 7-char symbol). 96 leaves headroom for slightly longer symbols. Each unit costs Poseidon2 gates over the URL bytes, so lower is cheaper. |
| `MAX_PLAINTEXT_LEN` | 32 | Crypto price strings are ~15 bytes (`"104231.50000000"`). 32 covers fiat formats and leaves slack. Each unit costs verification gates per response field. |
| `NUM_RESPONSE_RESOLVE` | 1 | We attest one field per call: the price. The lib *would* support more, but Primus's attestor has a bug (see "Don't attest multiple fields from the same URL" below) that effectively forces N=1. Symbol commitment is handled via the URL allow-list instead. |
| `maxResponseNum` (parser config) | 1 | This is the parser's name for `NUM_REQUEST_URLS` — confusingly named in the upstream lib. Must equal the contract's `NUM_REQUEST_URLS` (now 1) or the witness shape mismatches. |

The upstream lib also ships a commitment-based path (`verify_attestation_comm`, using Pedersen commitments on Grumpkin for fields too large for a single SHA256). Our local copy drops it — we only attest short price strings that fit comfortably in the hashing path. Restore from upstream if commitment mode becomes needed.

### Why `op: "SHA256"` is mandatory in each claim

Primus offers two response-extraction semantics:
- **REVEAL** — the parsed value lands literally in the signed `attestation.data` (`{"instType":"SPOT"}`).
- **SHA256** — `attestation.data` only contains a hash (`{"key":"<32-byte hex>"}`) and the plaintext stays with the prover.

The Noir `verify_attestation_hashing` *only* accepts the SHA256 shape — its check is `SHA256(content_witness) == data[key]`. Without `op: "SHA256"` the data field is plaintext and the contract has nothing to bind against. So every claim's `responseResolves` entry sets `"op": "SHA256"`.

### Why the allowed URLs contain the ticker symbol

`allowed_url_hashes` is a set-membership check on the request URL inside the circuit. If the allow-list were just `.../ticker/price` (no `?symbol=...`), then ANY symbol would attest successfully and the contract would have no cryptographic commitment to which asset the price represents. The on-chain event would say *"some Binance price"*.

By baking `?symbol=ETHUSDT` (and equivalents) into the allow-list URLs, the URL prefix match itself proves *"this is an ETH price from Binance"* — at zero extra circuit cost. The trade-off is granularity: with `NUM_ALLOWED_URLS=3` and three providers, we have exactly one slot per provider for one symbol. Adding a second symbol means redeploying, or forking the lib for `NUM_ALLOWED_URLS > 3`.

### Don't attest multiple fields from the same URL (structural limit, not a bug)

It would be natural to attest the price *and* the symbol in one request:

```jsonc
"responseResolves": [[
  { "keyName": "price",  "parsePath": "$.price",  "op": "SHA256" },
  { "keyName": "symbol", "parsePath": "$.symbol", "op": "SHA256" }
]]
```

**It doesn't work** — and after tracing the SDK source, it's clearer that the multi-resolve path is **not implemented end-to-end**, not buggy at a single layer. The shape is syntactically accepted everywhere; the actual fan-out is never built.

**What we observed empirically.** A Binance ETHUSDT attestation with the two-resolve shape above came back with both `data` keys mapped to the same SHA256:

```json
"data": {
  "SHA256($.symbol)": "7e6e9fce…",   // = SHA256("ETHUSDT")
  "SHA256($.price)":  "7e6e9fce…"    // ALSO = SHA256("ETHUSDT")
}
```

`SHA256("2253.35000000")` (the price's actual hash) never appears in the signed envelope. On-chain verification then fails because `SHA256(content[price])` doesn't match the hex at the claimed offset inside the signed `data` string.

**Where it falls apart, layer by layer:**

1. **JS SDK `assemblyResponse`** (`assembly_params.js`) correctly turns N resolves into N `subconditions` inside one `CONDITION_EXPANSION` object. So the wire payload looks right.
2. **JS SDK `attest()`** (`index.js:384–390`) iterates the URL-level array but only reads `responseResolve[0].keyName`, then checks `responseIds.length != responseResolves.length` — a vacuous check (URL-count vs URL-count, always equal). `responseIds` ends up indexed by URL, not by resolve. That alone means the JS-side already treats "one resolve per URL" as the data model.
3. **Native attestor binary** (`primus-zktls-native.node`) receives the array with N subconditions but the `data` field it emits stamps the same SHA256 hex into every `keyName` slot. The fan-out across subconditions wasn't actually implemented in the binary either.
4. **Every Primus fixture we found** — `okx-attestation-*.json`, `binance-attestation.json`, `github-attestation-*.json`, the demos in `zktls-demo/` — uses exactly one resolve per URL. The multi-resolve path is never exercised upstream.

**Why it's likely designed this way, not just abandoned mid-build.** Primus's MPC-TLS mode descends from TLSNotary-family protocols where the *unit of work* is "one session, one selective reveal." Doing N reveals from a single session requires more MPC rounds and careful handling of cross-reveal correlations — implementing that is a meaningful engineering lift. Multi-URL avoids the issue entirely: each URL is its own MPC session with its own single reveal, run in sequence. That's exactly what the upstream Noir lib's `NUM_REQUEST_URLS = 2` hardcoding *anticipates* — the multi-field story was always meant to live at the multi-URL level. (We dropped it to `1` in our local copy because this PoC only ever issues one URL per attestation.)

In other words: this isn't "Primus shipped a bug we should report." It's "Primus's protocol unit is `(1 URL → 1 reveal)` and you design around it."

**Implications for us:**
- We commit the symbol via the **URL allow-list** instead of a second response field (the section above).
- If you ever need to attest N fields, the choices are: (a) **multi-URL** — N requests, one resolve each (canonical for the upstream lib, which keeps `NUM_REQUEST_URLS = 2`; we'd have to bump our local literal); (b) attest a single composite field (`parsePath: "$"` over the whole response body) and parse off-chain — limited by `MAX_PLAINTEXT_LEN`.
- This bound is unlikely to lift soon. Don't design assuming a future multi-resolve fix will arrive — design around the per-URL unit.

### Why one shared `verifier.json` instead of per-provider

Every claim's verifier config (mode, maxes, allowedUrls) was identical anyway — the allow-list is a property of the *contract* (what URLs it accepts), not of any specific provider. Hoisting it to `src/ts/providers/verifier.json` makes it visible that one deployed `QuoteVerifier` instance verifies attestations from any of the 3 providers. The per-provider claim files now describe only what actually differs: request URL, parsePath, TLS mode.

### Why the default `attMode` is `mpctls`

`mpctls` (MPC-TLS) hides the request body — including auth tokens — from the attestor; only the attested field becomes visible after selective opening. `proxytls` (proxy-TLS) routes traffic *through* the attestor in plaintext (mitigated by the Phala TEE deployment but still strictly weaker privacy).

We default to `mpctls` so that the same claim template can be reused for endpoints that *do* carry tokens. Public ticker endpoints don't benefit from the privacy, and one of them (OKX) rejects the MPC handshake (`WaitPlainClientTimeout`), so individual claims can override to `proxytls`. CLI override: `yarn attest okx symbol=ETH-USDT mode=proxytls`.

### Why we keep a local copy of the lib (with patches)

Primus's Noir lib (`att_verifier_lib`) lives at https://github.com/primus-labs/zktls-verification-noir under a subdirectory. Their tutorial expects you to either work *inside* that monorepo (each example contract sits beside the lib with `path = "../att_verifier_lib"`) or copy the lib into your project. They never publish git tags, and Nargo's git dependency mechanism requires a `tag` (no `rev` or `branch` accepted) — so importing the lib over git isn't possible without forking and self-tagging.

We keep a local copy at `src/nr/att_verifier_lib/` — based on upstream `main` (`65496b7b99879fc108b68bd7f08296225786a40c`) with the following local divergences, all documented at their call sites:

**Patches:**
1. `starts_with`'s strict `haystack.len() > needle.len()` relaxed to `>=` (so request URL byte-equal to allowed URL passes). Reasoning below.
2. `sha256_var(..., len as u64)` → `len as u32` because the upstream `Nargo.toml` we bumped from `noir-lang/sha256 v0.2.1` to `v0.3.0` for aztec-nr 4.3.0 compatibility tightened the length arg type. One-character mechanical fix.

**Larger rewrites:**
3. **`verify_attestation_hashing` now reconstructs `keccak256(envelope)` in-circuit.** Upstream takes `hash` as a witness and verifies ECDSA over it without tying `hash` to the envelope contents (upstream issue [#9](https://github.com/primus-labs/zktls-verification-noir/issues/9)). Our version takes the raw envelope fields, derives the hash via the Primus `encodePacked` byte layout, and binds each content's SHA256 hex to the signed `data` string at a witness-provided offset. Adds the `noir-lang/keccak256` dep.
4. **`NUM_REQUEST_URLS` dropped from 2 to 1** — see the Hard Constraints table.
5. **Pedersen-commitment path removed** (`verify_attestation_comm`, `verify_commitment_group`, the Grumpkin imports). Restore from upstream if commitment mode becomes needed.

#### The bug we hit

The unconstrained helper `starts_with` (line 142) and its caller `get_allowed_url_index` (line ~165) disagree about whether equal-length inputs are valid:

```rust
// caller permits equal length:
if (allowed_url.len() <= request_url.len()) {
    let result = starts_with(request_url, allowed_url);
}

// callee rejects equal length:
assert(haystack.len() > needle_length, "haystack shorter than needle");  // strict >
```

We hit this when the request URL is byte-identical to an entry in `allowedUrls` — which is exactly what we want, because we bake the full symbol-bearing URL (`?symbol=ETHUSDT`) into the allow-list to commit cryptographically to the asset on-chain.

#### Why we patch instead of working around it

Before settling on the patch we tried every off-circuit alternative we could think of, and each broke on a real constraint:

| Workaround | Why it doesn't work |
|---|---|
| Append bare `&` to request URL (empty trailing component) | Primus's MPC client rejects the URL with `PrimusServerNetworkError: recv websocket header error` at the offline phase. The URL never even reaches Binance. |
| Append `&_=1` style padding | Binance rejects unknown query params with HTTP 400 (`Not all sent parameters were read`). OKX and Coinbase are looser but Binance is the strict one. |
| Truncate the allowed URL by one byte (drop trailing `T`) | Weakens the on-chain symbol commitment: `?symbol=ETHUSD` matches both `ETHUSDT` and `ETHUSDC`. Acceptable for a PoC, sloppy for production. |
| Attest the symbol as a second `responseResolve` | Primus's attestor has a bug: when multiple resolves share a URL, it stamps `SHA256` of one field's value onto *every* `keyName` in `attestation.data`. The second hash is the same as the first, so on-chain verification fails. |
| Two requests, one resolve each | Avoids the multi-resolve bug but doubles HTTP cost and introduces price-tick drift between requests. |

So the patch became the cleanest move.

#### What the patch is

One character. `src/nr/att_verifier_lib/src/lib.nr` line 142:

```diff
- assert(haystack.len() > needle_length, "haystack shorter than needle");
+ assert(haystack.len() >= needle_length, "haystack shorter than needle");
```

#### Why this is safe

1. **`starts_with` is `unconstrained`.** Unconstrained functions in Noir run as hints during witness generation — their assertions are runtime checks, never circuit constraints. They don't enter the proof.

2. **The actual cryptographic prefix check is constrained, and already handles equal-length inputs.** Look at `verify_sig_and_urls` around line 27:

    ```rust
    for j in 0..MAX_URL_LEN {
        if j < allowed_url.len() {
            assert_eq(request_urls[i].storage()[j], allowed_url.storage()[j], "URL check failed");
        }
    }
    ```

    This iterates `j < allowed_url.len()` positions, both within bounds, and asserts byte equality. For `request == allowed` (equal length), it does the right thing — proves prefix-which-equals-equality.

3. **The loop body of `starts_with` agrees with `>=`.** Its `for j in 0..needle_length` requires `haystack.get(j)` to succeed for `j` up to `needle_length - 1`, which needs `haystack.len() >= needle_length`, exactly. The strict `>` is an off-by-one that disagrees with both the loop body's actual safety boundary and the caller's `<=` gate.

So loosening the guard from `>` to `>=` doesn't change what the contract *proves*, doesn't expose any byte the constrained path didn't already see, and aligns three places in the file that were inconsistent. The change is documented inline at the patch site with a citation to upstream and a justification.

#### Proper fix

Open an upstream PR at `primus-labs/zktls-verification-noir` flipping that one operator. If/when it merges and Primus tags a release that Nargo can `tag`-import, this local copy can be deleted and replaced with a git dependency, ending the local divergence.

## Prerequisites

- Node ≥ 22, yarn
- Aztec CLI 4.3.0 (`.aztecrc` pins it; `aztec-up install 4.3.0` if missing)
- A Base Sepolia wallet with a small amount of ETH for `submitTask` gas

### Getting Base Sepolia ETH

1. Claim Sepolia ETH on L1 from the pk910 PoW faucet: https://sepolia-faucet.pk910.de/
2. Bridge it to Base Sepolia: https://superbridge.app/base-sepolia

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
7. asserts the receipt is successful **and** queries the chain for the emitted `QuoteVerified` event

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

## Layout

```
.
├── README.md
├── package.json                                all scripts (attest, ccc, test:js, test:e2e, …)
├── tsconfig.json
├── vitest.config.ts
├── .aztecrc                                    pins aztec CLI 4.3.0
├── Nargo.toml                                  Noir workspace
├── config.json                                 Base Sepolia + Base mainnet RPC config
└── src/
    ├── nr/                                     Noir source
    │   ├── att_verifier_lib/                   local copy of primus-labs/zktls-verification-noir (hashing path only)
    │   └── quote_verifier/                     our contract
    └── ts/
        ├── attest.ts                           runs Primus pipeline, writes 3 JSONs
        ├── prepare-witness.ts                  rebuilds witness.json from raw.json
        ├── load-claim.ts                       merges per-provider claim + shared verifier
        ├── att-verifier-parsing/               local copy of Primus's TS parser (no aztec deps)
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

## Trust model — what's actually verified

The contract verifies, end-to-end, **all inside the private circuit**:

1. **Envelope reconstruction**: the circuit reads the witness envelope fields (recipient, request URL, header+method+body, response resolves, `data`, attConditions, timestamp, additionParams) and rebuilds `keccak256(encodePacked(envelope))` byte-for-byte from Primus's `encodePacked` layout.
2. **ECDSA signature** over the **derived** envelope hash, using the storage-pinned attestor pubkey. There is no witnessed `hash` to splice — the ECDSA check IS the binding from "signature" to "these specific witnessed envelope bytes."
3. **URL allow-list match**: the request URL byte-identically equals one of the 3 URLs whose Poseidon2 hash is stored as `allowed_url_hashes` at deploy.
4. **SHA256 content binding**: for each attested field, `sha256(content)` is computed in-circuit and asserted to appear (as 64-char hex) at a witness-provided offset inside the now-signature-bound `data` string.

The chain: `signature ⇒ derived envelope hash ⇒ specific envelope bytes ⇒ specific data string ⇒ specific SHA256 hex bytes ⇒ original content`. Each ⇒ is enforced by a circuit constraint.

Both the URL allow-list and the attestor pubkey are `PublicImmutable` — pinned at deploy, no admin functions to rotate either. Changes = redeploy. Justified for a PoC; production use would want an admin path with explicit governance.

With the attestor pinned, trust bottoms out at: **the attestor node behaves honestly** (Primus's published binary is honest, the Phala TEE prevents tampering) and **the HTTPS endpoint itself isn't lying**. This is zkTLS as an oracle with a small trusted set, not trustless TLS.

### What used to be a gap, and how it's closed

In the upstream lib, `verify_attestation_hashing` takes `hash` as a witness — the circuit verifies ECDSA over it but never ties it to the envelope contents. A prover could pair a real Primus-signed `hash` with `data_hashes` they invented and pass both checks independently. Upstream issue [#9](https://github.com/primus-labs/zktls-verification-noir/issues/9) flags this.

Our local lib closes it by **reconstructing `keccak256(envelope)` inside the circuit** from the witnessed envelope fields and verifying ECDSA over the *derived* hash. There is no opaque `hash` witness to splice with anymore — `derived_hash` is forced equal to `keccak256(env_bytes)` by circuit constraints, and ECDSA forces that equal to the real signed hash. So any prover supplying envelope fields different from what the attestor signed will fail ECDSA. The per-content SHA256 check then operates on bytes pulled from the (now signature-bound) `data` string.
