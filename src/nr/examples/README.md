# Examples

This directory holds example consumers of the [`attestation_verifier`](../attestation_verifier/) lib — small Noir crates that show how to compose its building blocks against real Primus zkTLS attestations.

## Available examples

| Crate | What it shows | Provider used |
|---|---|---|
| [`quote_verifier/`](./quote_verifier/) | Canonical full-attestation check via the `verify_attestation_hashing` wrapper; verifies a token symbol + spot price extracted from a CoinGecko response. | CoinGecko `/api/v3/simple/price` |

## Running an example

Each example is its own Nargo crate listed in the workspace's [`Nargo.toml`](../../../Nargo.toml). From the repo root:

```bash
yarn compile               # compiles all workspace members
yarn benchmark             # runs the benchmark suite (quote_verifier included)
```

A TypeScript driver wires real Primus attestation payloads into each example — see [`src/ts/`](../../ts/) for fixture loading and proof generation.

## Adding a new example

1. Create `src/nr/examples/<name>/` with a `Nargo.toml` and `src/main.nr`.
2. Add `src/nr/examples/<name>` to the workspace members in the repo-root [`Nargo.toml`](../../../Nargo.toml).
3. Depend on the lib via a path dep: `attestation_verifier = { path = "../../attestation_verifier" }`.
4. Pick the composition pattern that fits your use case:
   - **Allow-list of full URLs** → call `verify_attestation_hashing` (wrapper).
   - **Single pinned URL prefix, custom URL check, or no URL check** → compose `derive_envelope_hash` + `verify_ecdsa_over_hash` + `bind_content_hashes` directly. See the lib's [composition soundness](../attestation_verifier/README.md#composition-soundness) section for the safe ordering.
5. Add a row to the table above so consumers can find it.

---

# QuoteVerifier — design notes

The rest of this README documents the consumer-side decisions the QuoteVerifier example makes against the [`attestation_verifier`](../attestation_verifier/) lib. These are *example choices*, not lib constraints — if you're building a different consumer (e.g. a klines oracle, a credit-score attester), you'd revisit each of these on its own terms.

## Providers

Three exchange ticker endpoints, all attest a single `price` field. **One deployed `QuoteVerifier` accepts attestations from any of the three providers** — the shared allow-list (`src/ts/providers/verifier.json`) lists all 3 provider+symbol URLs as the contract's `allowed_url_hashes`.

| Provider | Request URL template | Path | Default mode |
|---|---|---|---|
| Binance  | `api.binance.com/api/v3/ticker/price?symbol={symbol}` | `$.price` | mpctls |
| OKX      | `www.okx.com/api/v5/market/ticker?instId={symbol}` | `$.data[0].last` | mpctls (proxytls if rejected) |
| Coinbase | `api.coinbase.com/v2/prices/{symbol}/spot` | `$.data.amount` | mpctls |

To switch the supported asset (e.g. BTC instead of ETH), edit `src/ts/providers/verifier.json` so all 3 allowed URLs reflect the new symbol, then redeploy. The contract pins URL hashes and the attestor pubkey as `PublicImmutable` — there are no admin update functions; it's a fresh deploy each time.

## Data-model choices

The lib's [generic parameters](../attestation_verifier/README.md#generic-parameters-reference) are picked here to fit ticker-price attestations. Each unit costs circuit gates per call site, so lower-is-cheaper.

| Constant | Value | Why |
|---|---|---|
| `MAX_URL_LEN` | 96 | Longest ticker URL is ~65 chars (Binance + 7-char symbol). 96 leaves headroom for slightly longer symbols. |
| `MAX_PLAINTEXT_LEN` | 32 | Crypto price strings are ~15 bytes (`"104231.50000000"`). 32 covers fiat formats and leaves slack. |
| `NUM_RESPONSE_RESOLVE` | 1 | We attest one field per call: the price. The lib *would* support more, but Primus's attestor only does `(1 URL → 1 reveal)` (see [below](#dont-attest-multiple-fields-from-the-same-url-structural-limit-not-a-bug)). Symbol commitment is handled via the URL allow-list instead. |
| `NUM_ALLOWED_URLS` | 3 | One slot per provider, sharing one deployed contract. |
| `maxResponseNum` (parser config) | 1 | The off-chain TS parser's name for `NUM_REQUEST_URLS` — confusingly named in the upstream lib. Must equal the lib's `NUM_REQUEST_URLS` (now 1) or the witness shape mismatches. |

## Why `op: "SHA256"` is mandatory in each claim

Primus offers two response-extraction semantics:

- **REVEAL** — the parsed value lands literally in the signed `attestation.data` (`{"instType":"SPOT"}`).
- **SHA256** — `attestation.data` only contains a hash (`{"key":"<32-byte hex>"}`); the plaintext stays with the prover.

The lib's `bind_content_hashes` only accepts the SHA256 shape — its check is `sha256(content_witness) == data[key]`. Without `op: "SHA256"` the data field is plaintext and the contract has nothing to bind against. So every claim's `responseResolves` entry sets `"op": "SHA256"`.

## Why the allowed URLs contain the ticker symbol

`allowed_url_hashes` is a set-membership check on the request URL inside the circuit. If the allow-list were just `.../ticker/price` (no `?symbol=...`), then ANY symbol would attest successfully and the contract would have no cryptographic commitment to which asset the price represents. The on-chain event would say *"some Binance price"*.

By baking `?symbol=ETHUSDT` (and equivalents) into the allow-list URLs, the URL prefix match itself proves *"this is an ETH price from Binance"* — at zero extra circuit cost. The trade-off is granularity: with `NUM_ALLOWED_URLS=3` and three providers, we have exactly one slot per provider for one symbol. Adding a second symbol means redeploying, or bumping `NUM_ALLOWED_URLS` (now a generic — pick whatever you need).

### Why the patch instead of a workaround

Pinning the full URL into the allow-list means the request URL is byte-equal to the allowed URL — which is exactly the equal-length case [the lib's `starts_with` patch](../attestation_verifier/README.md#the-starts_with-patch) fixes. Before settling on the patch we tried every off-circuit alternative and each broke on a real constraint:

| Workaround | Why it doesn't work |
|---|---|
| Append bare `&` to request URL (empty trailing component) | Primus's MPC client rejects the URL with `PrimusServerNetworkError: recv websocket header error` at the offline phase. The URL never even reaches Binance. |
| Append `&_=1` style padding | Binance rejects unknown query params with HTTP 400 (`Not all sent parameters were read`). OKX and Coinbase are looser but Binance is the strict one. |
| Truncate the allowed URL by one byte (drop trailing `T`) | Weakens the on-chain symbol commitment: `?symbol=ETHUSD` matches both `ETHUSDT` and `ETHUSDC`. Acceptable for a PoC, sloppy for production. |
| Attest the symbol as a second `responseResolve` | Primus's attestor stamps `SHA256` of one field's value onto *every* `keyName` slot when N > 1 — see the next section. |
| Two requests, one resolve each | Avoids the multi-resolve issue but doubles HTTP cost and introduces price-tick drift between requests. |

So the patch became the cleanest move. The patch itself, why it's safe, and the upstream fix path are documented in the [lib README](../attestation_verifier/README.md#the-starts_with-patch).

## Don't attest multiple fields from the same URL (structural limit, not a bug)

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

`SHA256("2253.35000000")` (the price's actual hash) never appears in the signed envelope. On-chain verification then fails because `sha256(content[price])` doesn't match the hex at the claimed offset inside the signed `data` string.

**Where it falls apart, layer by layer:**

1. **JS SDK `assemblyResponse`** (`assembly_params.js`) correctly turns N resolves into N `subconditions` inside one `CONDITION_EXPANSION` object. So the wire payload looks right.
2. **JS SDK `attest()`** (`index.js:384–390`) iterates the URL-level array but only reads `responseResolve[0].keyName`, then checks `responseIds.length != responseResolves.length` — a vacuous check (URL-count vs URL-count, always equal). `responseIds` ends up indexed by URL, not by resolve. That alone means the JS-side already treats "one resolve per URL" as the data model.
3. **Native attestor binary** (`primus-zktls-native.node`) receives the array with N subconditions but the `data` field it emits stamps the same SHA256 hex into every `keyName` slot. The fan-out across subconditions wasn't implemented in the binary either.
4. **Every Primus fixture we found** — `okx-attestation-*.json`, `binance-attestation.json`, `github-attestation-*.json`, the demos in `zktls-demo/` — uses exactly one resolve per URL. The multi-resolve path is never exercised upstream.

**Why it's likely designed this way, not just abandoned mid-build.** Primus's MPC-TLS mode descends from TLSNotary-family protocols where the *unit of work* is "one session, one selective reveal." Doing N reveals from a single session requires more MPC rounds and careful handling of cross-reveal correlations — implementing that is a meaningful engineering lift. Multi-URL avoids the issue entirely: each URL is its own MPC session with its own single reveal, run in sequence. That's exactly what the upstream Noir lib's `NUM_REQUEST_URLS = 2` hardcoding *anticipates* — the multi-field story was always meant to live at the multi-URL level. (Our local lib dropped it to `1` because the QuoteVerifier example only ever issues one URL per attestation.)

In other words: this isn't "Primus shipped a bug we should report." It's "Primus's protocol unit is `(1 URL → 1 reveal)` and you design around it."

**Implications:**

- We commit the symbol via the **URL allow-list** instead of a second response field (see [above](#why-the-allowed-urls-contain-the-ticker-symbol)).
- If you ever need to attest N fields, the choices are: (a) **multi-URL** — N requests, one resolve each (canonical for the upstream lib, which keeps `NUM_REQUEST_URLS = 2`; we'd have to bump our local literal); (b) attest a single composite field (`parsePath: "$"` over the whole response body) and parse off-chain — limited by `MAX_PLAINTEXT_LEN`.
- This bound is unlikely to lift soon. Don't design assuming a future multi-resolve fix will arrive — design around the per-URL unit.

## Why one shared `verifier.json` instead of per-provider

Every claim's verifier config (mode, maxes, allowedUrls) was identical anyway — the allow-list is a property of the *contract* (what URLs it accepts), not of any specific provider. Hoisting it to `src/ts/providers/verifier.json` makes it visible that one deployed `QuoteVerifier` instance verifies attestations from any of the 3 providers. The per-provider claim files now describe only what actually differs: request URL, parsePath, TLS mode.

## Why the default `attMode` is `mpctls`

`mpctls` (MPC-TLS) hides the request body — including auth tokens — from the attestor; only the attested field becomes visible after selective opening. `proxytls` (proxy-TLS) routes traffic *through* the attestor in plaintext (mitigated by the Phala TEE deployment but still strictly weaker privacy).

We default to `mpctls` so the same claim template can be reused for endpoints that *do* carry tokens. Public ticker endpoints don't benefit from the privacy, and one of them (OKX) rejects the MPC handshake (`WaitPlainClientTimeout`), so individual claims can override to `proxytls`. CLI override: `yarn attest okx symbol=ETH-USDT mode=proxytls`.

## Trust model — what's actually verified

The QuoteVerifier contract verifies, end-to-end, **all inside the private circuit**:

1. **Envelope reconstruction**: the circuit reads the witness envelope fields (recipient, request URL, header+method+body, response resolves, `data`, attConditions, timestamp, additionParams) and rebuilds `keccak256(encodePacked(envelope))` byte-for-byte from Primus's `encodePacked` layout. (Lib: `derive_envelope_hash`.)
2. **ECDSA signature** over the **derived** envelope hash, using the storage-pinned attestor pubkey. There is no witnessed `hash` to splice — the ECDSA check IS the binding from "signature" to "these specific witnessed envelope bytes." (Lib: `verify_ecdsa_over_hash`; see also [splice attack closure](../attestation_verifier/README.md#trust-model-closing-the-splice-attack).)
3. **URL allow-list match**: the request URL byte-identically equals one of the 3 URLs whose Poseidon2 hash is stored as `allowed_url_hashes` at deploy. (Lib: `match_url_against_allowlist`.)
4. **SHA256 content binding**: for each attested field, `sha256(content)` is computed in-circuit and asserted to appear (as 64-char hex) at a witness-provided offset inside the now-signature-bound `data` string. (Lib: `bind_content_hashes`.)

The chain: `signature ⇒ derived envelope hash ⇒ specific envelope bytes ⇒ specific data string ⇒ specific SHA256 hex bytes ⇒ original content`. Each ⇒ is enforced by a circuit constraint.

Both the URL allow-list and the attestor pubkey are `PublicImmutable` — pinned at deploy, no admin functions to rotate either. Changes = redeploy. Justified for a PoC; production use would want an admin path with explicit governance.

With the attestor pinned, trust bottoms out at: **the attestor node behaves honestly** (Primus's published binary is honest, the Phala TEE prevents tampering) and **the HTTPS endpoint itself isn't lying**. This is zkTLS as an oracle with a small trusted set, not trustless TLS.
