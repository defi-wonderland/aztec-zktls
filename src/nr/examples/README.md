# Examples

This directory holds example consumers of the [`attestation_verifier`](../attestation_verifier/) lib — small Noir crates that show how to compose its building blocks against real Primus zkTLS attestations.

## Available examples

| Crate | What it shows | Provider used |
|---|---|---|
| [`quote_verifier/`](./quote_verifier/) | Spot-price attestation: `verify_attestation` (cryptography) + contract-side URL allow-list via `Map<Field, PublicImmutable<bool>>` + in-circuit decimal-string price normalization recorded into `Map<Field, PublicImmutable<Quote>>` keyed by `envelope.timestamp`. | Binance / OKX / Coinbase ticker endpoints |

## Running an example

Each example is its own Nargo crate listed in the workspace's [`Nargo.toml`](../../../Nargo.toml). From the repo root:

```bash
yarn compile               # compiles all workspace members
yarn bench                 # runs the benchmark suite (quote_verifier included)
```

A TypeScript driver wires real Primus attestation payloads into each example — see [`src/ts/`](../../ts/) for fixture loading and proof generation.

## Adding a new example

1. Create `src/nr/examples/<name>/` with a `Nargo.toml` and `src/main.nr`.
2. Add `src/nr/examples/<name>` to the workspace members in the repo-root [`Nargo.toml`](../../../Nargo.toml).
3. Depend on the lib via a path dep: `attestation_verifier = { path = "../../attestation_verifier" }`.
4. The lib gives you three primitives + a canonical-order wrapper (`verify_attestation`). It takes no positions on URL matching, recipient identity, timestamp windows, etc. — implement those in the contract that wraps the verification call. The QuoteVerifier example below shows the canonical pattern (Map-based exact-equality URL hash lookup); other shapes (single pinned URL prefix, multi-tenant routing, no URL check at all) compose the same primitives differently.
5. Add a row to the table above so consumers can find it.

---

# QuoteVerifier — design notes

The rest of this README documents the consumer-side decisions the QuoteVerifier example makes against the [`attestation_verifier`](../attestation_verifier/) lib. These are *example choices*, not lib constraints — if you're building a different consumer (e.g. a klines oracle, a credit-score attester), you'd revisit each of these on its own terms.

## Providers

Three exchange ticker endpoints, all attest a single `price` field. **One deployed `QuoteVerifier` accepts attestations from any of the three providers** — the shared verifier config (`src/ts/providers/verifier.json`) lists all 3 provider+symbol URLs; the deploy script hashes each one and initializes a slot in the contract's `allowed_url_hashes` map.

| Provider | Request URL template | Path | Default mode |
|---|---|---|---|
| Binance  | `api.binance.com/api/v3/ticker/price?symbol={symbol}` | `$.price` | mpctls |
| OKX      | `www.okx.com/api/v5/market/ticker?instId={symbol}` | `$.data[0].last` | mpctls (proxytls if rejected) |
| Coinbase | `api.coinbase.com/v2/prices/{symbol}/spot` | `$.data.amount` | mpctls |

To switch the supported asset (e.g. BTC instead of ETH), edit `src/ts/providers/verifier.json` so all 3 allowed URLs reflect the new symbol, then redeploy. The contract pins URL hashes and the attestor pubkey as `PublicImmutable` — there are no admin update functions; it's a fresh deploy each time.

## Allow-list shape: `Map<Field, PublicImmutable<bool>>`

Storage holds the allow-list as a map keyed by `poseidon2_hash(zero-padded URL bytes)`:

```noir
allowed_url_hashes: Map<Field, PublicImmutable<bool, Context>, Context>,
```

The constructor takes `[Field; 3]` (one hash per provider URL) and initializes each map slot to `true`. `verify(...)` hashes the request URL from the signature-bound envelope and reads the corresponding slot — an uninitialized read panics with "Trying to read from uninitialized PublicImmutable", which effectively rejects any URL not in the allow-list.

**Why a map instead of a fixed-size array of hashes:**

- **O(1) lookup** — no `for j in 0..N` loop over slots, regardless of allow-list size.
- **Exact equality is implicit.** Different URL bytes → different Poseidon hash → not in map. There's no prefix-match footgun: a longer signed request URL produces a different hash than the canonical allowed URL, so it gets rejected. The `request_url.len() == allowed_url.len()` assertion the earlier prefix-match design needed is now a structural property of "hash equality."
- **Allow-list size isn't baked into `verify()`'s circuit shape.** The contract still picks a `NUM_ALLOWED_URLS_AT_DEPLOY` for the constructor's input array, but the circuit doesn't iterate the list — it does one map lookup. Bumping the allow-list size at redeploy time is just changing the constant.

The trade-off: every request URL must be byte-equal to a pre-known allowed URL. Any extra query parameter (`&recv_window=`, `&otherthing=`) the prover appends produces a hash miss → revert. That's the security property we want here — see the lib README's [discussion of the soundness footguns](../attestation_verifier/README.md#divergences-from-upstream) that the prefix-match design (which we removed) had.

## Quote storage and price normalization

Every successful `verify()` initializes one slot in `historical_quotes`:

```noir
historical_quotes: Map<Field, PublicImmutable<Quote, Context>, Context>,
```

`Quote` is `{ price: u128, timestamp: u64 }`. The slot is keyed by the attestor-signed `envelope.timestamp` (cast to `Field`). `PublicImmutable` writes from public context take effect immediately, so the entry is readable from both public and private context as soon as the `verify()` tx is included — **no delay**. Reading a never-written timestamp slot reverts with "Trying to read from uninitialized PublicImmutable".

Public consumers (and tests) use the `get_quote_at(timestamp: u64) -> pub Quote` view function. Private consumers do `self.storage.historical_quotes.at(t).read()` directly.

### Why historical-only, no "latest_quote" view

An earlier draft included a `latest_quote: DelayedPublicMutable<Quote, QUOTE_DELAY>` slot that updated on every `verify()`. We dropped it: `DelayedPublicMutable`'s delay applies to *all* readers (public and private), so a "latest" view backed by it was always at least `QUOTE_DELAY` seconds stale, which defeated the point of having a fresh-price view. The other primitive options each made the trade-off worse:

- `PublicMutable<Quote>` — public-readable only; loses private-readability entirely.
- Two slots (PublicMutable + DelayedPublicMutable) — doubles writes for marginal gain.

The historical map is strictly more useful: every entry is immediate, both contexts can read it, and consumers wanting "the most recent" track timestamps off-chain (event log, indexer, etc.) and query the specific slot.

### Why 8-decimal fixed-point

The three providers emit prices as decimal strings with varying precision: Binance 8 decimals (`"1234.50000000"`), Coinbase 2 (`"1234.50"`), OKX variable. To make `Quote.price` a single comparable number, the contract normalizes everything to a `u128` mantissa with 8-decimal precision (`1234.5 → 123450000000`).

8 was picked because it matches Binance natively (zero scale-up cost for the most precise feed), is the Chainlink convention, and easily fits in `u128` for any realistic price. The constant lives at `global PRICE_DECIMALS: u32 = 8` in the contract.

### The in-circuit parser

`parse_decimal_price(bytes: BoundedVec<u8, MAX_PLAINTEXT_LEN>) -> u128` is a `#[contract_library_method]` that:

1. Loops over the (signature-bound) content bytes.
2. Asserts each byte is either an ASCII digit (`0x30..=0x39`) or a single `.` (`0x2e`).
3. Builds the mantissa as `value = value * 10 + digit`.
4. Tracks how many digits appeared after the dot.
5. Asserts `decimals_seen <= PRICE_DECIMALS` (more would mean precision loss).
6. Scales the mantissa up by `10 ** (PRICE_DECIMALS - decimals_seen)` using a compile-time-bounded loop.

Reverts on: multiple decimal points, non-digit/non-dot bytes, or more than 8 fractional digits. The input must be the signature-bound `contents[i]` from `verify_attestation` (otherwise content binding wouldn't have happened and the bytes are not trusted).

## Data-model choices

The lib's [generic parameters](../attestation_verifier/README.md#generic-parameters-reference) are picked here to fit ticker-price attestations. Each unit costs circuit gates per call site, so lower-is-cheaper.

| Constant | Value | Why |
|---|---|---|
| `MAX_URL_LEN` | 96 | Longest ticker URL is ~65 chars (Binance + 7-char symbol). 96 leaves headroom for slightly longer symbols. |
| `MAX_PLAINTEXT_LEN` | 32 | Crypto price strings are ~15 bytes (`"104231.50000000"`). 32 covers fiat formats and leaves slack. |
| `NUM_RESPONSE_RESOLVE` | 1 | We attest one field per call: the price. The lib *would* support more, but Primus's attestor only does `(1 URL → 1 reveal)` (see [below](#dont-attest-multiple-fields-from-the-same-url-structural-limit-not-a-bug)). Symbol commitment is handled via the URL allow-list instead. |
| `NUM_ALLOWED_URLS_AT_DEPLOY` | 3 | Constructor takes this many URL hashes (one per provider). Pure deploy-time constant — `verify()` does a single map lookup and doesn't iterate. |
| `maxResponseNum` (parser config) | 1 | The off-chain TS parser's name for `NUM_REQUEST_URLS` — confusingly named in the upstream lib. Must equal the lib's `NUM_REQUEST_URLS` (now 1) or the witness shape mismatches. |

## Why `op: "SHA256"` is mandatory in each claim

Primus offers two response-extraction semantics:

- **REVEAL** — the parsed value lands literally in the signed `attestation.data` (`{"instType":"SPOT"}`).
- **SHA256** — `attestation.data` only contains a hash (`{"key":"<32-byte hex>"}`); the plaintext stays with the prover.

The lib's `bind_content_hashes` only accepts the SHA256 shape — its check is `sha256(content_witness) == data[key]`. Without `op: "SHA256"` the data field is plaintext and the contract has nothing to bind against. So every claim's `responseResolves` entry sets `"op": "SHA256"`.

## Why the allowed URLs contain the ticker symbol

`allowed_url_hashes` is a set-membership check on the request URL inside the circuit. If the allow-list were just `.../ticker/price` (no `?symbol=...`), then ANY symbol would attest successfully and the contract would have no cryptographic commitment to which asset the price represents. The recorded quote would say *"some Binance price"* with no way to tell ETHUSDT from BTCUSDT.

By baking `?symbol=ETHUSDT` (and equivalents) into the allow-list URLs, the URL match itself proves *"this is an ETH price from Binance"* — at zero extra circuit cost (one hash + one map read). The trade-off is granularity: with three slots, we have exactly one slot per provider for one symbol. Adding a second symbol means redeploying (or scaling up `NUM_ALLOWED_URLS_AT_DEPLOY` to fit more slots).

### A note on design history

An earlier draft used a byte-prefix URL match inside the lib (`match_url_against_allowlist`), and we patched a one-character bug in its `starts_with` helper to allow `request_url == allowed_url`. On security review two soundness issues surfaced (prefix-match accepting longer signed URLs; overlapping-prefix allow-lists letting the prover pick the matched slot). Cleanest fix: remove URL matching from the lib and let consumers express the policy they actually want. The current Map-based exact-equality pattern is the result. See lib README [divergences](../attestation_verifier/README.md#divergences-from-upstream) for the full history.

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

1. **Envelope reconstruction**: the circuit reads the witness envelope fields (recipient, request URL, header+method+body, response resolves, `data`, attConditions, timestamp, additionParams) and rebuilds `keccak256(encodePacked(envelope))` byte-for-byte from Primus's `encodePacked` layout. (Lib: `derive_envelope_hash`, invoked via `verify_attestation`.)
2. **ECDSA signature** over the **derived** envelope hash, using the storage-pinned attestor pubkey. There is no witnessed `hash` to splice — the ECDSA check IS the binding from "signature" to "these specific witnessed envelope bytes." (Lib: `verify_ecdsa_over_hash`, invoked via `verify_attestation`; see also [splice attack closure](../attestation_verifier/README.md#trust-model-closing-the-splice-attack).)
3. **SHA256 content binding**: for each attested field, `sha256(content)` is computed in-circuit and asserted to appear (as 64-char hex) at a witness-provided offset inside the now-signature-bound `data` string. (Lib: `bind_content_hashes`, invoked via `verify_attestation`.)
4. **URL allow-list check** (contract policy, **not** lib): the contract hashes the signature-bound `envelope.request_url` (with explicit zero-padding to `MAX_URL_LEN`) and reads the corresponding slot in `allowed_url_hashes`. An uninitialized slot reverts; otherwise the URL is in the allow-list. Exact byte equality is structural — different URL bytes produce different Poseidon hashes.
5. **Price parse + storage write**: the signature-bound content bytes are parsed in-circuit into a `u128` mantissa scaled to 8 decimals (reverts on non-digit bytes, multiple dots, or more than 8 fractional digits). An enqueued public call initializes `historical_quotes[envelope.timestamp]` with the `Quote { price, timestamp }`. Duplicate-timestamp submissions are silently skipped via `is_initialized()`.

The chain: `signature ⇒ derived envelope hash ⇒ specific envelope bytes ⇒ specific data string ⇒ specific SHA256 hex bytes ⇒ original content ⇒ parsed u128 price`, **plus** `envelope.request_url ⇒ specific Poseidon hash ⇒ allow-list membership`. Each ⇒ is a circuit constraint.

The attestor pubkey is `PublicImmutable` and the URL allow-list is a `Map<Field, PublicImmutable<bool>>` — both are pinned at deploy with no admin functions to rotate either. Changes = redeploy. Justified for a PoC; production use would want an admin path with explicit governance.

With the attestor pinned, trust bottoms out at: **the attestor node behaves honestly** (Primus's published binary is honest, the Phala TEE prevents tampering) and **the HTTPS endpoint itself isn't lying**. This is zkTLS as an oracle with a small trusted set, not trustless TLS.

## Known limitations

**1. No freshness enforcement on `envelope.timestamp` — replays are possible.**

The contract accepts an attestation regardless of how old `envelope.timestamp` is. A submitter who has held onto a saved Primus proof from days ago can submit it now and have the contract record a stale price at that historical timestamp. The historical entry itself is sound (the price *was* attested at that time), but a downstream consumer reading `get_quote_at(t)` for a specific `t` cannot tell whether `t` was just submitted or was submitted weeks ago.

Defenses a production version would add:

- **Reject ancient envelopes** in `verify()` via `assert(envelope.timestamp / 1000 + MAX_AGE >= self.context.timestamp())`. Anchor-block-relative.
- **Monotonicity in `record_quote`** if a "latest" view is ever reintroduced.

For PoC purposes, **consumers should treat `Quote.timestamp` as the trustworthy "when this was observed" signal and apply their own freshness policy** when reading via `get_quote_at(t)`. Specifically, never read a price and trust it as "current" without checking `block.timestamp - quote.timestamp` against your own staleness threshold.

**2. The attestor pubkey and URL allow-list are immutable.**

There is no admin path to rotate the attestor pubkey or amend the URL allow-list. If Primus rotates their attestor key, this contract stops being able to verify new attestations — a redeploy is required. Similarly for switching the supported asset symbol (ETH → BTC) or adding a fourth provider. Fine for a PoC; a real deployment would want a delayed-mutable admin path with explicit governance.

**3. `verify()` has no replay-protection at the `(attestor, signature)` level.**

A given signature can be re-submitted any number of times. The `is_initialized()` guard on `historical_quotes[timestamp]` makes the second submission a no-op at the storage layer, but the verification still runs (and costs gas). If you wanted to charge fees per attestation or prevent gas wastage from re-submissions, you'd add a nullifier on the signature.
