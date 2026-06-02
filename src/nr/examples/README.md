# Examples

Example consumers of the [`attestation_verifier`](../attestation_verifier/) lib.

## Available examples

| Crate | What it shows | Provider used |
|---|---|---|
| [`quote_verifier/`](./quote_verifier/) | Spot-price attestation: lib primitives + URL allow-list + in-circuit price normalization + on-chain `historical_quotes` map. | Binance / OKX / Coinbase ticker endpoints |
| [`options/klines_oracle/`](./options/klines_oracle/) | Admin-managed oracle for Binance klines candles. Prefix-match URL policy (base + caller-pinned query), six SHA256_EX-bound numeric fields parsed to a `KlinesCandle`. | Binance `/api/v3/klines` |
| [`options/option_escrow/`](./options/option_escrow/) | American/European option escrow gated by `klines_oracle`. Lifecycle: `quote_option` → `subscribe` → (`exercise` \| `recover`). Per-option escrow + Core/Quote/Proposal notes. | (consumes the oracle) |

## Running

```bash
yarn compile      # all workspace members
yarn bench        # benchmarks (quote_verifier included)
```

TS drivers live in [`src/ts/`](../../ts/).

## Adding a new example

1. Create `src/nr/examples/<name>/` (Nargo.toml + src/main.nr).
2. Register it in the workspace [`Nargo.toml`](../../../Nargo.toml).
3. Depend on the lib: `attestation_verifier = { path = "../../attestation_verifier" }`.
4. Compose the three primitives in your `verify` (see QuoteVerifier). Apply your own policy (URL match, recipient, freshness) around them.
5. Add a row to the table above.

---

# QuoteVerifier — design notes

## Providers

One deployed contract accepts attestations from all three providers — the shared verifier config (`src/ts/providers/verifier.json`) lists the (URL, parsePath) pairs and the deploy script pair-hashes them into `allowed_attestation_hashes`.

| Provider | Request URL template | Path | Default mode |
|---|---|---|---|
| Binance  | `api.binance.com/api/v3/ticker/price?symbol={symbol}` | `$.price` | mpctls |
| OKX      | `www.okx.com/api/v5/market/ticker?instId={symbol}` | `$.data[0].last` | mpctls (proxytls if rejected) |
| Coinbase | `api.coinbase.com/v2/prices/{symbol}/spot` | `$.data.amount` | mpctls |

To switch asset (ETH → BTC): edit `verifier.json` and redeploy. The allow-list and attestor pubkey are `PublicImmutable` — no admin rotation.

## Allow-list: `Map<Field, PublicImmutable<bool>>` keyed by `poseidon2_hash([url_hash, rr_hash])`

```noir
allowed_attestation_hashes: Map<Field, PublicImmutable<bool, Context>, Context>,
```

Each slot binds a `(request_url, response_resolves[0])` pair (each inner hash over the field's bytes zero-padded to its bound). The constructor seeds one slot per allowed pair; `verify()` derives the same pair-hash from the signature-bound envelope and reads the slot — an uninitialized read reverts.

**Why bind both fields:** the Primus attestor doesn't care what `parsePath` you ask for. URL-only allow-listing lets a submitter request the allow-listed URL with a different `parsePath` (e.g. `$` for the whole body) and have *that* value recorded as the canonical price. Pinning the pair forbids this.

**Why a map:** O(1) lookup, no slot loop, exact equality is structural (different bytes → different hash → not in map).

## Storage: `historical_quotes`

```noir
historical_quotes: Map<Field, PublicImmutable<Quote, Context>, Context>,
```

`Quote = { price: u128, timestamp: u64 }`, keyed by attestor-signed `envelope.timestamp`. `PublicImmutable` writes from public context take effect immediately — readable from both public and private the moment `verify()` is included. No "latest" slot: consumers track timestamps off-chain (event log / indexer) and query `get_quote_at(t)`.

A `QuoteRecorded { price, timestamp }` event fires on each new slot init (skipped on duplicate-timestamp re-submissions). Listening for this event is the canonical way to build an off-chain "latest quote" view.

## Price normalization

Prices arrive as decimal strings with varying precision (Binance 8 dp, Coinbase 2, OKX variable). The in-circuit `parse_decimal_price` scales each to a `u128` mantissa at `PRICE_DECIMALS = 8` (Chainlink convention, Binance-native). Reverts on multiple dots, non-digit bytes, or > 8 fractional digits.

## Data-model choices

The lib's [generics](../attestation_verifier/README.md#generic-parameters-reference) are picked for ticker prices — each value costs circuit gates, so lower is cheaper.

| Constant | Value | Rationale |
|---|---|---|
| `MAX_URL_LEN` | 96 | Longest URL ~65 chars; headroom for longer symbols. |
| `MAX_PLAINTEXT_LEN` | 32 | `"104231.50000000"` ≈ 15 bytes; covers fiat formats. |
| `NUM_RESPONSE_RESOLVE` | 1 | Primus's protocol unit is `(1 URL → 1 reveal)`. Symbol commitment goes in the URL allow-list. |
| `NUM_ALLOWED_URLS_AT_DEPLOY` | 3 | One slot per provider. Constructor-only — `verify()` is O(1). |
| `maxResponseNum` (TS parser) | 1 | Must equal `NUM_REQUEST_URLS`. |

`op: "SHA256"` is mandatory in each claim — the lib's `bind_content_hashes` needs `attestation.data` to contain a SHA256 hex, not the raw plaintext.

The allow-list URLs include the ticker symbol (`?symbol=ETHUSDT`) so the URL match itself commits to which asset the price represents — at zero extra circuit cost.

## Trust model

End-to-end, all in-circuit:

1. **Envelope reconstruction**: rebuild `keccak256(envelope)` from witnessed fields. (Lib: `derive_envelope_hash`.)
2. **ECDSA** over the derived hash with the storage-pinned pubkey — no witnessed `hash` to splice. (Lib: `verify_ecdsa_over_hash`; see [splice attack](../attestation_verifier/README.md#trust-model-closing-the-splice-attack).)
3. **SHA256 content binding** against the now-signature-bound `data`. (Lib: `bind_content_hashes`.)
4. **(URL, response_resolve) pair-hash allow-list check** (contract policy).
5. **Parse + record**: in-circuit decimal parse to `u128`, then `historical_quotes[timestamp]` init + `QuoteRecorded` emit.

Trust bottoms out at the attestor behaving honestly (Primus binary + Phala TEE) and the HTTPS endpoint not lying. zkTLS as an oracle with a small trusted set, not trustless TLS.

## Known limitations

**1. No freshness enforcement.** Stale signed envelopes can be replayed. The historical entry is sound (it *was* attested at that timestamp), but downstream consumers MUST check `block.timestamp - quote.timestamp` against their own staleness threshold. Production hardening: `assert(envelope.timestamp / 1000 + MAX_AGE >= self.context.timestamp())` in `verify()`.

**2. Allow-list + attestor are immutable.** Rotating the attestor key or amending the allow-list requires redeploy. A production version would want a delayed-mutable admin path.

**3. No nullifier on signatures.** Re-submissions of the same signature don't double-write (`is_initialized()` guard) but still consume gas. Add a signature nullifier if that's a concern.

---

# KlinesOracle — design notes

Admin-managed verifier that turns Primus zkTLS klines attestations into a parsed `KlinesCandle`. Pins the attestor pubkey and base URL prefix at deploy as `PublicImmutable` (no admin rotation — redeploy to change). Consumers pass a per-call `query_prefix` (e.g. `?symbol=ETHUSDT&interval=1m&`).

## Storage

```noir
attestor: PublicImmutable<PublicKey, Context>,
base_url_prefix: PublicImmutable<BaseUrlPrefix, Context>,
```

`BaseUrlPrefix` is a fixed-length byte buffer + length (64 bytes capacity), packed into 4 Fields for the `PublicImmutable`.

## URL policy: prefix match, not allow-list

Klines URLs include variable suffixes (`startTime`, `endTime`) that the consumer can't enumerate at deploy — exact-equality (like QuoteVerifier's pair-hash) doesn't fit. Instead, the oracle asserts:

```
request_url[0..base.len + query.len] == base || query_prefix
```

with bytes past that boundary deliberately unconstrained. **Soundness lives one level up** in the consumer: it must commit to the canonical `query_prefix` off-chain (the option escrow stores `poseidon2_hash(query_prefix)` in its `QuoteNote` and checks it on exercise) so an arbitrary suffix can't be swapped at submit time.

## Six bound fields

Each candle has six numeric fields the attestor SHA256_EX-binds: `openTime`, `open`, `high`, `low`, `close`, `closeTime`. Prices parse to a `u64` scaled to 8 decimals; timestamps parse as `u64` ms. The contract is interval-agnostic (1m, 5m, 1h — all valid); the consumer checks `close_time - open_time + 1` against its expected interval.

## What the oracle does NOT do

- No symbol/interval/timing interpretation — those are consumer policy.
- No allow-list of attestors — only the admin-pinned one is accepted.
- No per-consumer state.

---

# OptionEscrowLogic — design notes

Fully-collateralized American/European option contracts gated by `klines_oracle`. Each option instance lives in its own private `Escrow` (from `aztec-standards`) addressed by `(secret_key, this_address)`. State is three notes (Core/Quote/Proposal) keyed by the escrow address.

Tech design: [Notion](https://www.notion.so/defi-wonderland/zkTLS-Option-Escrow-3669a4c092c78078a447c09fd8d3e5a6).

## Lifecycle

```
quote_option ──► subscribe ──► exercise   (option exercised in the money)
                      │
                      └─────► recover    (post-expiry unexercised, OR pending-cancel)
```

| Action | Caller | What flows |
|---|---|---|
| `quote_option` | proposer (buyer OR seller) | proposer's deposit → escrow. Writes Core+Quote+Proposal notes. Shares the escrow secret with both parties. |
| `subscribe` | counterparty (whichever side is missing) | counterparty's deposit → escrow. Premium released escrow → seller. Proposal note nullified. |
| `exercise` (buyer, in-the-money) | buyer | Settlement: buyer → seller. Locked collateral: escrow → buyer. |
| `recover` (pending) | proposer | proposer's deposit reclaimed escrow → proposer. |
| `recover` (post-expiry) | seller | seller's collateral reclaimed escrow → seller. |

## Buyer / seller / call / put

Call options: seller's collateral is `base_token`; buyer settles with `quote_token` to receive the base on exercise.
Put options: seller's collateral is `quote_token`; buyer settles with `base_token` to receive the quote on exercise.

The flavor (call/put) and side (buyer/seller) for the proposer determine which token + amount flows at each step.

## Timing windows

`CoreTerms.deadline` is the exercise cutoff. `is_american` flips the window semantics:

- **American**: exercise must be strictly before `deadline`; candle must have finalized AND fall within `RECENCY_WINDOW_S` (10 min) of `now`.
- **European**: exercise must be within `[deadline, deadline + LATE_EXERCISE_GRACE_S]` (24h grace); candle's `open_time` must straddle `deadline` within `SETTLEMENT_WINDOW_S` (5 min).

`privately_check_timestamp` (from `public_checks_contract`) enforces these against `block.timestamp` from private context.

## Exercise oracle binding

At `quote_option`, the QuoteNote stores `pinned_query_prefix_hash = poseidon2_hash(query_prefix_padded_to_MAX_QUERY_PREFIX_LEN)`. At `exercise`, the buyer's claimed `query_prefix` must hash to the same value, then gets forwarded to the oracle. This binds **which feed** the option settles against — the buyer can't swap symbols at exercise time.

The oracle's prefix-match URL policy + this consumer-side commitment is what makes the overall flow sound despite the oracle's unconstrained URL suffix.

## Known limitations

Inherits all of QuoteVerifier's limitations on the underlying attestation, plus:

**4. Settlement requires a candle near `deadline`.** If no honest candle is attested within the European settlement window, the option can't be exercised — falls through to `recover`. American is more forgiving via `RECENCY_WINDOW_S`.

**5. Strike check is midpoint-based.** Uses `(open + close) / 2` rather than a closing price or VWAP — fine for a PoC, but a real product would think harder about which candle field to use (close-only is more aligned with conventional options).

**6. No partial fills or cancels post-subscribe.** Once subscribed, the only exits are `exercise` (if in-the-money + timing window holds) or `recover` (post-expiry unexercised).
