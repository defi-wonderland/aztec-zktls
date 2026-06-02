# Examples

Example consumers of the [`attestation_verifier`](../attestation_verifier/) lib.

## Available examples

| Crate | What it shows | Provider used |
|---|---|---|
| [`quote_verifier/`](./quote_verifier/) | Spot-price attestation: lib primitives + URL allow-list + in-circuit price normalization + on-chain `historical_quotes` map. | Binance / OKX / Coinbase ticker endpoints |

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
