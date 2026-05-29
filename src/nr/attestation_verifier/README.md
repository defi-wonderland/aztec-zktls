# attestation_verifier

Primus zkTLS attestation verifier — Noir building blocks for proving the validity of a Primus-signed envelope inside a Noir/Aztec circuit.

Modified from [primus-labs/zktls-verification-noir](https://github.com/primus-labs/zktls-verification-noir) (commit `65496b7`). See the root [README](../../../README.md#local-divergences-from-upstream) for the full list of local divergences (the biggest is the in-circuit `keccak256(envelope)` reconstruction that closes upstream [issue #9](https://github.com/primus-labs/zktls-verification-noir/issues/9)).

## Install

```toml
[dependencies]
attestation_verifier = { git = "https://github.com/defi-wonderland/aztec-zktls-poc", tag = "vX.Y.Z", directory = "src/nr/attestation_verifier" }
```

(Repo will be renamed to `aztec-zktls` once it leaves PoC status — update the URL accordingly.)

If you're consuming the lib from another crate inside *this* workspace, use a path dep instead — the relative path depends on where your `Nargo.toml` sits. The bundled example at `src/nr/examples/quote_verifier/` uses `path = "../../attestation_verifier"`.

The lib pulls `noir-lang/sha256@v0.3.0`, `noir-lang/keccak256@v0.1.3`, and `noir-lang/poseidon@v0.3.0` as transitive deps.

## API

Four building blocks plus a convenience wrapper. Each does one thing; consumers compose them based on use case.

### Building blocks

#### `derive_envelope_hash(envelope_fields...) -> [u8; 32]`

Reconstruct `keccak256(encodePacked(envelope))` byte-for-byte from envelope fields. Output is what the Primus attestor signed.

Byte layout (matches Primus's `encodePacked`):

```
recipient(20)
|| keccak256(request_urls[0] || request_hmb)
|| keccak256(response_resolves concat)
|| data
|| att_conditions
|| timestamp_be(8)
|| addition_params
```

#### `verify_ecdsa_over_hash(public_key_x, public_key_y, signature, hash)`

Assert an ECDSA-secp256k1 signature is valid for the given hash and public key. The caller is responsible for ensuring `hash` came from a derived (not witnessed) source — typically the output of `derive_envelope_hash` against the same envelope.

#### `match_url_against_allowlist<MAX_URL_LEN, NUM_ALLOWED_URLS>(request_url, allowed_urls) -> Field`

Find which entry of `allowed_urls` is a byte-prefix of `request_url`, constrain the prefix match, and return the Poseidon2 hash of the matched entry. Reverts if no entry matches.

`NUM_ALLOWED_URLS` is generic (upstream hardcoded it at 3). The returned hash is computed over `MAX_URL_LEN` bytes of the matched URL zero-padded, so consumers comparing hashes off-circuit must agree on `MAX_URL_LEN`.

#### `bind_content_hashes<N, MAX_CONTENT_LEN, MAX_DATA_LEN>(contents, data, data_hash_offsets)`

For each content `c[i]`, compute `sha256(c[i])` and assert its 64-character lowercase hex appears at `data_hash_offsets[i]` inside `data`.

**Soundness:** `data` is unverified bytes from this function's perspective. The caller MUST have established that `data` came from a signature-bound envelope (typically: pass `envelope.data` AFTER `verify_ecdsa_over_hash` against a hash derived from that same envelope). Without that ordering, the function proves nothing.

### Convenience wrapper

#### `verify_attestation_hashing(...) -> [Field; 1]`

Composes the four building blocks in the canonical order:

1. `derive_envelope_hash(...)` → `hash`
2. `verify_ecdsa_over_hash(pk, sig, hash)`
3. `match_url_against_allowlist(request_url, allowed_urls)` → matched hash
4. `bind_content_hashes(contents, data, offsets)`

Returns the matched allowed URL's Poseidon2 hash. Most consumers use this directly.

## Usage

### Canonical: full attestation check

```noir
use attestation_verifier::verify_attestation_hashing;

let matched: [Field; 1] = verify_attestation_hashing(
    attestor_x, attestor_y, signature,
    [request_url], allowed_urls,
    contents,
    recipient, request_hmb, response_resolves,
    data, att_conditions, timestamp, addition_params,
    data_hash_offsets,
);
// Now assert `matched[0]` is in your contract's allowed-URL hash set, then act
// on `contents` (price, balance, whatever the attestor revealed).
```

### Non-canonical: single pinned URL prefix

For an oracle that pins one base URL prefix (rather than maintaining an allow-list of full URLs), compose the building blocks directly and skip `match_url_against_allowlist`:

```noir
use attestation_verifier::{derive_envelope_hash, verify_ecdsa_over_hash, bind_content_hashes};

// 1. Reconstruct + verify the signature is over THIS envelope.
let envelope_hash = derive_envelope_hash(
    recipient, [request_url], request_hmb, response_resolves,
    data, att_conditions, timestamp, addition_params,
);
verify_ecdsa_over_hash(attestor_x, attestor_y, signature, envelope_hash);

// 2. Caller-specific URL check (e.g. byte-equality of the first N bytes
//    against a pinned `base_url_prefix`). Skipped here for brevity.
assert_url_starts_with_pinned_prefix(request_url, base_url_prefix);

// 3. Bind each content to the now-signature-bound `data` string.
bind_content_hashes(contents, data, data_hash_offsets);
```

## Generic parameters reference

| Parameter | Used by | Meaning |
|---|---|---|
| `MAX_URL_LEN` | `derive_envelope_hash`, `match_url_against_allowlist`, wrapper | Max bytes per URL (in `request_urls` and `allowed_urls`) |
| `MAX_HMB_LEN` | `derive_envelope_hash`, wrapper | Max bytes of `request.header + method + body` concat |
| `N` | `derive_envelope_hash`, `bind_content_hashes`, wrapper | Number of response-resolve fields per request |
| `MAX_RR_LEN` | `derive_envelope_hash`, wrapper | Max bytes per `response_resolve` entry |
| `MAX_CONTENT_LEN` | `bind_content_hashes`, wrapper | Max bytes per attested content value |
| `MAX_DATA_LEN` | `derive_envelope_hash`, `bind_content_hashes`, wrapper | Max bytes of envelope's `data` JSON |
| `MAX_COND_LEN` | `derive_envelope_hash`, wrapper | Max bytes of envelope's `att_conditions` |
| `MAX_PARAMS_LEN` | `derive_envelope_hash`, wrapper | Max bytes of envelope's `addition_params` |
| `NUM_ALLOWED_URLS` | `match_url_against_allowlist`, wrapper | Number of allow-list slots (generic; upstream was hardcoded at 3) |

`NUM_REQUEST_URLS` is fixed at 1 inside `derive_envelope_hash` (and therefore the wrapper). Lifting it would also require multi-request handling in the off-chain `encodePacked` step.

## Composition soundness

If you call the building blocks directly, the safe order is:

1. `derive_envelope_hash` — produces a verified hash of the envelope you're about to trust.
2. `verify_ecdsa_over_hash` — binds the attestor's signature to that exact hash.
3. **From this point on, all envelope fields are signature-bound**. You can now safely:
   - call `match_url_against_allowlist` (or do your own URL constraint)
   - call `bind_content_hashes` against `envelope.data`

Skipping or reordering this gives you a function that compiles but proves nothing. The wrapper enforces this composition for you.

## See also

- [Root README](../../../README.md) — full PoC context, providers, design decisions, divergences from upstream.
- Example consumer: [`src/nr/examples/quote_verifier/`](../examples/quote_verifier/) — an Aztec contract that uses the wrapper.
- Upstream: [primus-labs/zktls-verification-noir](https://github.com/primus-labs/zktls-verification-noir).
