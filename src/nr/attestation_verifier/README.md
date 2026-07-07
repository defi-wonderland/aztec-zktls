# attestation_verifier

Three Noir cryptographic primitives for proving a Primus zkTLS attestation is valid. Aztec-agnostic; usable in any Noir circuit.

Modified from [primus-labs/zktls-verification-noir](https://github.com/primus-labs/zktls-verification-noir) (commit `65496b7`). Biggest change: in-circuit `keccak256(envelope)` reconstruction that closes upstream [issue #9](https://github.com/primus-labs/zktls-verification-noir/issues/9). See [Divergences](#divergences-from-upstream).

## Install

```toml
[dependencies]
attestation_verifier = { git = "https://github.com/defi-wonderland/aztec-zktls", tag = "vX.Y.Z", directory = "src/nr/attestation_verifier" }
```

Direct deps: `noir-lang/sha256@v0.3.0`, `noir-lang/keccak256@v0.1.3`. **No aztec-nr dependency.**

## API

Three primitives. The lib takes **no policy positions** (no URL matching, allow-list, recipient check, timestamp window). Compose them in canonical order in your consumer.

#### `derive_envelope_hash(...) -> [u8; 32]`

Reconstruct `keccak256(encodePacked(envelope))` byte-for-byte from envelope fields. Byte layout (matches Primus's `encodePacked`):

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

ECDSA-secp256k1 check. Caller is responsible for ensuring `hash` came from a *derived* (not witnessed) source.

#### `bind_content_hashes<N, MAX_CONTENT_LEN, MAX_DATA_LEN>(contents, data, data_hash_offsets)`

For each `c[i]`, assert `sha256(c[i])`'s 64-char lowercase hex appears at `data_hash_offsets[i]` inside `data`.

**Soundness:** `data` is unverified bytes from this function's perspective. Caller MUST pass `envelope.data` AFTER `verify_ecdsa_over_hash` against a hash *derived from that same envelope*. Otherwise the function proves nothing.

## Usage

```noir
use attestation_verifier::{bind_content_hashes, derive_envelope_hash, verify_ecdsa_over_hash};

let envelope_hash = derive_envelope_hash(
    recipient, [request_url], request_hmb, response_resolves,
    data, att_conditions, timestamp, addition_params,
);
verify_ecdsa_over_hash(attestor_x, attestor_y, signature, envelope_hash);
bind_content_hashes(contents, data, data_hash_offsets);

// Now apply your own policy. See QuoteVerifier for a Map-based allow-list pattern.
```

## Generic parameters

| Parameter | Used by | Meaning |
|---|---|---|
| `MAX_URL_LEN` | `derive_envelope_hash` | Max bytes per request URL |
| `MAX_HMB_LEN` | `derive_envelope_hash` | Max bytes of `header + method + body` concat |
| `N` | `derive_envelope_hash`, `bind_content_hashes` | Number of response resolves |
| `MAX_RR_LEN` | `derive_envelope_hash` | Max bytes per `response_resolve` entry |
| `MAX_CONTENT_LEN` | `bind_content_hashes` | Max bytes per attested content value |
| `MAX_DATA_LEN` | `derive_envelope_hash`, `bind_content_hashes` | Max bytes of envelope's `data` JSON |
| `MAX_COND_LEN` | `derive_envelope_hash` | Max bytes of `att_conditions` |
| `MAX_PARAMS_LEN` | `derive_envelope_hash` | Max bytes of `addition_params` |

`NUM_REQUEST_URLS` is fixed at 1 — see [Divergences](#divergences-from-upstream) point 4.

## Composition soundness

The three primitives must be composed in this order:

1. `derive_envelope_hash` → derived hash.
2. `verify_ecdsa_over_hash` → binds signature to that hash.
3. From here on, all envelope fields are signature-bound. Apply any policy (URL match, etc.) and call `bind_content_hashes`.

Skipping or reordering compiles but proves nothing. No wrapper is provided — the composition is short enough that doing it explicitly in your consumer is clearer than hiding it behind a 14-parameter wrapper. See [`QuoteVerifier::verify`](../examples/quote_verifier/src/main.nr).

## Hashing URLs from BoundedVec (consumer gotcha)

`BoundedVec::storage()` returns the underlying `[u8; MAX]` array; bytes past `len()` are **witnessed, not necessarily zero**. Hashing `storage()` directly lets a prover craft trailing bytes for a hash collision.

Safe pattern: copy into a fresh `[Field; MAX]`, zero-padding by construction. The off-chain hasher must apply the same padding. See [QuoteVerifier](../examples/quote_verifier/) for the canonical implementation.

## Trust model: closing the splice attack

Upstream's `verify_attestation_hashing` took `hash` as a function input — the circuit verified ECDSA over it but never tied it to the envelope contents. A prover could pair a real Primus-signed `hash` with invented envelope fields and pass both checks independently ([issue #9](https://github.com/primus-labs/zktls-verification-noir/issues/9)).

This lib reconstructs `keccak256(envelope)` in-circuit and verifies ECDSA over the *derived* hash. There is no opaque `hash` witness to splice — `derived_hash` is constraint-equal to `keccak256(env_bytes)`, and ECDSA forces that equal to the real signed hash.

The chain:

```
signature => derived envelope hash => specific envelope bytes => specific data string => specific SHA256 hex bytes => original content
```

Every arrow is a circuit constraint. Remaining trust assumption: the attestor signs only what it observed over the wire — zkTLS as an oracle with a small trusted set, not trustless TLS.

## Divergences from upstream

Based on upstream `main` at commit `65496b7b99879fc108b68bd7f08296225786a40c`:

1. `sha256_var(..., len as u64)` → `len as u32` (one-char fix for `noir-lang/sha256@v0.3.0`).
2. **`derive_envelope_hash` reconstructs `keccak256(envelope)` in-circuit.** Closes [issue #9](https://github.com/primus-labs/zktls-verification-noir/issues/9). Adds the `noir-lang/keccak256` dep.
3. **Split into three building blocks**: `derive_envelope_hash`, `verify_ecdsa_over_hash`, `bind_content_hashes`. No wrapper — consumers compose explicitly.
4. **`NUM_REQUEST_URLS` fixed at 1**. Primus's protocol unit is `(1 URL → 1 reveal)`; SDK and native attestor only populate slot 0 in practice. Not exposed as a generic until Primus actually ships multi-URL signing with a documented byte layout.
5. **URL allow-list matching removed.** Upstream's `verify_sig_and_urls` was a byte-prefix match with two soundness footguns (longer signed URLs prefix-passing; overlapping-prefix allow-lists letting the prover pick which slot matched). Consumers own URL policy now — see [QuoteVerifier](../examples/quote_verifier/) for a Map-based exact-equality pattern.
6. **Pedersen-commitment path removed** (`verify_attestation_comm`, Grumpkin imports). Restore from upstream if you need it for fields > one SHA256 block.

## See also

- [Root README](../../../README.md) — setup, scripts, repo layout.
- [Examples README](../examples/README.md) — QuoteVerifier design notes.
- Upstream: [primus-labs/zktls-verification-noir](https://github.com/primus-labs/zktls-verification-noir).
