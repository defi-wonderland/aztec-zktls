# attestation_verifier

Primus zkTLS attestation verifier — three Noir cryptographic primitives for proving a Primus-signed envelope is valid. Aztec-agnostic; usable in any Noir circuit.

Modified from [primus-labs/zktls-verification-noir](https://github.com/primus-labs/zktls-verification-noir) (commit `65496b7`). See [Divergences from upstream](#divergences-from-upstream) below; the biggest is the in-circuit `keccak256(envelope)` reconstruction that closes upstream [issue #9](https://github.com/primus-labs/zktls-verification-noir/issues/9).

## Install

```toml
[dependencies]
attestation_verifier = { git = "https://github.com/defi-wonderland/aztec-zktls-poc", tag = "vX.Y.Z", directory = "src/nr/attestation_verifier" }
```

(Repo rename to `aztec-zktls` pending — update the URL once it lands.)

If you're consuming the lib from another crate inside *this* workspace, use a path dep instead. The bundled example at `src/nr/examples/quote_verifier/` uses `path = "../../attestation_verifier"`.

The lib has **no aztec-nr dependency**. Direct deps are only `noir-lang/sha256@v0.3.0` and `noir-lang/keccak256@v0.1.3`, so the lib drops into any Noir circuit — not just Aztec contracts.

## API

Three building blocks. The lib takes **no policy positions** — no URL matching, no allow-list, no recipient validation, no timestamp window. Consumers compose these primitives in the canonical order (see [Composition soundness](#composition-soundness) below).

#### `derive_envelope_hash(...) -> [u8; 32]`

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

#### `bind_content_hashes<N, MAX_CONTENT_LEN, MAX_DATA_LEN>(contents, data, data_hash_offsets)`

For each content `c[i]`, compute `sha256(c[i])` and assert its 64-character lowercase hex appears at `data_hash_offsets[i]` inside `data`.

**Soundness:** `data` is unverified bytes from this function's perspective. The caller MUST have established that `data` came from a signature-bound envelope (typically: pass `envelope.data` AFTER `verify_ecdsa_over_hash` against a hash derived from that same envelope). Without that ordering, the function proves nothing.

## Usage

```noir
use attestation_verifier::{bind_content_hashes, derive_envelope_hash, verify_ecdsa_over_hash};

// 1. Reconstruct keccak256(envelope) from the witnessed fields.
let envelope_hash = derive_envelope_hash(
    recipient, [request_url], request_hmb, response_resolves,
    data, att_conditions, timestamp, addition_params,
);

// 2. ECDSA-verify the signature against the *derived* hash. After this returns,
//    every envelope field is provably what the attestor signed.
verify_ecdsa_over_hash(attestor_x, attestor_y, signature, envelope_hash);

// 3. Bind each content's SHA256 hex into the (now signature-bound) data string.
bind_content_hashes(contents, data, data_hash_offsets);

// Now apply your own policy — URL allow-list, recipient identity, timestamp
// window, anything else. See the QuoteVerifier example for the canonical
// Map<Field, PublicImmutable<bool>> URL-hash lookup pattern.
```

## Generic parameters reference

| Parameter | Used by | Meaning |
|---|---|---|
| `MAX_URL_LEN` | `derive_envelope_hash` | Max bytes per request URL |
| `MAX_HMB_LEN` | `derive_envelope_hash` | Max bytes of `request.header + method + body` concat |
| `N` | `derive_envelope_hash`, `bind_content_hashes` | Number of response-resolve fields per request |
| `MAX_RR_LEN` | `derive_envelope_hash` | Max bytes per `response_resolve` entry |
| `MAX_CONTENT_LEN` | `bind_content_hashes` | Max bytes per attested content value |
| `MAX_DATA_LEN` | `derive_envelope_hash`, `bind_content_hashes` | Max bytes of envelope's `data` JSON |
| `MAX_COND_LEN` | `derive_envelope_hash` | Max bytes of envelope's `att_conditions` |
| `MAX_PARAMS_LEN` | `derive_envelope_hash` | Max bytes of envelope's `addition_params` |

`NUM_REQUEST_URLS` is fixed at 1 inside `derive_envelope_hash` — see [Divergences](#divergences-from-upstream) point 4.

## Composition soundness

The three primitives must be composed in this order:

1. `derive_envelope_hash` — produces a derived hash of the envelope you're about to trust.
2. `verify_ecdsa_over_hash` — binds the attestor's signature to that exact hash.
3. **From this point on, all envelope fields are signature-bound.** You can safely:
   - apply any policy check (URL match, recipient identity, timestamp window, etc.)
   - call `bind_content_hashes` against `envelope.data`

Skipping or reordering this gives you a function that compiles but proves nothing. The lib does not provide a wrapper that enforces the order — the composition is short enough (3 calls) that doing it explicitly in your consumer is clearer than hiding it behind a 14-parameter wrapper. See [`QuoteVerifier::verify`](../examples/quote_verifier/src/main.nr) for the canonical example.

## Hashing URLs from BoundedVec (consumer gotcha)

A common consumer pattern after running the three primitives: hash the now-signature-bound request URL to compare against an allow-list of URL hashes in storage. There's a subtle trap when hashing a `BoundedVec<u8, MAX_URL_LEN>`.

**The trap:** `BoundedVec::storage()` returns the underlying `[u8; MAX_URL_LEN]` array, and bytes at positions `>= len()` are **witnessed values, not necessarily zero**. A prover could craft trailing bytes that produce a hash colliding with an allow-listed URL's hash if you feed `storage()` straight into a hash function.

**The safe pattern:** copy into a fresh `[Field; MAX_URL_LEN]`, zero-padding by construction:

```noir
use aztec::protocol::hash::poseidon2_hash;

let mut hash_input: [Field; MAX_URL_LEN] = [0; MAX_URL_LEN];
for j in 0..MAX_URL_LEN {
    if j < url.len() {
        hash_input[j] = url.storage()[j] as Field;
    }
}
let url_hash = poseidon2_hash(hash_input);
```

Off-chain hashers must apply the same zero-padding to `MAX_URL_LEN` so the hashes agree. QuoteVerifier uses this pattern; see [examples README](../examples/README.md).

## Trust model: closing the splice attack

Upstream's `verify_attestation_hashing` took `hash` as a function input — the circuit verified ECDSA over it but never tied it to the envelope contents. A prover could pair a real Primus-signed `hash` with envelope fields they invented and pass both checks independently. Upstream issue [#9](https://github.com/primus-labs/zktls-verification-noir/issues/9) flags this.

This lib closes the gap by reconstructing `keccak256(envelope)` in-circuit from the witnessed envelope fields and verifying ECDSA over the *derived* hash. There is no opaque `hash` witness to splice with anymore — `derived_hash` is constraint-equal to `keccak256(env_bytes)`, and ECDSA forces that equal to the real signed hash. Any prover supplying envelope fields different from what the attestor signed fails ECDSA at step 2 of the canonical composition.

The end-to-end chain a consumer gets:

```
signature => derived envelope hash => specific envelope bytes => specific data string => specific SHA256 hex bytes => original content
```

Every arrow is a circuit constraint. The remaining trust assumption sits with the attestor itself (it signs only what it actually observed over the wire) — zkTLS as an oracle with a small trusted set, not trustless TLS.

## Divergences from upstream

Primus's Noir lib lives at <https://github.com/primus-labs/zktls-verification-noir> as a subdirectory of a monorepo. They never publish git tags, and Nargo's git-dep mechanism requires a `tag` (no `rev` or `branch`) — so importing the lib over git isn't possible without forking and self-tagging.

This lib is based on upstream `main` at commit `65496b7b99879fc108b68bd7f08296225786a40c`. Divergences:

1. **`sha256_var(..., len as u64)` → `len as u32`** because `noir-lang/sha256` v0.3.0 (aztec-nr 4.3.0 compatible) tightened the length-arg type. One-character mechanical fix.

2. **`derive_envelope_hash` reconstructs `keccak256(envelope)` in-circuit.** Closes upstream issue [#9](https://github.com/primus-labs/zktls-verification-noir/issues/9) — see [Trust model](#trust-model-closing-the-splice-attack) above. Adds the `noir-lang/keccak256` dep.

3. **Monolithic verifier split into three building blocks** — `derive_envelope_hash`, `verify_ecdsa_over_hash`, `bind_content_hashes`. No wrapper: consumers compose them explicitly in their `verify` function (the canonical order is enforced by the type flow, not by a wrapping function).

4. **`NUM_REQUEST_URLS` dropped from 2 to 1.** Primus's protocol unit is `(1 URL -> 1 reveal)` — see the multi-resolve discussion in the [examples README](../examples/README.md#dont-attest-multiple-fields-from-the-same-url-structural-limit-not-a-bug). Real attestations always carry exactly one request URL; lifting back to 2+ would also require multi-request handling in the off-chain `encodePacked` parser.

    *Could we expose it as a generic instead of fixing it at 1?* Mechanically yes — the URL side would mirror the `response_resolves` loop in `derive_envelope_hash` (~30 lines). We deliberately don't, for two reasons. **(a)** Primus's SDK + native attestor only ever populate slot 0 even when given multi-URL input (the JS SDK reads `responseResolve[0]` only; the native binary stamps the same hash across all slots), so there's no real envelope shape with `N > 1` to verify a circuit against today. **(b)** Upstream's old `N = 2` byte layout was never exercised end-to-end; if Primus ever ships multi-URL signing for real, we'd want their spec'd layout at that point, not a guess now. Until then, a `NUM_REQUEST_URLS` generic would be a knob no one can turn. Revisit when Primus ships it.

5. **URL allow-list matching removed entirely.** Upstream's `verify_attestation_hashing` baked in a `verify_sig_and_urls` step that took a fixed-size allow-list and did a byte-prefix match. We initially kept it (as `match_url_against_allowlist`) and patched a one-character bug in its `starts_with` helper. Two soundness footguns surfaced on review: (a) the constrained loop only checked bytes up to `allowed_url.len()`, so a longer signed request URL with the allowed URL as a prefix would pass; (b) the unconstrained index choice was only implicitly pinned by the byte-equality loop, so overlapping-prefix allow-lists let the prover pick which slot's hash got returned. Cleanest fix: remove URL matching from the lib entirely. Consumers own URL policy — see [QuoteVerifier](../examples/quote_verifier/) for the canonical Map-based exact-equality pattern. Side effects: the lib no longer depends on `aztec-nr` (`poseidon2_hash` was only used here), the unconstrained `starts_with` / `get_allowed_url_index` helpers are gone, and the upstream `starts_with` patch is gone.

6. **Pedersen-commitment path removed** (`verify_attestation_comm`, `verify_commitment_group`, the Grumpkin imports). The commitment-mode is useful when an attested field exceeds a single SHA256 block; restore from upstream if you need it.

## See also

- [Root README](../../../README.md) — setup, scripts, repo layout.
- [Examples README](../examples/README.md) — consumer-side design notes for the QuoteVerifier example.
- Upstream: [primus-labs/zktls-verification-noir](https://github.com/primus-labs/zktls-verification-noir).
