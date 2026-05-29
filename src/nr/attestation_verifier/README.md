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

## Trust model: closing the splice attack

Upstream's `verify_attestation_hashing` took `hash` as a function input — the circuit verified ECDSA over it but never tied it to the envelope contents. A prover could pair a real Primus-signed `hash` with envelope fields they invented and pass both checks independently. Upstream issue [#9](https://github.com/primus-labs/zktls-verification-noir/issues/9) flags this.

This lib closes the gap by reconstructing `keccak256(envelope)` in-circuit from the witnessed envelope fields and verifying ECDSA over the *derived* hash. There is no opaque `hash` witness to splice with anymore — `derived_hash` is constraint-equal to `keccak256(env_bytes)`, and ECDSA forces that equal to the real signed hash. Any prover supplying envelope fields different from what the attestor signed fails ECDSA at step 2 of the canonical composition.

The end-to-end chain a consumer gets:

```
signature ⇒ derived envelope hash ⇒ specific envelope bytes ⇒ specific data string ⇒ specific SHA256 hex bytes ⇒ original content
```

Every ⇒ is a circuit constraint. The remaining trust assumption sits with the attestor itself (it signs only what it actually observed over the wire) — zkTLS as an oracle with a small trusted set, not trustless TLS.

## Divergences from upstream

Primus's Noir lib lives at <https://github.com/primus-labs/zktls-verification-noir> as a subdirectory of a monorepo. They never publish git tags, and Nargo's git-dep mechanism requires a `tag` (no `rev` or `branch`) — so importing the lib over git isn't possible without forking and self-tagging.

This lib is based on upstream `main` at commit `65496b7b99879fc108b68bd7f08296225786a40c` with the following local divergences. All are documented inline at their call sites.

**Patches:**

1. `starts_with`'s strict `haystack.len() > needle.len()` relaxed to `>=` so a request URL byte-equal to an allowed URL passes. See [the patch in detail](#the-starts_with-patch) below.
2. `sha256_var(..., len as u64)` → `len as u32` because `noir-lang/sha256` v0.3.0 (aztec-nr 4.3.0 compatible) tightened the length-arg type. One-character mechanical fix.

**Larger rewrites:**

3. **`derive_envelope_hash` reconstructs `keccak256(envelope)` in-circuit.** Closes upstream issue [#9](https://github.com/primus-labs/zktls-verification-noir/issues/9) — see [Trust model](#trust-model-closing-the-splice-attack) above. Adds the `noir-lang/keccak256` dep.
4. **Monolithic verifier split into building blocks** — `derive_envelope_hash`, `verify_ecdsa_over_hash`, `match_url_against_allowlist`, `bind_content_hashes`. The original `verify_attestation_hashing` remains as a canonical-order wrapper. Consumers with non-canonical needs (e.g. a single pinned URL prefix, no allow-list) call the building blocks directly.
5. **`NUM_REQUEST_URLS` dropped from 2 to 1.** Primus's protocol unit is `(1 URL → 1 reveal)` — see the multi-resolve discussion in the [examples README](../examples/README.md#dont-attest-multiple-fields-from-the-same-url-structural-limit-not-a-bug). Real attestations always carry exactly one request URL; lifting back to 2+ would also require multi-request handling in the off-chain `encodePacked` parser.
6. **`NUM_ALLOWED_URLS` lifted to a generic.** Was hardcoded at 3 upstream; now a generic parameter of `match_url_against_allowlist` and the wrapper. Consumers pick whatever fits.
7. **Pedersen-commitment path removed** (`verify_attestation_comm`, `verify_commitment_group`, the Grumpkin imports). The commitment-mode is useful when an attested field exceeds a single SHA256 block; restore from upstream if you need it.

## The `starts_with` patch

Upstream's unconstrained `starts_with` helper and its caller `get_allowed_url_index` disagree about whether equal-length inputs are valid:

```rust
// caller permits equal length:
if (allowed_url.len() <= request_url.len()) {
    let result = starts_with(request_url, allowed_url);
}

// callee rejects equal length:
assert(haystack.len() > needle_length, "haystack shorter than needle");  // strict >
```

You hit this whenever the request URL is byte-identical to an entry in `allowedUrls` — a natural pattern when the allow-list pins full URLs (so the URL match itself commits to specific query parameters). The QuoteVerifier example uses exactly this pattern; see the [examples README](../examples/README.md#why-the-allowed-urls-contain-the-ticker-symbol) for the consumer-side context, including [the alternatives we tried off-circuit](../examples/README.md#why-the-patch-instead-of-a-workaround) before settling on the patch.

### What the patch is

One character, inside the `unconstrained fn starts_with` helper:

```diff
- assert(haystack.len() > needle_length, "haystack shorter than needle");
+ assert(haystack.len() >= needle_length, "haystack shorter than needle");
```

### Why it's safe

1. **`starts_with` is `unconstrained`.** Unconstrained functions run as hints during witness generation — their assertions are runtime checks, never circuit constraints. They don't enter the proof.

2. **The actual cryptographic prefix check is constrained, and already handles equal-length inputs.** Inside `match_url_against_allowlist`:

    ```rust
    for j in 0..MAX_URL_LEN {
        if j < allowed_url.len() {
            assert_eq(request_urls[i].storage()[j], allowed_url.storage()[j], "URL check failed");
        }
    }
    ```

    The loop iterates `j < allowed_url.len()` positions, both within bounds, and asserts byte equality. For `request == allowed` (equal length), it proves prefix-which-equals-equality — correctly.

3. **The loop body of `starts_with` itself agrees with `>=`.** Its `for j in 0..needle_length` requires `haystack.get(j)` to succeed for `j` up to `needle_length - 1`, which needs `haystack.len() >= needle_length`. The strict `>` was an off-by-one that disagreed with both the loop body's actual safety boundary and the caller's `<=` gate.

So loosening the guard from `>` to `>=` doesn't change what the circuit *proves*, doesn't expose any byte the constrained path didn't already see, and aligns three places in the file that were inconsistent.

### Proper fix

Open an upstream PR at `primus-labs/zktls-verification-noir` flipping that one operator. Once it merges and Primus tags a release that Nargo can `tag`-import, this local copy can be deleted in favor of a git-dep, ending the local divergence.

## See also

- [Root README](../../../README.md) — setup, scripts, repo layout.
- [Examples README](../examples/README.md) — consumer-side design notes for the QuoteVerifier example.
- Upstream: [primus-labs/zktls-verification-noir](https://github.com/primus-labs/zktls-verification-noir).
