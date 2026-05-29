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
