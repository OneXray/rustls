# REALITY hybrid acceptance probe

The later [0.23.45 upstream sync](UPSTREAM-0.23.45.md) preserves this probe and
records new version-specific results. The 0.23.43 results below are historical.

An independent, test-only workspace for the public REALITY key-exchange API.
It does not add an ML-KEM dependency to the rustls library or select a VCore
production provider. Its only path dependency is the rustls crate in this same
repository. No private rustls interface, third-party source patch, AWS-LC,
system proxy, host VPN, or externally addressed proxy target is used.

## Provider and evidence boundary

The adapter wraps the ring provider's public `X25519.start_reality` exchange.
That same exchange supplies the X25519 component of both the hybrid keyshare
and REALITY authentication. `ml-kem` 0.3.2 supplies real ML-KEM-768, with its
`zeroize` feature enabled; ring generates a fresh random seed. Explicit local
temporary secrets are zeroized. The RustCrypto crate states that its
implementation has not been independently audited, so this remains an
acceptance experiment, **not production cryptographic approval**.
[RustCrypto ML-KEM documentation](https://docs.rs/ml-kem/0.3.2/ml_kem/)

The client share is `ML-KEM public key (1184) || X25519 public key (32)`;
the server share is `ML-KEM ciphertext (1088) || X25519 public key (32)`;
the TLS shared secret is `ML-KEM secret (32) || X25519 secret (32)`.
REALITY retains its existing X25519/HMAC/Ed25519 authentication; this probe
does not claim post-quantum authentication.
[Mihomo's uTLS REALITY implementation](https://github.com/MetaCubeX/utls/blob/v1.8.7/reality.go)

The public seams under test are `SupportedKxGroup`/`ActiveKeyExchange`, the
REALITY `ClientConfig` builder, the negotiated TLS group, and bytes delivered
through a real Mihomo VLESS listener to a loopback TCP echo server.

`hybrid` gives the provider **only** the hybrid group; no classical fallback
is possible. `fallback` explicitly adds X25519 and exercises the existing
`hybrid_component` mechanism. A selected hybrid initial share alone does not
imply a policy forbidding fallback: that policy belongs to provider groups.

## Run

From the repository root:

```sh
cargo test --locked --manifest-path reality-tests/Cargo.toml --target-dir target/reality-hybrid-probe
cargo build --locked --manifest-path reality-tests/Cargo.toml --target-dir target/reality-hybrid-probe
cargo clippy --locked --manifest-path reality-tests/Cargo.toml --target-dir target/reality-hybrid-probe --all-targets -- -D warnings
python3 reality-tests/mihomo_loopback.py \
  --mihomo /absolute/path/to/official-latest-mihomo \
  --openssl /absolute/path/to/openssl \
  --probe "$PWD/target/reality-hybrid-probe/debug/reality-hybrid-probe"
```

Download Mihomo from its official **latest** release without a local source
build or GitHub API lookup; pass the resulting binary explicitly. The harness
prints `mihomo -v` and `openssl version`. OpenSSL must support TLS 1.3 and the
`X25519MLKEM768` group. Its camouflage target uses exactly the tested group:
Mihomo's REALITY server mirrors that target's handshake.

The native harness runs six cases:

- Classic X25519 regression and strict hybrid REALITY: VLESS sends 31 bytes and
  receives the exact payload, with the expected negotiated group.
- Explicitly allowed classical fallback: hybrid initial choice, X25519 result,
  and the same end-to-end payload check.
- Strict hybrid against a classic-only target: a TLS `HandshakeFailure` is
  required; an unrelated timeout does not satisfy the test.
- Wrong short ID and wrong valid X25519 server key: an `InvalidCertificate`
  error is required.

All negative cases additionally require zero target connections and zero
target bytes. Processes, echo listeners, certificates, and configurations are
cleaned up after each case. Peer debug logging is disabled, and generated
ephemeral authentication material is never printed. Fixed credentials in the
harness are public, throwaway fixtures, not deployment examples.

## Local result: 2026-09-22

- Four provider tests pass: same-key REALITY authentication plus real hybrid
  agreement, explicit classical fallback, malformed/low-order server shares,
  and low-order authentication-key rejection.
- Native cases pass with official Mihomo v1.19.31 (Go 1.26.8, darwin arm64)
  and OpenSSL 3.6.4. Three successful cases each deliver exactly 31 bytes;
  all three rejection cases report zero target connections and zero bytes.
- This does not validate a VCore production integration, non-macOS execution,
  performance/resource limits, a PQ certificate scheme, or N0's other gates.

The fork's ring-only regression run also passed 241 library tests, 217 existing
API tests and nine REALITY API tests. With REALITY disabled, 227 library and
217 API tests passed. Documentation tests passed 15 and ignored five. The
no-std check and library cross-checks for aarch64-apple-ios and
x86_64-apple-darwin passed; these are not device-runtime evidence.

An additional ring-only `cargo doc --no-deps` build succeeds with seven
pre-existing links to disabled AWS-LC/FIPS symbols. Using
`RUSTDOCFLAGS='-D warnings'` makes that documentation build fail. These
upstream links were not changed or hidden by enabling a different provider.

TDD trace: the initial real-exchange test failed with the unimplemented hybrid
provider; after implementing the adapter it passed. The independent fallback
test then failed because `hybrid_component()` returned `None`; implementing
the public component/completion methods made that slice pass. The fork's API
RED/GREEN and ordinary TLS regressions are recorded separately by its tests.
