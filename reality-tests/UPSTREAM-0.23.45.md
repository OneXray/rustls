# Upstream 0.23.45 synchronization

Date: 2026-09-23. Local branch: `chore/sync-rustls-0.23.45`.
This is a fork synchronization and regression check, not a published dependency
or a completed VCore integration. No remote branch was changed.

## Inputs and merge

- Fork parent: `4334fcf00f60188cfdf3c25d2e6cb4a342a01864`, including the classic
  and explicit hybrid REALITY interfaces.
- Official upstream tag `v/0.23.45`:
  `2976d90fd1c2db6b518700dd101b714069cfcb17`, fetched from
  `https://github.com/rustls/rustls.git`.
- [Official stable release](https://github.com/rustls/rustls/releases/tag/v/0.23.45)
  includes handshake alignment and HRR corrections. Import the upstream release
  unchanged; do not reimplement its fixes in the fork.
- One conflict, in `bogo/Cargo.toml`: preserve the fork's `reality` feature while
  accepting upstream's removal of the obsolete PostQuantum shim dependency.
  Its implementation is now in the main upstream crate. The upstream removal of
  `bogo/fetch-and-build` is retained; its history remains available in Git.
- REALITY remains connection-local, ring-based and feature-gated. Default
  REALITY remains X25519. Hybrid selection, same-key authentication, failure
  cleanup and explicit fallback policy are retained without additional changes.
  Update the independent probe lockfile to the same local rustls 0.23.45.

The tested `git diff HEAD` over source and lockfiles (excluding this report and
the README pointer) has SHA-256
`aecb16150f58d0220c896e1cc52418ca49547f97b77bddb7381c3d8a2e845dae`.
Testing precedes the merge commit; no later commit ID is claimed as its input.
Main Cargo.lock: `f2d5da98fe626e981ccc924e7ea905b69e77f259e612d5558826fdea48d37c6b`.
Probe Cargo.lock: `2e0a8d454345e6226bd3e23afc2aae04bc7d42e0517b3e475ff39a148efbfde3`.

## Executed checks

Host: macOS 27 ARM64, Rust/Cargo 1.98.1. Logs are under
`target/sync-0.23.45/`. All commands start in the fork root.

| Command / scope | Result |
| --- | --- |
| `cargo test --locked -p rustls --no-default-features --features ring,std,tls12,reality --lib --test api --test reality` | 246 library + 222 API + 9 REALITY tests pass |
| Same command with `--release` | Same 477 tests pass |
| `cargo test --locked -p rustls --no-default-features --features ring,std,tls12 --lib --test api` | 232 library + 222 API tests pass with REALITY disabled |
| `cargo test --locked -p rustls --no-default-features --features ring,std,tls12,reality --doc` | 15 pass, 5 ignored |
| `cargo clippy --locked -p rustls --no-default-features --features ring,std,tls12,reality --lib --test reality -- -D warnings` | Pass |
| `cargo check --locked -p bogo` | Pass; conflict resolution compiles, not a full BoringSSL runner execution |
| `cargo check --locked -p rustls --lib --no-default-features --features ring,reality` | no-std check passes |
| Previous check with `ring,std,tls12,reality` and `--target aarch64-apple-ios`, `x86_64-apple-darwin`, `aarch64-linux-android` | Three cross-checks pass; Android NDK 28.2.13676358/API 24 with target-specific CC/AR |
| `cargo tree --locked -p rustls --no-default-features --features ring,std,tls12,reality -e normal` | ring 0.17.14, one local rustls, no AWS-LC in the production graph |
| Probe `cargo test/build --locked --manifest-path reality-tests/Cargo.toml --target-dir target/reality-hybrid-probe` | Four provider tests and native build pass |
| Probe clippy with `--all-targets -- -D warnings` | Pass |
| Root/probe `cargo fmt … -- --check`, `git diff --check` and staged diff check | Pass |

Upstream development dependencies and Bogo can build AWS-LC for their own test
providers. This does not change the ring-only production graph.

## Native Mihomo evidence

Run the existing `mihomo_loopback.py` with explicit `--mihomo`, `--openssl` and
`--probe` paths as documented in the README. Mihomo was freshly downloaded from
the official latest release, without an API request, local compilation or stale
cache fallback. Observed version: v1.19.31 / Go 1.26.8 / darwin arm64;
binary SHA-256 `fae1f37e28ee53fcf5be7a8bb121099db1fe442e44205734ed49c62579364090`.
OpenSSL 3.6.4 supplies the loopback camouflage server.

All six native cases pass: classic, strict hybrid and explicitly permitted
classical fallback each exchange exactly 31 bytes through a VLESS listener;
strict-hybrid/classic-target mismatch, wrong short ID and wrong public key each
produce the required TLS error with zero target connections and bytes. The
negotiated group is checked, not inferred from the initial ClientHello offer.
Owned processes, temporary credentials/configuration and listeners are cleaned
up. No host routes, DNS, VPN or firewall are changed.

| Log | SHA-256 |
| --- | --- |
| `reality-debug.log` | `b4d859dabde008c1c8451dbeca263f67cae3d6ca947bc6986bf307a3ef9d2659` |
| `reality-release.log` | `de231496b031df2c086cc67ccc80a07894162ea2263341b556a777380d54486e` |
| `tls-debug.log` | `211e82d6b7a8e86e8a650de6bddb484d36955651938dd39caa61fa3c485cf330` |
| `mihomo.log` | `2043b04d60cfc14a3149757402640676a2f9e0e0d66d0430e9e11d474b9a35f7` |

## Remaining gates

No VCore production manifest or lockfile is changed to use this unpublished
revision. Publishing the approved dependency branch and subsequent VCore
integration/audits require a separate authorized step. Windows, physical
devices, full platform builds, upstream Bogo/fuzz campaigns, remote CI and
release packaging are not tested by this report. Ordinary TLS results above are
local API tests, not VCore's application data path.

This imports the stable upstream dependency graph; it is not a claim that every
transitive or test dependency is independently at its newest major version.
VCore's newly required latest-stable dependency audit and remaining upgrades
must be evaluated separately, including source/provider compatibility.
