# Plan: Optional native-tls Support for Downstream Rebuilds

## Motivation

Support downstream rebuilders (distro packagers, enterprise forks) who need to build
uv against the system OpenSSL for FIPS compliance and post-quantum cryptography (PQC)
support. The system OpenSSL may be configured with FIPS modules, PQC providers
(oqs-provider), or governed by system crypto policies (e.g., Fedora/RHEL).

## Design

Add compile-time `rustls-tls` (default) and `native-tls` cargo features to
`uv-client`, forwarded through the top-level `uv` crate.

Following maturin's dual-backend approach, the two features are **additive, not
mutually exclusive**. Cargo features are additive by design, so a mutually
exclusive scheme (e.g. `compile_error!` when both or neither is set) breaks under
the feature combinations upstream CI exercises:

- `--all-features` enables *both* backends simultaneously.
- `cargo publish --workspace` builds each crate in isolation; dependents pull
  `uv-client` in with `default-features = false`, i.e. with *neither* backend.

To build cleanly in every combination there are three cfg states:

- `#[cfg(feature = "rustls-tls")]` -- rustls always wins the tie, so the default
  build and `--all-features` behave identically to upstream.
- `#[cfg(all(feature = "native-tls", not(feature = "rustls-tls")))]` -- native-tls
  code is active only when rustls is *not* also selected. When this is the only
  backend, OpenSSL handles all certificate management, trust store access, and TLS
  negotiation natively.
- `#[cfg(not(any(feature = "rustls-tls", feature = "native-tls")))]` -- a "neither
  backend" fallback of inert stubs so `uv-client` still compiles when reqwest is
  built without any TLS backend.

### How to build with native-tls

```sh
cargo build -p uv --no-default-features --features native-tls
```

This disables the default `rustls-tls` feature and activates `native-tls` instead,
pulling in system OpenSSL via the `native-tls` crate. No workspace-level patching
is required -- the feature flags handle everything.

## Scope of Changes

### 1. Workspace `Cargo.toml`

- **Removed** `"rustls"` from the workspace-level `reqwest` dependency features.
  TLS backend selection is now controlled solely by `uv-client`'s feature flags
  (`rustls-tls` enables `reqwest/rustls`, `native-tls` enables `reqwest/native-tls`).
- **Set** `default-features = false` on the workspace `uv-client` dependency so that
  downstream crates don't implicitly activate `rustls-tls` via Cargo feature
  unification. Because features are additive there is no way to turn a backend
  *off* once a dependent enables it, so the default has to be "no backend" at the
  workspace level; the `uv` crate's own `default` features re-enable `rustls-tls`.
- **Added** `openssl = { version = "0.10.81" }` as a workspace dependency, consumed
  (optionally) by `uv-client` only under the `native-tls` feature.

### 2. `crates/uv-client/Cargo.toml`

- Added features:
  ```toml
  [features]
  default = ["rustls-tls"]
  rustls-tls = [
      "dep:rustls",
      "dep:rustls-native-certs",
      "dep:rustls-pki-types",
      "dep:webpki",
      "dep:webpki-root-certs",
      "dep:x509-parser",
      "reqwest/rustls",
  ]
  native-tls = ["dep:openssl", "reqwest/native-tls"]
  ```
- Made six dependencies optional: `rustls`, `rustls-native-certs`, `rustls-pki-types`,
  `webpki`, `webpki-root-certs`, `x509-parser`
- Added `openssl = { workspace = true, optional = true }`, activated only by the
  `native-tls` feature. It is used to classify TLS certificate errors in
  `retry.rs` (see below).

### 3. `crates/uv/Cargo.toml`

- Added TLS feature forwarding:
  ```toml
  default = ["rustls-tls", "performance", "uv-distribution/static", "test-defaults"]
  rustls-tls = ["uv-client/rustls-tls"]
  native-tls = ["uv-client/native-tls"]
  ```
  The `uv` binary re-adds `rustls-tls` here so the default build is unchanged even
  though the workspace `uv-client` dependency sets `default-features = false`.

### 4. `crates/uv-client/src/tls/` (module directory)

Restructured from a single `tls.rs` file into a `tls/` module directory:

- **`tls/mod.rs`** -- shared types and backend-dispatched logic:
  - No `compile_error!` guards -- the features are additive (see Design).
  - Shared imports (`std::io::{self, Read}`, `reqwest::Identity`), the
    `CertificateError` enum, and `read_identity()` are gated behind
    `#[cfg(any(feature = "rustls-tls", feature = "native-tls"))]` so they vanish
    in the neither-backend build (where `reqwest::Identity` is unavailable).
  - `read_identity()` has a cfg-gated body:
    - `#[cfg(feature = "rustls-tls")]`: `Identity::from_pem(&buf)` -- reqwest's
      rustls backend accepts a combined PEM buffer with certificate chain and key.
    - `#[cfg(all(feature = "native-tls", not(feature = "rustls-tls")))]`:
      `Identity::from_pkcs8_pem(&buf, &buf[key_start..])` -- reqwest's native-tls
      backend requires the key argument to start with a
      `-----BEGIN PRIVATE KEY-----` PEM header. The full buffer is passed as the
      cert argument (OpenSSL's `X509::stack_from_pem` ignores non-certificate PEM
      sections). The key slice starts at the PKCS#8 marker found via byte scanning.
  - Conditional `mod rustls` and `pub use self::rustls::{CertificateFileError, Certificates}`
    re-export, both gated behind `#[cfg(feature = "rustls-tls")]`.

- **`tls/rustls.rs`** -- all rustls-specific certificate management (~400 lines):
  - `Certificates` struct (webpki root loading, `SSL_CERT_FILE`/`SSL_CERT_DIR`
    parsing, DER validation via `anchor_from_trusted_cert`).
  - Internal types: `CertificateSource`, `DiagnosticCertificate`,
    `InvalidCertificateWarning`, `InvalidCertificateReason`.
  - All unit tests (`test_from_ssl_cert_file_*`, `test_from_ssl_cert_dir_*`,
    `test_merge_deduplicates`, `test_webpki_roots_not_empty`).

### 5. `crates/uv-client/src/base_client.rs`

- `reqwest::Certificate` import gated `#[cfg(any(feature = "rustls-tls", feature = "native-tls"))]`.
  In the neither-backend build reqwest does not expose `Certificate`, so a
  `type Certificate = std::convert::Infallible` placeholder is defined under
  `#[cfg(not(any(...)))]` -- it keeps signatures resolving while being
  uninhabited (never constructible).
- `warn_user_once` and `crate::tls::read_identity` imports gated
  `#[cfg(any(feature = "rustls-tls", feature = "native-tls"))]`.
- `CertificateSource` enum: `WebPki` and `Custom` variants gated behind
  `#[cfg(feature = "rustls-tls")]`; the `System` variant gated
  `#[cfg(any(feature = "rustls-tls", feature = "native-tls"))]` (never constructed
  in the neither build).
- In `create_secure_and_insecure_clients()`:
  - `#[cfg(feature = "rustls-tls")]`: load custom certs from env via
    `Certificates::from_env()`, determine `CertificateSource` (Custom / System / WebPki).
  - `#[cfg(all(feature = "native-tls", not(feature = "rustls-tls")))]`: skip custom
    cert loading (OpenSSL handles `SSL_CERT_FILE` and `SSL_CERT_DIR` natively), set
    source to `CertificateSource::System`.
  - `#[cfg(not(any(...)))]`: `let (custom_certs, certificate_source) =
    (None::<Vec<Certificate>>, CertificateSource::Unknown);`.
  - The `danger_accept_invalid_certs` / `security` match is gated `any(...)`; the
    neither arm discards it with `let _ = security;`.
- In `create_client()`:
  - `#[cfg(feature = "rustls-tls")]`: call `.tls_backend_rustls()`, apply cert
    source logic with `tls_certs_only()`.
  - native-tls: no explicit backend call (reqwest selects native-tls automatically),
    no certificate configuration needed (system TLS stack handles it). The
    `custom_certs` parameter is discarded with `let _ = custom_certs`, gated
    `#[cfg(not(feature = "rustls-tls"))]`.
  - The mTLS `read_identity` block is gated `any(...)`.
  - `create_client()` carries `#[cfg_attr(not(feature = "rustls-tls"),
    allow(clippy::needless_pass_by_value))]` because `custom_certs` is consumed
    only on the rustls path.

### 6. `crates/uv-client/src/retry.rs`

- Gated `use rustls::{AlertDescription, Error as RustlsError}` behind
  `#[cfg(feature = "rustls-tls")]`, and added `use openssl::error::ErrorStack`
  behind `#[cfg(all(feature = "native-tls", not(feature = "rustls-tls")))]`.
- `is_tls_certificate_error()` classifies certificate failures identically under
  both backends, so retry behavior does not depend on the TLS backend:
  - `#[cfg(feature = "rustls-tls")]`: unchanged from upstream -- matches
    `RustlsError::InvalidCertificate`, `NoCertificatesPresented`, and the
    hand-picked list of certificate-related `AlertDescription` variants.
  - `#[cfg(all(feature = "native-tls", not(feature = "rustls-tls")))]`: inspects the
    nested [`ErrorStack`] for an OpenSSL error in the SSL library (`ERR_LIB_SSL`)
    whose reason code is either `SSL_R_CERTIFICATE_VERIFY_FAILED` (local
    verification failure) or a certificate-related TLS alert (encoded as
    `SSL_AD_REASON_OFFSET + <alert>`). The alert list mirrors the rustls
    `AlertDescription` set. Non-certificate TLS failures (e.g. a received
    `internal_error` alert) remain retryable, matching the rustls path.
  - `#[cfg(not(any(feature = "rustls-tls", feature = "native-tls")))]`: `let _ =
    reqwest_err; false` -- no TLS backend, nothing to classify.
- The OpenSSL constants (`ERR_LIB_SSL = 20`, `SSL_R_CERTIFICATE_VERIFY_FAILED = 134`,
  `SSL_AD_REASON_OFFSET = 1000`, and the certificate alert-description list) are
  defined locally and gated behind
  `#[cfg(all(feature = "native-tls", not(feature = "rustls-tls")))]`; they are not
  re-exported by `openssl-sys` but are stable across OpenSSL 1.1.1 and 3.x.

### 7. `crates/uv-client/src/error.rs`

- `with_certificate_source()`: rustls path checks `is_ssl()` and attaches the
  source; other paths discard the argument via
  `#[cfg(not(feature = "rustls-tls"))] let _ = certificate_source;` and carry
  `#[cfg_attr(not(feature = "rustls-tls"), allow(unused_mut))]`.
- `suggests_system_certs()`: rustls path checks for a `WebPki` certificate source;
  otherwise returns `false` under `#[cfg(not(feature = "rustls-tls"))]` (system
  certs are always used). Carries
  `#[cfg_attr(not(feature = "rustls-tls"), allow(clippy::unused_self))]`.

### 8. Files NOT changed

- **`uv-cli`, `uv-settings`**: `--system-certs` / `--native-tls` flags remain;
  `--system-certs` becomes a no-op under native-tls (system certs are always used).
- **Test server infrastructure** (`tests/it/http_util.rs`): `tokio-rustls` remains
  a dev-dependency; the test server uses rustls unconditionally regardless of the
  client TLS backend. There is no OpenSSL-based equivalent test server, so the `it`
  integration tests only build under `rustls-tls`.
- **Integration tests** (`tests/it/ssl_certs.rs`): no changes; they test the
  rustls path which remains the default.

## Cfg Guard Convention

Because the features are additive, the gates encode a strict precedence rather than
positive-only checks:

- `#[cfg(feature = "rustls-tls")]` -- rustls-specific code; rustls always wins.
- `#[cfg(all(feature = "native-tls", not(feature = "rustls-tls")))]` -- native-tls
  code, active only when rustls is *not* also selected.
- `#[cfg(any(feature = "rustls-tls", feature = "native-tls"))]` -- code shared by
  both backends (e.g. `read_identity`, `reqwest::Certificate` usage).
- `#[cfg(not(any(feature = "rustls-tls", feature = "native-tls")))]` -- the
  neither-backend fallback of inert stubs.

The `not()` in the native-tls gate is what makes `--all-features` compile: with both
features on, only the rustls arms are active and the native arms are elided, so the
two backends never both try to configure reqwest.

## Behavioral Differences Under native-tls

| Aspect | rustls-tls (default) | native-tls |
|--------|---------------------|------------|
| Default trust store | Bundled Mozilla roots | System OpenSSL trust store |
| `--system-certs` | Switches to system roots | No-op (always system) |
| `SSL_CERT_FILE`/`SSL_CERT_DIR` | Loaded by uv, validated by webpki | Handled natively by OpenSSL |
| `SSL_CLIENT_CERT` | `Identity::from_pem` (combined PEM) | `Identity::from_pkcs8_pem` (split cert/key) |
| Certificate validation warnings | Detailed per-cert diagnostics | Delegated to OpenSSL |
| TLS certificate retry detection | Matches `RustlsError` variants | Matches OpenSSL `ErrorStack` reason codes (equivalent classification) |
| FIPS mode | Not supported | Inherited from system OpenSSL |
| PQC key exchange | Not supported | Inherited from system OpenSSL/provider |

## Build Requirements for native-tls

Downstream build environments need:
- `openssl-devel` (or equivalent) and `pkg-config`
- System OpenSSL >= 1.0.2 (for ALPN/HTTP2 support)
- For FIPS: OpenSSL configured with FIPS provider
- For PQC: OpenSSL 3.5+ or oqs-provider

## Verification

The following commands confirm the build is clean in every feature combination:

```sh
# Default build (rustls) still works
cargo build -p uv --profile fast-build
cargo clippy -p uv-client
cargo test -p uv-client --lib

# native-tls only
cargo build -p uv --profile fast-build --no-default-features --features native-tls
cargo clippy -p uv-client --no-default-features --features native-tls
cargo test -p uv-client --no-default-features --features native-tls --lib

# Both backends at once (as upstream CI runs `--all-features`); rustls wins
cargo clippy -p uv-client --all-features

# Neither backend (as `cargo publish` builds dependents in isolation)
cargo clippy -p uv-client --no-default-features

# Verify no rustls dependency in the native-tls-only build
cargo tree -p uv --no-default-features --features native-tls -i rustls
# -> "nothing to print"

# Verify no aws-lc dependency
cargo tree -p uv --no-default-features --features native-tls -i aws-lc-rs
# -> "error: package ID specification `aws-lc-rs` did not match any packages"
```
