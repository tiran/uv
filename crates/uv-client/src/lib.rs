pub use base_client::{
    AuthIntegration, BaseClient, BaseClientBuilder, ClientBuildError, DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_MAX_REDIRECTS, DEFAULT_READ_TIMEOUT, DEFAULT_READ_TIMEOUT_UPLOAD, DEFAULT_RETRIES,
    ExtraMiddleware, RedirectClientWithMiddleware, RedirectPolicy, RequestBuilder,
    RetryParsingError, fetch_with_url_fallback,
};
pub use cached_client::{CacheControl, CachedClient, CachedClientError, DataWithCachePolicy};
pub use error::{Error, ErrorKind, ProblemDetails, WrappedReqwestError};
pub use file_hash::FileHashError;
pub use flat_index::{FlatIndexClient, FlatIndexEntries, FlatIndexEntry, FlatIndexError};
pub use registry_client::{
    Connectivity, MetadataFormat, MetadataRangeRequest, RegistryClient, RegistryClientBuilder,
    SimpleDetailMetadata, SimpleDetailMetadatum, SimpleIndexMetadata, VersionFiles,
};
pub(crate) use retry::UvRetryableStrategy;
pub use retry::{RetriableError, RetryState, retryable_on_request_failure};
pub use rkyvutil::OwnedArchive;
pub use tls::{CertificateFileError, Certificates};

/// Install the process-wide rustls [`CryptoProvider`] for the selected TLS backend.
///
/// With the default `aws-lc` backend, rustls's compile-time default (aws-lc-rs) provider is used and
/// this is a no-op. With the `ossl` backend, it installs the system-OpenSSL 3.x provider from
/// [`rustls_native_ossl`]. Call this once, early in `main`, before building any TLS client.
///
/// [`CryptoProvider`]: rustls::crypto::CryptoProvider
#[cfg(feature = "ossl")]
pub fn install_crypto_provider() {
    use std::sync::Once;

    static INSTALL: Once = Once::new();
    // `install_default` succeeds only if it sets *our* provider as the process default; an error
    // means a different provider was already installed. rustls exposes no provider identity to
    // check, so requiring success is how we guarantee the OpenSSL provider is active. Silently
    // accepting a foreign provider would bypass the system crypto policy the `ossl` backend
    // enforces, so a conflict (only reachable if `aws-lc` is also enabled) is fatal. The `Once`
    // keeps repeated calls (e.g. across tests) idempotent.
    INSTALL.call_once(|| {
        rustls_native_ossl::default_provider()
            .install_default()
            .expect("expected to install the OpenSSL rustls crypto provider, but another provider was already installed");
    });
}

/// Install the process-wide rustls crypto provider for the selected TLS backend.
///
/// No-op with the default `aws-lc` backend; see the `ossl`-feature variant.
#[cfg(not(feature = "ossl"))]
pub fn install_crypto_provider() {}

mod base_client;
mod cached_client;
mod error;
mod file_hash;
mod flat_index;
mod html;
mod httpcache;
mod linehaul;
mod middleware;
mod registry_client;
mod remote_metadata;
mod retry;
mod rkyvutil;
mod tls;
#[cfg(feature = "ossl")]
mod tls_ossl;
