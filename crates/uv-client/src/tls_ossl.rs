//! Custom rustls [`ClientConfig`] for the `ossl` backend.
//!
//! The server certificate is verified by OpenSSL's own X.509 machinery (full chain and hostname, via
//! `X509_verify_cert`) rather than rustls-webpki. rustls-webpki could perform this verification
//! instead; OpenSSL is used so the system crypto module owns path validation as well as the
//! primitives. reqwest passes a preconfigured rustls config through verbatim, so this also sets ALPN
//! and mTLS, which reqwest would otherwise handle.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use rustls::ClientConfig;
use rustls_native_certs::load_native_certs;
use rustls_native_ossl::cert_verifier::OsslServerCertVerifier;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use uv_static::EnvVars;

use crate::tls::Certificates;

/// ALPN protocols matching reqwest's HTTP/2 + HTTP/1.1 negotiation. reqwest does not set ALPN on a
/// preconfigured config, so it is set here.
const ALPN_PROTOCOLS: [&[u8]; 2] = [b"h2", b"http/1.1"];

/// Build the rustls [`ClientConfig`] used by the secure client on the `ossl` backend.
pub(crate) fn client_config(custom_certificates: Option<&Certificates>) -> Result<ClientConfig> {
    // Always trust the system store; add any user-provided custom certificates on top. OpenSSL's
    // verifier takes explicit roots, so the system store is loaded here rather than by OpenSSL.
    let mut roots: Vec<CertificateDer<'static>> = load_native_certs().certs;
    if let Some(custom) = custom_certificates {
        roots.extend(custom.der().iter().cloned());
    }
    if roots.is_empty() {
        bail!("No trusted CA certificates found in the system trust store");
    }

    let verifier = OsslServerCertVerifier::builder(&roots)
        .context("Failed to build the OpenSSL certificate verifier")?
        .build();

    let builder =
        ClientConfig::builder_with_provider(rustls_native_ossl::default_provider().into())
            .with_safe_default_protocol_versions()
            .context("Failed to configure TLS protocol versions")?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier));

    // Configure mTLS from `SSL_CLIENT_CERT`, mirroring the reqwest-based backends.
    let mut config = match load_client_auth()? {
        Some((chain, key)) => builder
            .with_client_auth_cert(chain, key)
            .context("Failed to configure the `SSL_CLIENT_CERT` client certificate")?,
        None => builder.with_no_client_auth(),
    };

    config.alpn_protocols = ALPN_PROTOCOLS
        .iter()
        .map(|protocol| protocol.to_vec())
        .collect();
    Ok(config)
}

/// Load the client certificate chain and private key from `SSL_CLIENT_CERT`, if set.
fn load_client_auth() -> Result<Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>> {
    let Some(path) = std::env::var_os(EnvVars::SSL_CLIENT_CERT) else {
        return Ok(None);
    };
    let pem = fs_err::read(&path).context("Failed to read `SSL_CLIENT_CERT`")?;
    let chain = rustls_pemfile::certs(&mut pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificates from `SSL_CLIENT_CERT`")?;
    if chain.is_empty() {
        bail!("No certificates found in `SSL_CLIENT_CERT`");
    }
    let key = rustls_pemfile::private_key(&mut pem.as_slice())
        .context("Failed to parse the private key from `SSL_CLIENT_CERT`")?
        .context("No private key found in `SSL_CLIENT_CERT`")?;
    Ok(Some((chain, key)))
}
