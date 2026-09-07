// TLS backend selection.
//
// The client uses one of two TLS backends: `rustls-tls` (the default) or `native-tls`, the
// system's native TLS stack. The `uv` and `uv-dev` binaries always select a backend through their
// default features, so every real build of uv has one.
//
// The crate also compiles with neither feature enabled: a fallback that keeps `uv-client` building
// in isolation (for example under `--no-default-features` feature-matrix checks). Such a build has
// no TLS backend and cannot establish secure connections; it is not a supported way to build uv.
//
// Because these are additive Cargo features, both can be enabled at once (for example under
// `cargo <cmd> --all-features`). In that case `rustls-tls` is used and the `native-tls` code paths
// are compiled out, so the `native-tls` implementation is gated on
// `all(feature = "native-tls", not(feature = "rustls-tls"))`.

#[cfg(any(feature = "rustls-tls", feature = "native-tls"))]
use std::io::{self, Read};

#[cfg(any(feature = "rustls-tls", feature = "native-tls"))]
use reqwest::Identity;

#[cfg(feature = "rustls-tls")]
mod rustls;

#[cfg(feature = "rustls-tls")]
pub use self::rustls::{CertificateFileError, Certificates};

#[cfg(any(feature = "rustls-tls", feature = "native-tls"))]
#[derive(thiserror::Error, Debug)]
pub(crate) enum CertificateError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Reqwest(reqwest::Error),
}

/// Return the [`Identity`] from the provided file.
///
/// The file is expected to contain a PEM-encoded certificate chain and private key.
#[cfg(any(feature = "rustls-tls", feature = "native-tls"))]
pub(crate) fn read_identity(
    ssl_client_cert: &std::ffi::OsStr,
) -> Result<Identity, CertificateError> {
    let mut buf = Vec::new();
    fs_err::File::open(ssl_client_cert)?.read_to_end(&mut buf)?;

    #[cfg(feature = "rustls-tls")]
    {
        Identity::from_pem(&buf).map_err(|tls_err| {
            debug_assert!(tls_err.is_builder(), "must be a rustls::Error internally");
            CertificateError::Reqwest(tls_err)
        })
    }

    #[cfg(all(feature = "native-tls", not(feature = "rustls-tls")))]
    {
        // `Identity::from_pkcs8_pem` requires the key argument to begin with the
        // PKCS#8 PEM header. The certificate argument is parsed by OpenSSL's
        // `X509::stack_from_pem`, which only extracts certificate blocks and ignores
        // private key blocks, so we can pass the full buffer as-is.
        const KEY_MARKER: &[u8] = b"-----BEGIN PRIVATE KEY-----";
        let key_start = buf
            .windows(KEY_MARKER.len())
            .position(|window| window == KEY_MARKER)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "no PKCS#8 private key found in client certificate file",
                )
            })?;
        Identity::from_pkcs8_pem(&buf, &buf[key_start..]).map_err(CertificateError::Reqwest)
    }
}
