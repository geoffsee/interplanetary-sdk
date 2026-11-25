//! TLS material for TCPCLv4.
//!
//! RFC 9174 §4.4.3 starts TLS on the existing TCP connection after the contact
//! headers, with the active entity as the TLS client. The RFC does not define
//! an ALPN protocol id, so none is offered.
//!
//! Node identity is checked after SESS_INIT (RFC 9174 §4.4.4.3). A certificate
//! matches when its subjectAltName contains the peer node id as a URI or as the
//! RFC 9174 `id-on-bundleEID` otherName (`1.3.6.1.5.5.7.8.11`).

use interplanetary_types::{Error, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::io::Cursor;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use x509_parser::prelude::*;

/// OID `id-on-bundleEID` from RFC 9174 Appendix B.
const BUNDLE_EID_OID: &str = "1.3.6.1.5.5.7.8.11";

/// Client and server configuration from one end-entity certificate.
#[derive(Clone)]
pub(crate) struct TlsMaterial {
    pub(crate) client: Arc<ClientConfig>,
    pub(crate) server: TlsAcceptor,
}

impl std::fmt::Debug for TlsMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsMaterial").finish_non_exhaustive()
    }
}

pub(crate) fn install_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub(crate) fn build(ca_pem: &[u8], cert_pem: &[u8], key_pem: &[u8]) -> Result<TlsMaterial> {
    install_provider();
    let mut roots = RootCertStore::empty();
    for ca in read_certs(ca_pem)? {
        roots
            .add(ca)
            .map_err(|err| Error::invalid_config(format!("CA certificate: {err}")))?;
    }
    if roots.is_empty() {
        return Err(Error::invalid_config("CA PEM contained no certificates"));
    }
    let certs = read_certs(cert_pem)?;
    let key = read_key(key_pem)?;

    let verifier = rustls::server::WebPkiClientVerifier::builder(roots.clone().into())
        .build()
        .map_err(|err| Error::invalid_config(format!("client certificate verifier: {err}")))?;
    let server = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs.clone(), key.clone_key())
        .map_err(|err| Error::invalid_config(format!("TLS server certificate: {err}")))?;

    let client = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .map_err(|err| Error::invalid_config(format!("TLS client certificate: {err}")))?;

    Ok(TlsMaterial {
        client: Arc::new(client),
        server: TlsAcceptor::from(Arc::new(server)),
    })
}

pub(crate) fn server_name(name: &str) -> Result<ServerName<'static>> {
    ServerName::try_from(name.to_string())
        .map_err(|_| Error::invalid_config(format!("TLS server name `{name}` is not a DNS name")))
}

/// Node ids named by the peer certificate.
pub(crate) fn certificate_node_ids(der: &[u8]) -> Vec<String> {
    let Ok((_, cert)) = X509Certificate::from_der(der) else {
        return Vec::new();
    };
    let Ok(Some(san)) = cert.subject_alternative_name() else {
        return Vec::new();
    };
    let mut ids = Vec::new();
    for name in &san.value.general_names {
        match name {
            GeneralName::URI(uri) => ids.push((*uri).to_string()),
            GeneralName::OtherName(oid, value) if oid.to_id_string() == BUNDLE_EID_OID => {
                if let Some(text) = der_string(value) {
                    ids.push(text);
                }
            }
            _ => {}
        }
    }
    ids
}

pub(crate) fn peer_authenticates(certs: &[Vec<u8>], node_id: &str) -> bool {
    certs
        .iter()
        .any(|der| certificate_node_ids(der).iter().any(|id| id == node_id))
}

fn der_string(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    let tag = data[0];
    let (len, rest) = read_der_len(&data[1..])?;
    if rest.len() < len {
        return None;
    }
    let bytes = &rest[..len];
    match tag {
        0x0c | 0x16 | 0x13 => std::str::from_utf8(bytes).ok().map(str::to_string),
        _ => None,
    }
}

fn read_der_len(bytes: &[u8]) -> Option<(usize, &[u8])> {
    let first = *bytes.first()?;
    if first & 0x80 == 0 {
        return Some((first as usize, &bytes[1..]));
    }
    let octets = (first & 0x7f) as usize;
    if octets == 0 || octets > 2 || bytes.len() < 1 + octets {
        return None;
    }
    let mut len = 0usize;
    for byte in &bytes[1..1 + octets] {
        len = (len << 8) | *byte as usize;
    }
    Some((len, &bytes[1 + octets..]))
}

fn read_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut Cursor::new(pem))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|err| Error::invalid_config(format!("certificate PEM: {err}")))
}

fn read_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut Cursor::new(pem))
        .map_err(|err| Error::invalid_config(format!("private key PEM: {err}")))?
        .ok_or_else(|| Error::invalid_config("private key PEM was empty"))
}
