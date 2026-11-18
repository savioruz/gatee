use chrono::{DateTime, Duration, Utc};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};
use thiserror::Error;
use tracing::info;

#[derive(Error, Debug)]
pub enum CaError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Rcgen error: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("Rustls error: {0}")]
    Rustls(#[from] rustls::Error),
}

struct CachedLeaf {
    config: Arc<rustls::ServerConfig>,
    expires: DateTime<Utc>,
}

pub struct CertificateAuthority {
    ca_cert_pem: String,
    ca_key_pair: KeyPair,
    cache: RwLock<HashMap<String, CachedLeaf>>,
}

impl CertificateAuthority {
    pub fn load_or_generate(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Result<Self, CaError> {
        let cp = cert_path.as_ref();
        let kp = key_path.as_ref();

        if cp.exists() && kp.exists() {
            let cert_pem = std::fs::read_to_string(cp)?;
            let key_pem = std::fs::read_to_string(kp)?;
            let key_pair = KeyPair::from_pem(&key_pem)?;
            return Ok(Self {
                ca_cert_pem: cert_pem,
                ca_key_pair: key_pair,
                cache: RwLock::new(HashMap::new()),
            });
        }

        info!("Generating new local Root CA: {}", cp.display());
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "relay-gateway local CA");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let cert = params.self_signed(&key_pair)?;
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        if let Some(parent) = cp.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }
        if let Some(parent) = kp.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }
        std::fs::write(cp, &cert_pem)?;
        std::fs::write(kp, &key_pem)?;

        Ok(Self {
            ca_cert_pem: cert_pem,
            ca_key_pair: key_pair,
            cache: RwLock::new(HashMap::new()),
        })
    }

    pub fn cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    pub fn server_config_for(&self, hostname: &str) -> Result<Arc<rustls::ServerConfig>, CaError> {
        let host = hostname.to_lowercase();
        let now = Utc::now();

        {
            let cache_read = self
                .cache
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(entry) = cache_read.get(&host) {
                if entry.expires - now > Duration::hours(24) {
                    return Ok(Arc::clone(&entry.config));
                }
            }
        }

        let mut params = CertificateParams::new(vec![host.clone()])?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, &host);
        params.distinguished_name = dn;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];

        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let ca_params = CertificateParams::from_ca_cert_pem(&self.ca_cert_pem)?;
        let ca_cert = ca_params.self_signed(&self.ca_key_pair)?;
        let leaf_cert = params.signed_by(&leaf_key, &ca_cert, &self.ca_key_pair)?;

        let leaf_cert_der = leaf_cert.der().to_vec();
        let ca_cert_der = ca_cert.der().to_vec();
        let cert_chain = vec![
            rustls::pki_types::CertificateDer::from(leaf_cert_der),
            rustls::pki_types::CertificateDer::from(ca_cert_der),
        ];

        let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der()),
        );

        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)?;
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let config_arc = Arc::new(server_config);
        let expires = now + Duration::days(30);

        let mut cache_write = self
            .cache
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache_write.insert(
            host,
            CachedLeaf {
                config: Arc::clone(&config_arc),
                expires,
            },
        );

        Ok(config_arc)
    }
}
