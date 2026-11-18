use gatee_ca::CertificateAuthority;
use tempfile::tempdir;

#[test]
fn test_ca_generation_and_leaf_signing() {
    let dir = tempdir().expect("tempdir");
    let cert_path = dir.path().join("ca.pem");
    let key_path = dir.path().join("ca-key.pem");

    let ca = CertificateAuthority::load_or_generate(&cert_path, &key_path).expect("generate ca");
    assert!(cert_path.exists());
    assert!(key_path.exists());
    assert!(ca.cert_pem().contains("BEGIN CERTIFICATE"));

    let config = ca
        .server_config_for("api.openai.com")
        .expect("leaf signing");
    assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
}

#[test]
fn test_ca_reload_existing() {
    let dir = tempdir().expect("tempdir");
    let cert_path = dir.path().join("ca.pem");
    let key_path = dir.path().join("ca-key.pem");

    let ca1 = CertificateAuthority::load_or_generate(&cert_path, &key_path).expect("generate ca");
    let pem1 = ca1.cert_pem().to_string();

    let ca2 = CertificateAuthority::load_or_generate(&cert_path, &key_path).expect("reload ca");
    assert_eq!(ca2.cert_pem(), pem1);

    // Verify cache hit and signing still work
    let config1 = ca2.server_config_for("example.com").expect("leaf 1");
    let config2 = ca2
        .server_config_for("example.com")
        .expect("leaf 2 (cached)");
    assert!(std::sync::Arc::ptr_eq(&config1, &config2));
}
