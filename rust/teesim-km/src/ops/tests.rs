use super::*;
use crate::TaConfig;
use kmr_wire::keymint::{Algorithm, Digest, EcCurve};
use kmr_wire::{KeySizeInBits, RsaExponent};
use openssl::{
    asn1::Asn1Time,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    sign::Verifier,
    x509::{X509NameBuilder, X509},
};

fn ec_key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

fn fail<T>(err: OpError) -> T {
    panic!("{}: {}", err.code, err.msg)
}

// All signing material is generated for this test. No device keybox is needed.
fn new_ta(level: i32) -> Ta {
    let key = ec_key();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "TEESimulator test only")
        .unwrap();
    let name = name.build();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::from_unix(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::from_unix(2_461_449_600).unwrap())
        .unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();
    let cert_pem = String::from_utf8(cert.build().to_pem().unwrap()).unwrap();
    let key_pem = String::from_utf8(key.ec_key().unwrap().private_key_to_pem().unwrap()).unwrap();
    // The loader requires two certificates. These tests do not validate a trust chain.
    let xml = format!(
        "<AndroidAttestation><Keybox><Key algorithm=\"ecdsa\">\
         <PrivateKey>{key_pem}</PrivateKey><CertificateChain>\
         <Certificate>{cert_pem}</Certificate><Certificate>{cert_pem}</Certificate>\
         </CertificateChain></Key></Keybox></AndroidAttestation>"
    );
    let mut config = TaConfig::defaults(&xml);
    config.security_level = level;
    Ta::new_ex(config).unwrap()
}

fn ec_params(purpose: KeyPurpose) -> Vec<KeyParam> {
    vec![
        KeyParam::Algorithm(Algorithm::Ec),
        KeyParam::EcCurve(EcCurve::P256),
        KeyParam::KeySize(KeySizeInBits(256)),
        KeyParam::Purpose(purpose),
        KeyParam::Digest(Digest::Sha256),
        KeyParam::NoAuthRequired,
        KeyParam::CertificateNotBefore(DateTime { ms_since_epoch: 0 }),
        KeyParam::CertificateNotAfter(DateTime {
            ms_since_epoch: 2_461_449_600_000,
        }),
    ]
}

#[test]
fn import_early_boot_only_fails_before_and_after_early_boot_ended() {
    let data = ec_key().private_key_to_pkcs8().unwrap();
    // Each profile has a TA per security level. Exercise every supported level.
    for level in [1, 2, 0] {
        let mut ta = new_ta(level);
        for ended in [false, true] {
            if ended {
                ta.early_boot_ended().unwrap_or_else(fail);
            }
            for purpose in [KeyPurpose::AttestKey, KeyPurpose::Sign] {
                let mut params = ec_params(purpose);
                params.push(KeyParam::AttestationChallenge(b"test challenge".to_vec()));
                params.push(KeyParam::AttestationApplicationId(b"test app".to_vec()));
                params.push(KeyParam::EarlyBootOnly);
                let err = ta
                    .import_key(params, KeyFormat::Pkcs8, data.clone(), None)
                    .err()
                    .unwrap_or_else(|| panic!("EARLY_BOOT_ONLY import succeeded: level={level}, ended={ended}, purpose={purpose:?}"));
                assert_eq!(
                    err.code, -73,
                    "level={level}, ended={ended}, purpose={purpose:?}"
                );
            }
        }
    }
}

fn sign(ta: &mut Ta, blob: &[u8]) -> Vec<u8> {
    let op = ta
        .begin(
            KeyPurpose::Sign,
            blob,
            vec![KeyParam::Digest(Digest::Sha256)],
            None,
        )
        .unwrap_or_else(fail);
    ta.finish(
        op.op_handle,
        Some(b"test message".to_vec()),
        None,
        None,
        None,
        None,
    )
    .unwrap_or_else(fail)
}

#[test]
fn ordinary_imports_and_parameter_mismatch_are_unchanged() {
    let ec = ec_key();
    let rsa = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut ta = new_ta(1);
    let mut ec_blob = Vec::new();
    for ended in [false, true] {
        if ended {
            ta.early_boot_ended().unwrap_or_else(fail);
        }
        let result = ta
            .import_key(
                ec_params(KeyPurpose::Sign),
                KeyFormat::Pkcs8,
                ec.private_key_to_pkcs8().unwrap(),
                None,
            )
            .unwrap_or_else(fail);
        assert!(crate::is_marked(&result.key_blob));
        assert!(!result.certificate_chain.is_empty());
        let signature = sign(&mut ta, &result.key_blob);
        let mut verifier = Verifier::new(MessageDigest::sha256(), &ec).unwrap();
        verifier.update(b"test message").unwrap();
        assert!(verifier.verify(&signature).unwrap());
        ec_blob = result.key_blob;

        let mut params = ec_params(KeyPurpose::Sign);
        params.retain(|p| {
            !matches!(
                p,
                KeyParam::Algorithm(_) | KeyParam::EcCurve(_) | KeyParam::KeySize(_)
            )
        });
        params.extend([
            KeyParam::Algorithm(Algorithm::Rsa),
            KeyParam::KeySize(KeySizeInBits(2048)),
            KeyParam::RsaPublicExponent(RsaExponent(65537)),
        ]);
        ta.import_key(
            params,
            KeyFormat::Pkcs8,
            rsa.private_key_to_pkcs8().unwrap(),
            None,
        )
        .unwrap_or_else(fail);

        let mut params = ec_params(KeyPurpose::Sign);
        params.retain(|p| !matches!(p, KeyParam::KeySize(_)));
        params.push(KeyParam::KeySize(KeySizeInBits(384)));
        let err = ta
            .import_key(
                params,
                KeyFormat::Pkcs8,
                ec.private_key_to_pkcs8().unwrap(),
                None,
            )
            .unwrap_err();
        assert_eq!(err.code, -44);
    }
    // Recreate the TA with stable boot/root-key settings and a new test signing key.
    let mut restarted = new_ta(1);
    assert!(!sign(&mut restarted, &ec_blob).is_empty());
}

#[test]
fn ordinary_attested_import_still_returns_a_signed_chain() {
    let mut ta = new_ta(1);
    let mut params = ec_params(KeyPurpose::AttestKey);
    params.push(KeyParam::AttestationChallenge(b"test challenge".to_vec()));
    params.push(KeyParam::AttestationApplicationId(b"test app".to_vec()));
    let result = ta
        .import_key(
            params,
            KeyFormat::Pkcs8,
            ec_key().private_key_to_pkcs8().unwrap(),
            None,
        )
        .unwrap_or_else(fail);
    assert_eq!(result.certificate_chain.len(), 3);
    let leaf = X509::from_der(&result.certificate_chain[0].encoded_certificate).unwrap();
    let issuer = X509::from_der(&result.certificate_chain[1].encoded_certificate).unwrap();
    assert!(leaf.verify(&issuer.public_key().unwrap()).unwrap());
}

#[test]
fn generated_early_boot_key_keeps_its_usage_restriction() {
    let mut ta = new_ta(1);
    let mut params = ec_params(KeyPurpose::Sign);
    params.push(KeyParam::EarlyBootOnly);
    let result = ta.generate_key(params.clone(), None).unwrap_or_else(fail);
    assert!(!sign(&mut ta, &result.key_blob).is_empty());
    ta.early_boot_ended().unwrap_or_else(fail);
    let err = ta
        .begin(
            KeyPurpose::Sign,
            &result.key_blob,
            vec![KeyParam::Digest(Digest::Sha256)],
            None,
        )
        .unwrap_err();
    assert_eq!(err.code, -73);
    ta.generate_key(params, None).unwrap_or_else(fail);
}
