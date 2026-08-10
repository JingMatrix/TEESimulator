// Attestation signing keys loaded from a keybox.xml.
//
// Implements the TA's `RetrieveCertSigningInfo` trait so that generated keys are
// attested with the RSA and EC batch keys from the configured keybox. There is no
// hard-coded fallback: a keybox must be supplied.

use base64::{engine::general_purpose, Engine as _};
use kmr_common::{
    crypto::ec, crypto::rsa, crypto::CurveType, crypto::KeyMaterial, Error,
};
use kmr_ta::device::{RetrieveCertSigningInfo, SigningAlgorithm, SigningKeyType};
use kmr_wire::keymint::{self, EcCurve};
use roxmltree::Document;

/// Per-algorithm signing key material plus its certificate chain.
#[derive(Clone)]
struct AlgoInfo {
    key: KeyMaterial,
    chain: Vec<keymint::Certificate>,
}

/// Signing information for the asymmetric key types we attest with.
#[derive(Clone)]
pub struct CertSignInfo {
    rsa: AlgoInfo,
    ec: AlgoInfo,
}

impl CertSignInfo {
    /// The batch signing key and its keybox certificate chain for one algorithm (EC when `ec` is
    /// true, else RSA). Patch mode re-signs a real attestation leaf with this key and appends this
    /// chain, matching the algorithm of the key being attested.
    pub fn batch(&self, ec: bool) -> (KeyMaterial, &[keymint::Certificate]) {
        let a = if ec { &self.ec } else { &self.rsa };
        (a.key.clone(), &a.chain)
    }
}

impl CertSignInfo {
    /// Parse a keybox.xml string and extract the RSA and EC signing keys/chains.
    pub fn new(keybox_xml: &str) -> Result<Self, String> {
        let doc = Document::parse(keybox_xml).map_err(|e| format!("keybox parse: {e:?}"))?;

        let rsa_node = doc
            .descendants()
            .find(|n| n.has_tag_name("Key") && n.attribute("algorithm") == Some("rsa"))
            .ok_or("keybox: no <Key algorithm=\"rsa\">")?;
        let ec_node = doc
            .descendants()
            .find(|n| n.has_tag_name("Key") && n.attribute("algorithm") == Some("ecdsa"))
            .ok_or("keybox: no <Key algorithm=\"ecdsa\">")?;

        Ok(CertSignInfo {
            rsa: parse_algo(rsa_node, SigningAlgorithm::Rsa)?,
            ec: parse_algo(ec_node, SigningAlgorithm::Ec)?,
        })
    }
}

fn parse_algo(node: roxmltree::Node, algo: SigningAlgorithm) -> Result<AlgoInfo, String> {
    let name = match algo {
        SigningAlgorithm::Rsa => "RSA",
        SigningAlgorithm::Ec => "EC",
    };

    let priv_pem = node
        .children()
        .find(|n| n.has_tag_name("PrivateKey"))
        .ok_or_else(|| format!("{name}: missing PrivateKey"))?
        .text()
        .ok_or_else(|| format!("{name}: empty PrivateKey"))?;
    let key_der = decode_pem(priv_pem)?;

    let mut chain = Vec::new();
    for cert in node.descendants().filter(|n| n.has_tag_name("Certificate")) {
        let pem = cert.text().ok_or_else(|| format!("{name}: empty Certificate"))?;
        chain.push(keymint::Certificate { encoded_certificate: decode_pem(pem)? });
    }
    if chain.len() < 2 {
        return Err(format!("{name}: expected at least 2 certificates, found {}", chain.len()));
    }

    let key = match algo {
        SigningAlgorithm::Rsa => KeyMaterial::Rsa(rsa::Key(key_der).into()),
        // Keyboxes in the field use NIST P-256 for the EC batch key.
        SigningAlgorithm::Ec => {
            KeyMaterial::Ec(EcCurve::P256, CurveType::Nist, ec::Key::P256(ec::NistKey(key_der)).into())
        }
    };
    Ok(AlgoInfo { key, chain })
}

/// Strip PEM armor and all whitespace, then base64-decode.
fn decode_pem(pem: &str) -> Result<Vec<u8>, String> {
    let mut b64 = String::with_capacity(pem.len());
    for line in pem.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("-----") {
            continue;
        }
        b64.extend(line.chars().filter(|c| !c.is_whitespace()));
    }
    general_purpose::STANDARD.decode(&b64).map_err(|e| format!("base64: {e:?}"))
}

impl RetrieveCertSigningInfo for CertSignInfo {
    fn signing_key(&self, key_type: SigningKeyType) -> Result<KeyMaterial, Error> {
        Ok(match key_type.algo_hint {
            SigningAlgorithm::Rsa => self.rsa.key.clone(),
            SigningAlgorithm::Ec => self.ec.key.clone(),
        })
    }

    fn cert_chain(&self, key_type: SigningKeyType) -> Result<Vec<keymint::Certificate>, Error> {
        Ok(match key_type.algo_hint {
            SigningAlgorithm::Rsa => self.rsa.chain.clone(),
            SigningAlgorithm::Ec => self.ec.chain.clone(),
        })
    }
}
