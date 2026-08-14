// Attestation signing keys loaded from a keybox.xml.
//
// Implements the TA's `RetrieveCertSigningInfo` trait so that generated keys are
// attested with the batch keys from the configured keybox. A factory batch keybox
// carries both an RSA and an EC key and each attested key is signed with the matching
// algorithm; an RKP-extracted keybox carries only an EC P-256 key, so every leaf
// (RSA keys included) is signed with the EC key, exactly as a real RKP device does.
// At least one key must be present, but neither is individually required.

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

/// Signing information for the asymmetric key types we attest with. Each algorithm is optional; a
/// keybox must carry at least one, but an RKP-extracted keybox legitimately has only the EC key.
#[derive(Clone)]
pub struct CertSignInfo {
    rsa: Option<AlgoInfo>,
    ec: Option<AlgoInfo>,
}

impl CertSignInfo {
    /// Choose the batch key for an attested key, preferring the matching algorithm (`prefer_ec`) and
    /// falling back to the other key when the keybox lacks the preferred one. Returns the key info
    /// plus whether the chosen key is EC, so callers stamp the signature fields for the key that
    /// actually signs rather than the key being attested. `new` guarantees at least one key exists,
    /// so the fallback is always present.
    fn pick(&self, prefer_ec: bool) -> (&AlgoInfo, bool) {
        let (primary, other) = if prefer_ec { (&self.ec, &self.rsa) } else { (&self.rsa, &self.ec) };
        match primary {
            Some(a) => (a, prefer_ec),
            None => (
                other.as_ref().expect("keybox has at least one signing key"),
                !prefer_ec,
            ),
        }
    }

    /// The batch signing key, its keybox certificate chain, and whether that key is EC. `prefer_ec`
    /// requests the algorithm matching the key being attested; when absent, the other key is used
    /// (an EC-only RKP keybox signs every leaf with its EC key). Patch mode re-signs a real
    /// attestation leaf with this key and appends this chain.
    pub fn batch(&self, prefer_ec: bool) -> (KeyMaterial, &[keymint::Certificate], bool) {
        let (a, is_ec) = self.pick(prefer_ec);
        (a.key.clone(), &a.chain, is_ec)
    }
}

impl CertSignInfo {
    /// Parse a keybox.xml string and extract whichever of the RSA and EC signing keys/chains it
    /// carries. Requires at least one; a factory keybox has both, an RKP-extracted keybox only EC.
    pub fn new(keybox_xml: &str) -> Result<Self, String> {
        let doc = Document::parse(keybox_xml).map_err(|e| format!("keybox parse: {e:?}"))?;

        let node = |algo: &str| {
            doc.descendants()
                .find(|n| n.has_tag_name("Key") && n.attribute("algorithm") == Some(algo))
        };

        let rsa = node("rsa").map(|n| parse_algo(n, SigningAlgorithm::Rsa)).transpose()?;
        let ec = node("ecdsa").map(|n| parse_algo(n, SigningAlgorithm::Ec)).transpose()?;

        if rsa.is_none() && ec.is_none() {
            return Err("keybox: no <Key algorithm=\"rsa\"> or <Key algorithm=\"ecdsa\">".to_string());
        }

        let info = CertSignInfo { rsa, ec };
        log::info!(
            "teesim_km: keybox parsed (rsa={}, ec={})",
            info.rsa.is_some(),
            info.ec.is_some()
        );
        if let Some(a) = &info.rsa {
            crate::resign::log_chain("teesim_km: keybox RSA chain", &a.chain);
        }
        if let Some(a) = &info.ec {
            crate::resign::log_chain("teesim_km: keybox EC chain", &a.chain);
        }
        Ok(info)
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
        // kmr-ta derives the leaf's signature algorithm from the returned key material, so the EC
        // fallback for an RSA request on an EC-only keybox yields a correctly EC-signed leaf.
        let prefer_ec = matches!(key_type.algo_hint, SigningAlgorithm::Ec);
        Ok(self.pick(prefer_ec).0.key.clone())
    }

    fn cert_chain(&self, key_type: SigningKeyType) -> Result<Vec<keymint::Certificate>, Error> {
        let prefer_ec = matches!(key_type.algo_hint, SigningAlgorithm::Ec);
        Ok(self.pick(prefer_ec).0.chain.clone())
    }
}
