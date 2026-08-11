// Patch-mode attestation re-signing.
//
// In patch mode the real hardware generates and attests a key; we keep its (genuine, hardware-backed)
// key blob and re-sign only the attestation leaf under the profile's keybox, replacing the root of
// trust with the profile's locked/Verified one. Everything else in the real leaf — the attested
// public key, the challenge, the KeyMint version fields and the tee-enforced authorization list — is
// preserved, so the record carries authentic hardware attestation content behind a keybox-rooted,
// locked chain.
//
// kmr-ta builds attestation leaves too, but its cert module is private and its signing key is not
// exposed, so this path re-implements the small amount of X.509 assembly it needs with `x509-cert`
// (for the certificate structure) and hand-written DER (for the one field, the root of trust, that
// x509-cert cannot reach because it lives under a high-number `[704]` context tag). Signing reuses
// the same BoringSSL backend and keybox key that generation uses.

use crate::{Ta, OpError};
use kmr_common::crypto::{rsa, AccumulatingOperation, Ec, KeyMaterial, Rsa, Sha256};
use kmr_crypto_boring::{ec::BoringEc, rsa::BoringRsa, sha256::BoringSha256};
use kmr_wire::keymint::Digest;
use x509_cert::der::asn1::{BitString, ObjectIdentifier, OctetString};
use x509_cert::der::{Decode, Encode};
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;

/// Local (non-TA) failure code, matching `ops::ERR_UNKNOWN`.
const ERR: i32 = -1000;

/// One-line "subject <= issuer" description of a DER certificate, for logs. Best effort.
pub(crate) fn describe_cert(der: &[u8]) -> String {
    match Certificate::from_der(der) {
        Ok(c) => format!(
            "subject=[{}] issuer=[{}]",
            c.tbs_certificate.subject, c.tbs_certificate.issuer
        ),
        Err(e) => format!("<unparseable {}-byte cert: {e}>", der.len()),
    }
}

/// Log a certificate chain at info level under `tag`, one line per cert.
pub(crate) fn log_chain(tag: &str, certs: &[kmr_wire::keymint::Certificate]) {
    log::info!("{tag}: {} cert(s) in chain", certs.len());
    for (i, c) in certs.iter().enumerate() {
        log::info!("{tag}:   [{i}] {}", describe_cert(&c.encoded_certificate));
    }
}

const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const EC_SHA256_SIG_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const RSA_SHA256_SIG_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const ATTESTATION_EXT_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.17");

/// A short local error, formatting any Debug source.
fn wrap<E: core::fmt::Debug>(ctx: &'static str) -> impl Fn(E) -> OpError {
    move |e| OpError { code: ERR, msg: format!("patch: {ctx}: {e:?}") }
}

fn err(msg: &str) -> OpError {
    OpError { code: ERR, msg: format!("patch: {msg}") }
}

impl Ta {
    /// Re-sign a real hardware attestation `leaf` (DER) under the keybox with the profile's root of
    /// trust. Returns the new chain `[patched leaf, keybox chain…]`.
    pub fn patch_attestation(&self, leaf: &[u8]) -> Result<Vec<Vec<u8>>, OpError> {
        log::info!("teesim_km: patch_attestation input leaf: {}", describe_cert(leaf));
        let cert = Certificate::from_der(leaf).map_err(wrap("parse real leaf"))?;
        let mut tbs = cert.tbs_certificate;

        // Sign with the keybox key matching the attested key's algorithm, and append that key's chain.
        let is_ec = tbs.subject_public_key_info.algorithm.oid == ID_EC_PUBLIC_KEY;
        let (batch_key, batch_chain) = self.sign_info.batch(is_ec);
        let batch_leaf = batch_chain.first().ok_or_else(|| err("keybox chain is empty"))?;
        let batch_leaf =
            Certificate::from_der(&batch_leaf.encoded_certificate).map_err(wrap("parse keybox leaf"))?;

        let sig_alg = AlgorithmIdentifierOwned {
            oid: if is_ec { EC_SHA256_SIG_OID } else { RSA_SHA256_SIG_OID },
            // Match kmr-ta's generation path, which encodes no AlgorithmIdentifier parameters.
            parameters: None,
        };

        // Splice the profile's root of trust into the attestation extension.
        let exts = tbs.extensions.as_mut().ok_or_else(|| err("leaf has no extensions"))?;
        let ext = exts
            .iter_mut()
            .find(|e| e.extn_id == ATTESTATION_EXT_OID)
            .ok_or_else(|| err("leaf has no KeyMint attestation extension"))?;
        let patched = splice_root_of_trust(ext.extn_value.as_bytes(), &self.patch_rot)?;
        ext.extn_value = OctetString::new(patched).map_err(wrap("rewrap key description"))?;

        // Re-root the leaf at the keybox and re-sign the modified tbsCertificate.
        tbs.signature = sig_alg.clone();
        tbs.issuer = batch_leaf.tbs_certificate.subject.clone();
        let tbs_der = tbs.to_der().map_err(wrap("encode tbsCertificate"))?;
        let sig = self.sign_tbs(is_ec, batch_key, &tbs_der)?;

        let patched_leaf = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: sig_alg,
            signature: BitString::from_bytes(&sig).map_err(wrap("wrap signature"))?,
        }
        .to_der()
        .map_err(wrap("encode leaf"))?;

        let mut chain = Vec::with_capacity(1 + batch_chain.len());
        chain.push(patched_leaf);
        chain.extend(batch_chain.iter().map(|c| c.encoded_certificate.clone()));
        log::info!(
            "teesim_km: patch_attestation -> {} cert(s) [patched leaf + keybox {} chain]",
            chain.len(),
            if is_ec { "EC" } else { "RSA" }
        );
        for (i, c) in chain.iter().enumerate() {
            log::info!("teesim_km:   [{i}] {}", describe_cert(c));
        }
        Ok(chain)
    }

    /// Sign `tbs` with the keybox batch key using the same modes as kmr-ta's own cert signing
    /// (ECDSA/SHA-256 or RSASSA-PKCS1-v1_5/SHA-256).
    fn sign_tbs(&self, is_ec: bool, key: KeyMaterial, tbs: &[u8]) -> Result<Vec<u8>, OpError> {
        let run = |mut op: Box<dyn AccumulatingOperation>| -> Result<Vec<u8>, OpError> {
            op.update(tbs).map_err(wrap("sign update"))?;
            op.finish().map_err(wrap("sign finish"))
        };
        match key {
            KeyMaterial::Ec(_, _, k) if is_ec => {
                run(BoringEc::default().begin_sign(k, Digest::Sha256).map_err(wrap("ec begin_sign"))?)
            }
            KeyMaterial::Rsa(k) if !is_ec => run(
                BoringRsa::default()
                    .begin_sign(k, rsa::SignMode::Pkcs1_1_5Padding(Digest::Sha256))
                    .map_err(wrap("rsa begin_sign"))?,
            ),
            _ => Err(err("keybox key type does not match the attested key's algorithm")),
        }
    }
}

/// Build a DER `RootOfTrust ::= SEQUENCE { verifiedBootKey OCTET STRING, deviceLocked BOOLEAN,
/// verifiedBootState ENUMERATED, verifiedBootHash OCTET STRING }` from the profile's boot info. This
/// is the value generation emits (see kmr-ta's `RootOfTrust::from(&BootInfo)`), so patch and
/// generation report an identical root of trust.
// `state & 0xff` is a single ENUMERATED byte (VerifiedBootState is 0..=3); the mask makes the u8 cast
// exact, so the sign-loss lint does not apply.
#[allow(clippy::cast_sign_loss)]
pub(crate) fn build_root_of_trust(vb_key: &[u8], locked: bool, state: i32, vb_hash: &[u8]) -> Vec<u8> {
    // kmr-ta hashes an over-long verified-boot key (boot_info_hashed_key); mirror it.
    let key_bytes = if vb_key.len() > 32 {
        BoringSha256.hash(vb_key).map(|h| h.to_vec()).unwrap_or_else(|_| vb_key.to_vec())
    } else {
        vb_key.to_vec()
    };
    let mut body = Vec::new();
    body.extend_from_slice(&tlv(&[0x04], &key_bytes)); // verifiedBootKey OCTET STRING
    body.extend_from_slice(&[0x01, 0x01, if locked { 0xff } else { 0x00 }]); // deviceLocked BOOLEAN
    body.extend_from_slice(&[0x0a, 0x01, (state & 0xff) as u8]); // verifiedBootState ENUMERATED
    body.extend_from_slice(&tlv(&[0x04], vb_hash)); // verifiedBootHash OCTET STRING
    tlv(&[0x30], &body)
}

// `[704] EXPLICIT` — the context tag the RootOfTrust sits under in an AuthorizationList. Tag number
// 704 needs the high-tag-number form: 0xBF (context, constructed, 0x1F) then 704 as base-128.
const ROT_TAG: &[u8] = &[0xBF, 0x85, 0x40];

/// Replace the RootOfTrust inside a DER `KeyDescription`'s hardware-enforced AuthorizationList with
/// `rot_seq` (a bare `RootOfTrust` SEQUENCE). Every other field is copied verbatim.
fn splice_root_of_trust(key_desc: &[u8], rot_seq: &[u8]) -> Result<Vec<u8>, OpError> {
    let top = read_elem(key_desc)?;
    if top.tag != [0x30] {
        return Err(err("key description is not a SEQUENCE"));
    }
    let fields = split_elems(top.value)?;
    if fields.len() != 8 {
        return Err(err(&format!("key description has {} fields, expected 8", fields.len())));
    }
    // Field 7 (0-based) is the hardware-enforced AuthorizationList.
    let hw = read_elem(fields[7])?;
    if hw.tag != [0x30] {
        return Err(err("hardware-enforced list is not a SEQUENCE"));
    }
    let new_rot = tlv(ROT_TAG, rot_seq);
    let mut new_hw_body = Vec::with_capacity(hw.value.len());
    let mut replaced = false;
    let mut rest = hw.value;
    while !rest.is_empty() {
        let e = read_elem(rest)?;
        if e.tag == ROT_TAG {
            new_hw_body.extend_from_slice(&new_rot);
            replaced = true;
        } else {
            new_hw_body.extend_from_slice(&rest[..e.total]);
        }
        rest = &rest[e.total..];
    }
    // Real hardware always carries a root of trust; if some HAL omits it, append ours (the tag list
    // is ascending and [704] is high, so an append preserves ordering for the usual tag set).
    if !replaced {
        new_hw_body.extend_from_slice(&new_rot);
    }

    let mut body = Vec::with_capacity(key_desc.len());
    for f in &fields[..7] {
        body.extend_from_slice(f);
    }
    body.extend_from_slice(&tlv(&[0x30], &new_hw_body));
    Ok(tlv(&[0x30], &body))
}

/// One parsed TLV: its tag bytes, its value bytes, and the total encoded length (tag+len+value).
struct Elem<'a> {
    tag: &'a [u8],
    value: &'a [u8],
    total: usize,
}

/// Parse the leading DER TLV of `input`, supporting multi-byte tags and long-form lengths.
fn read_elem(input: &[u8]) -> Result<Elem<'_>, OpError> {
    if input.is_empty() {
        return Err(err("truncated DER (no tag)"));
    }
    let mut i = 1;
    if input[0] & 0x1f == 0x1f {
        loop {
            let b = *input.get(i).ok_or_else(|| err("truncated multi-byte tag"))?;
            i += 1;
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    let tag = &input[..i];
    let l0 = *input.get(i).ok_or_else(|| err("truncated length"))?;
    i += 1;
    let len = if l0 & 0x80 == 0 {
        l0 as usize
    } else {
        let nbytes = (l0 & 0x7f) as usize;
        if nbytes == 0 || nbytes > 4 {
            return Err(err("unsupported DER length"));
        }
        let mut v = 0usize;
        for _ in 0..nbytes {
            v = (v << 8) | *input.get(i).ok_or_else(|| err("truncated length bytes"))? as usize;
            i += 1;
        }
        v
    };
    let end = i.checked_add(len).ok_or_else(|| err("length overflow"))?;
    if end > input.len() {
        return Err(err("value runs past end of input"));
    }
    Ok(Elem { tag, value: &input[i..end], total: end })
}

/// Split a SEQUENCE's content into its element TLV slices.
fn split_elems(mut content: &[u8]) -> Result<Vec<&[u8]>, OpError> {
    let mut out = Vec::new();
    while !content.is_empty() {
        let e = read_elem(content)?;
        out.push(&content[..e.total]);
        content = &content[e.total..];
    }
    Ok(out)
}

/// Encode DER length octets for a value of length `n`.
// Each `as u8` writes one length octet from a value already reduced to 0..=255 (guarded `n < 0x80`,
// masked `v & 0xff`, or a byte count that never reaches 256), so the truncation lint does not apply.
#[allow(clippy::cast_possible_truncation)]
fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let mut be = Vec::new();
    let mut v = n;
    while v > 0 {
        be.push((v & 0xff) as u8);
        v >>= 8;
    }
    be.reverse();
    let mut out = Vec::with_capacity(1 + be.len());
    out.push(0x80 | be.len() as u8);
    out.extend_from_slice(&be);
    out
}

/// Build a TLV from tag bytes and a value.
fn tlv(tag: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tag.len() + 5 + value.len());
    out.extend_from_slice(tag);
    out.extend_from_slice(&der_len(value.len()));
    out.extend_from_slice(value);
    out
}
