// Patch-mode attestation re-signing.
//
// In patch mode the real hardware generates and attests a key; we keep its (genuine, hardware-backed)
// key blob and re-sign only the attestation leaf under the profile's keybox. Two kinds of field are
// rewritten to the profile's values: the root of trust (to the profile's locked/Verified one) and the
// OS / vendor / boot security levels (so a patched record does not leak the device's real, often
// stale, patch level, which would otherwise cost it Play Integrity's STRONG verdict). Everything else
// in the real leaf — the attested public key, the challenge, the KeyMint version fields and the rest
// of the authorization lists — is preserved, so the record carries authentic hardware attestation
// content behind a keybox-rooted, locked chain.
//
// kmr-ta builds attestation leaves too, but its cert module is private and its signing key is not
// exposed, so this path re-implements the small amount of X.509 assembly it needs with `x509-cert`
// (for the certificate structure) and hand-written DER (for the fields — the root of trust and the
// patch levels — that x509-cert cannot reach because they live under high-number context tags).
// Signing reuses the same BoringSSL backend and keybox key that generation uses.

use crate::{Ta, OpError};
use kmr_common::crypto::{rsa, AccumulatingOperation, Ec, KeyMaterial, Rsa, Sha256};
use kmr_crypto_boring::{ec::BoringEc, rsa::BoringRsa, sha256::BoringSha256};
use kmr_wire::keymint::Digest;
use kmr_wire::types::AttestationIdInfo;
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

        // Rewrite the profile-controlled fields (root of trust, patch levels, device IDs) so the
        // patched record reports the profile's identity rather than the device's real, often stale one.
        let exts = tbs.extensions.as_mut().ok_or_else(|| err("leaf has no extensions"))?;
        let ext = exts
            .iter_mut()
            .find(|e| e.extn_id == ATTESTATION_EXT_OID)
            .ok_or_else(|| err("leaf has no KeyMint attestation extension"))?;
        let overrides = PatchOverrides {
            root_of_trust: &self.patch_rot,
            os_version: self.os_version,
            os_patchlevel: self.os_patchlevel,
            vendor_patchlevel: self.vendor_patchlevel,
            boot_patchlevel: self.boot_patchlevel,
            attestation_ids: self.attestation_ids.as_ref(),
        };
        log::info!(
            "teesim_km: patch_attestation applying profile: os_version={} os_patchlevel={} vendor_patchlevel={} boot_patchlevel={} ids={}",
            self.os_version,
            self.os_patchlevel,
            self.vendor_patchlevel,
            self.boot_patchlevel,
            if self.attestation_ids.is_some() { "profile" } else { "device" }
        );
        let patched = patch_key_description(ext.extn_value.as_bytes(), &overrides)?;
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

// `AuthorizationList` context-tag numbers this module rewrites. The root of trust and the OS / vendor
// / boot levels live in the tee-enforced list of a real hardware leaf, and are inserted there if
// absent. The device-ID tags (710..=717, 723) appear only when the app requested ID attestation, so
// they are replaced in place but never inserted — adding an ID the caller did not ask for would not
// match what generation emits. Patch mode replaces the device's genuine values with the profile's so
// a patched record matches what generation would have emitted.
const TAG_ROOT_OF_TRUST: u32 = 704;
const TAG_OS_VERSION: u32 = 705;
const TAG_OS_PATCHLEVEL: u32 = 706;
const TAG_VENDOR_PATCHLEVEL: u32 = 718;
const TAG_BOOT_PATCHLEVEL: u32 = 719;
const TAG_ATTESTATION_ID_BRAND: u32 = 710;
const TAG_ATTESTATION_ID_DEVICE: u32 = 711;
const TAG_ATTESTATION_ID_PRODUCT: u32 = 712;
const TAG_ATTESTATION_ID_SERIAL: u32 = 713;
const TAG_ATTESTATION_ID_IMEI: u32 = 714;
const TAG_ATTESTATION_ID_MEID: u32 = 715;
const TAG_ATTESTATION_ID_MANUFACTURER: u32 = 716;
const TAG_ATTESTATION_ID_MODEL: u32 = 717;
const TAG_ATTESTATION_ID_SECOND_IMEI: u32 = 723;

/// Tags that patch mode inserts (in ascending order) into the tee-enforced list when a real leaf omits
/// them. Every other override is replace-only.
const INSERTABLE_TAGS: [u32; 5] = [
    TAG_ROOT_OF_TRUST,
    TAG_OS_VERSION,
    TAG_OS_PATCHLEVEL,
    TAG_VENDOR_PATCHLEVEL,
    TAG_BOOT_PATCHLEVEL,
];

/// Profile values patch mode writes into a real leaf's `KeyDescription`, replacing the device's own.
pub(crate) struct PatchOverrides<'a> {
    /// A bare DER `RootOfTrust` SEQUENCE (see `build_root_of_trust`).
    pub root_of_trust: &'a [u8],
    pub os_version: u32,
    pub os_patchlevel: u32,
    pub vendor_patchlevel: u32,
    pub boot_patchlevel: u32,
    /// Device IDs the profile vouches for, or `None` when it declines ID attestation.
    pub attestation_ids: Option<&'a AttestationIdInfo>,
}

/// Rewrite the profile-controlled fields of a DER `KeyDescription`: the root of trust, the OS / vendor
/// / boot security levels, and any device-ID tags the leaf carries. A field present in either
/// authorization list is replaced in place; a missing root-of-trust or level is inserted, in ascending
/// tag order, into the tee-enforced list. Every other field is copied verbatim.
fn patch_key_description(key_desc: &[u8], ov: &PatchOverrides) -> Result<Vec<u8>, OpError> {
    let top = read_elem(key_desc)?;
    if top.tag != [0x30] {
        return Err(err("key description is not a SEQUENCE"));
    }
    let fields = split_elems(top.value)?;
    if fields.len() != 8 {
        return Err(err(&format!("key description has {} fields, expected 8", fields.len())));
    }

    // (tag number, replacement element) for every field we own. The root of trust is a bare SEQUENCE
    // wrapped in its `[704] EXPLICIT` tag; the levels are integers KeyMint stores as `[tag] EXPLICIT
    // INTEGER`; the IDs are byte strings stored as `[tag] EXPLICIT OCTET STRING`.
    let mut overrides: Vec<(u32, Vec<u8>)> = vec![
        (TAG_ROOT_OF_TRUST, tlv(&context_tag(TAG_ROOT_OF_TRUST), ov.root_of_trust)),
        (TAG_OS_VERSION, explicit_integer(TAG_OS_VERSION, ov.os_version)),
        (TAG_OS_PATCHLEVEL, explicit_integer(TAG_OS_PATCHLEVEL, ov.os_patchlevel)),
        (TAG_VENDOR_PATCHLEVEL, explicit_integer(TAG_VENDOR_PATCHLEVEL, ov.vendor_patchlevel)),
        (TAG_BOOT_PATCHLEVEL, explicit_integer(TAG_BOOT_PATCHLEVEL, ov.boot_patchlevel)),
    ];
    if let Some(ids) = ov.attestation_ids {
        // A profile field left empty means "not supplied" — leave whatever the real leaf holds rather
        // than blanking a genuine value the app requested.
        let id_tags: [(u32, &[u8]); 9] = [
            (TAG_ATTESTATION_ID_BRAND, &ids.brand),
            (TAG_ATTESTATION_ID_DEVICE, &ids.device),
            (TAG_ATTESTATION_ID_PRODUCT, &ids.product),
            (TAG_ATTESTATION_ID_SERIAL, &ids.serial),
            (TAG_ATTESTATION_ID_IMEI, &ids.imei),
            (TAG_ATTESTATION_ID_MEID, &ids.meid),
            (TAG_ATTESTATION_ID_MANUFACTURER, &ids.manufacturer),
            (TAG_ATTESTATION_ID_MODEL, &ids.model),
            (TAG_ATTESTATION_ID_SECOND_IMEI, &ids.imei2),
        ];
        for (tag, value) in id_tags {
            if !value.is_empty() {
                overrides.push((tag, explicit_octet_string(tag, value)));
            }
        }
    }

    // Field 6 (0-based) is software-enforced, field 7 tee-enforced. Replace wherever present; a real
    // leaf keeps the root of trust and levels tee-enforced, but a stray software-enforced value is
    // corrected too so no genuine value survives.
    let mut seen: Vec<u32> = Vec::new();
    let sw = replace_in_list(read_list(fields[6])?, &overrides, &mut seen)?;
    let mut hw = replace_in_list(read_list(fields[7])?, &overrides, &mut seen)?;
    for num in INSERTABLE_TAGS {
        if !seen.contains(&num) {
            if let Some((_, elem)) = overrides.iter().find(|(t, _)| *t == num) {
                hw = insert_in_order(hw, num, elem)?;
            }
        }
    }

    let mut body = Vec::with_capacity(key_desc.len() + 32);
    for f in &fields[..6] {
        body.extend_from_slice(f);
    }
    body.extend_from_slice(&tlv(&[0x30], &sw));
    body.extend_from_slice(&tlv(&[0x30], &hw));
    Ok(tlv(&[0x30], &body))
}

/// The element bytes (content) of an `AuthorizationList` SEQUENCE.
fn read_list(field: &[u8]) -> Result<&[u8], OpError> {
    let e = read_elem(field)?;
    if e.tag != [0x30] {
        return Err(err("authorization list is not a SEQUENCE"));
    }
    Ok(e.value)
}

/// Copy an authorization-list body, substituting any element whose context tag matches an override
/// and recording which tags were substituted.
fn replace_in_list(
    body: &[u8],
    overrides: &[(u32, Vec<u8>)],
    seen: &mut Vec<u32>,
) -> Result<Vec<u8>, OpError> {
    let mut out = Vec::with_capacity(body.len());
    let mut rest = body;
    while !rest.is_empty() {
        let e = read_elem(rest)?;
        let mut hit = None;
        if let Some(n) = context_tag_number(e.tag) {
            if let Some((_, repl)) = overrides.iter().find(|(t, _)| *t == n) {
                hit = Some((n, repl));
            }
        }
        match hit {
            Some((n, repl)) => {
                out.extend_from_slice(repl);
                if !seen.contains(&n) {
                    seen.push(n);
                }
            }
            None => out.extend_from_slice(&rest[..e.total]),
        }
        rest = &rest[e.total..];
    }
    Ok(out)
}

/// Insert `element` (context tag number `num`) into an authorization-list body, keeping the list's
/// ascending tag order.
fn insert_in_order(body: Vec<u8>, num: u32, element: &[u8]) -> Result<Vec<u8>, OpError> {
    let mut out = Vec::with_capacity(body.len() + element.len());
    let mut rest: &[u8] = &body;
    let mut inserted = false;
    while !rest.is_empty() {
        let e = read_elem(rest)?;
        if !inserted {
            if let Some(n) = context_tag_number(e.tag) {
                if n > num {
                    out.extend_from_slice(element);
                    inserted = true;
                }
            }
        }
        out.extend_from_slice(&rest[..e.total]);
        rest = &rest[e.total..];
    }
    if !inserted {
        out.extend_from_slice(element);
    }
    Ok(out)
}

/// Build an `[tag_num] EXPLICIT INTEGER` element holding the non-negative `value`.
fn explicit_integer(tag_num: u32, value: u32) -> Vec<u8> {
    tlv(&context_tag(tag_num), &tlv(&[0x02], &der_uint(value)))
}

/// Build an `[tag_num] EXPLICIT OCTET STRING` element holding `value` — the encoding KeyMint uses for
/// attestation-ID tags.
fn explicit_octet_string(tag_num: u32, value: &[u8]) -> Vec<u8> {
    tlv(&context_tag(tag_num), &tlv(&[0x04], value))
}

/// DER identifier octets for a context-class, constructed tag (an `[n] EXPLICIT` tag).
// The low-tag path masks `n` to 5 bits before the cast and the base-128 path masks each digit to 7,
// so every `as u8` is exact.
#[allow(clippy::cast_possible_truncation)]
fn context_tag(n: u32) -> Vec<u8> {
    // Low tag numbers (0..=30) fit the identifier octet directly: context (0x80) | constructed (0x20).
    if n < 0x1f {
        return vec![0xA0 | (n & 0x1f) as u8];
    }
    let mut digits = Vec::new();
    let mut v = n;
    while v > 0 {
        digits.push((v & 0x7f) as u8);
        v >>= 7;
    }
    digits.reverse();
    let mut out = Vec::with_capacity(1 + digits.len());
    out.push(0xBF); // context (0x80) | constructed (0x20) | high-tag-number marker (0x1f)
    let last = digits.len() - 1;
    for (i, d) in digits.iter().enumerate() {
        // Every base-128 digit but the last carries the continuation bit.
        out.push(if i == last { *d } else { d | 0x80 });
    }
    out
}

/// The tag number of a context-class identifier, or `None` for any other class. Handles both the
/// low-tag form (`0xA0 | n`) and the high-tag-number form (`0xBF` then base-128 digits).
fn context_tag_number(tag: &[u8]) -> Option<u32> {
    let first = *tag.first()?;
    if first & 0xC0 != 0x80 {
        return None; // not context class
    }
    if first & 0x1f != 0x1f {
        return Some(u32::from(first & 0x1f));
    }
    let mut n: u32 = 0;
    for &b in &tag[1..] {
        n = n.checked_mul(128)?.checked_add(u32::from(b & 0x7f))?;
    }
    Some(n)
}

/// DER content octets for a non-negative INTEGER: minimal big-endian, with a leading `0x00` when the
/// top bit would otherwise make the value read as negative.
// Each `as u8` writes a byte already masked to 0..=255, so the truncation lint does not apply.
#[allow(clippy::cast_possible_truncation)]
fn der_uint(mut value: u32) -> Vec<u8> {
    if value == 0 {
        return vec![0x00];
    }
    let mut be = Vec::new();
    while value > 0 {
        be.push((value & 0xff) as u8);
        value >>= 8;
    }
    be.reverse();
    if be[0] & 0x80 != 0 {
        be.insert(0, 0x00);
    }
    be
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
