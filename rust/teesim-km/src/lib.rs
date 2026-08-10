// In-process KeyMint trusted application.
//
// Wraps the reference TA (kmr-ta) with a BoringSSL crypto backend and
// keybox-based attestation signing, and exposes a small request/response
// surface. The native interceptor decodes an intercepted IKeyMintDevice
// transaction into a kmr_wire request, calls `Ta::process`, and re-encodes the
// reply.

extern crate alloc;

mod attest;
pub mod capi;
mod device;
pub mod ffi;
mod ops;
mod resign;

use kmr_common::crypto;
use kmr_crypto_boring::{
    aes::BoringAes, aes_cmac::BoringAesCmac, des::BoringDes, ec::BoringEc, eq::BoringEq,
    hmac::BoringHmac, rng::BoringRng, rsa::BoringRsa, sha256::BoringSha256,
};
use kmr_ta::device::{
    BootloaderDone, Implementation, RetrieveAttestationIds, TrustedPresenceUnsupported,
};
use kmr_ta::{HalInfo, HardwareInfo, KeyMintTa, RpcInfo, RpcInfoV3};
use kmr_wire::keymint::{BootInfo, SecurityLevel, VerifiedBootState};
use kmr_wire::rpc::MINIMUM_SUPPORTED_KEYS_IN_CSR;
use kmr_wire::types::AttestationIdInfo;

/// Prefix stamped on every key blob produced by this TA. It lets the interceptor
/// route later operations: a blob that starts with this marker belongs to us and
/// is served here; anything else is forwarded to the real TEE. It must not
/// collide with the reserved km_compat prefixes (`pKMblob\0`, `pKMblob\1`,
/// `SoftKeyMintForV1Blob`).
pub const BLOB_MARKER: &[u8] = b"TEESIMkm\x00";

/// True if `blob` was produced by this TA.
pub fn is_marked(blob: &[u8]) -> bool {
    blob.starts_with(BLOB_MARKER)
}

/// Assemble the software crypto backend around BoringSSL and the boot-time clock.
fn crypto_impls() -> crypto::Implementation {
    crypto::Implementation {
        rng: Box::new(BoringRng),
        clock: Some(Box::new(device::Clock)),
        compare: Box::new(BoringEq),
        aes: Box::new(BoringAes),
        des: Box::new(BoringDes),
        hmac: Box::new(BoringHmac),
        rsa: Box::new(BoringRsa::default()),
        ec: Box::new(BoringEc::default()),
        ckdf: Box::new(BoringAesCmac),
        hkdf: Box::new(BoringHmac),
        sha256: Box::new(BoringSha256),
    }
}

/// The in-process TA plus the state the router needs around it.
pub struct Ta {
    inner: KeyMintTa,
    /// Retained copy of the keybox signing keys. kmr-ta owns its own copy for generation but does
    /// not expose it, and patch mode needs it to re-sign a real attestation leaf under the keybox.
    sign_info: attest::CertSignInfo,
    /// The profile's root of trust (locked/Verified) as a DER `RootOfTrust` SEQUENCE, spliced into a
    /// real leaf's attestation extension in patch mode. Identical to what generation emits.
    patch_rot: Vec<u8>,
    /// KeyMint HAL versions harvested at each level. The per-request override (see
    /// `override_attestation_identity`) sets the record's attestation/keymint version to match the
    /// HAL the request came through, so a generated key claims the real device's version.
    attest_version_tee: i32,
    attest_version_strongbox: i32,
}

/// Everything beyond the crypto backend that shapes a profile's attestation
/// records. The daemon resolves all of it and the interceptor hands it to
/// `Ta::new_ex`. The verified-boot fields feed KeyMint's key-encryption-key
/// derivation as well as the record's root of trust, so they are device-wide and
/// frozen — the daemon sends the device's real, unchanging values, which keeps
/// stored blobs decryptable across reboots and across profiles.
pub struct TaConfig<'a> {
    /// Contents of the profile's keybox.xml.
    pub keybox_xml: &'a str,
    /// 0 Software, 1 TrustedEnvironment, 2 StrongBox.
    pub security_level: i32,
    /// OS version, encoded `major*10000 + minor*100 + sub`.
    pub os_version: u32,
    /// System patch level, `YYYYMM`.
    pub os_patchlevel: u32,
    /// Vendor patch level, `YYYYMMDD`.
    pub vendor_patchlevel: u32,
    /// Boot patch level, `YYYYMMDD`.
    pub boot_patchlevel: u32,
    /// Verified-boot key digest (device-wide; feeds the KEK — keep it frozen).
    pub verified_boot_key: Vec<u8>,
    /// Verified-boot hash (device-wide).
    pub verified_boot_hash: Vec<u8>,
    /// Whether the bootloader reports the device locked.
    pub device_boot_locked: bool,
    /// 0 Verified, 1 SelfSigned, 2 Unverified, 3 Failed.
    pub verified_boot_state: i32,
    /// KeyMint HAL version harvested at TrustedEnvironment (attestationVersion; 100/200/300/400),
    /// reported by keys attested at that level.
    pub attest_version_tee: i32,
    /// KeyMint HAL version harvested at StrongBox; falls back to the TEE value when StrongBox is
    /// unavailable (a broken StrongBox is still offered, served by generation at the TEE version).
    pub attest_version_strongbox: i32,
    /// Device-ID values to vouch for, or `None` to decline ID attestation.
    pub attestation_ids: Option<AttestationIdInfo>,
}

impl<'a> TaConfig<'a> {
    /// The historical hard-coded identity, used when no daemon has pushed config
    /// yet (and by the plain `teesim_km_init` entry point). A zeroed root of trust
    /// is a placeholder; a configured profile supplies the device's real values.
    pub fn defaults(keybox_xml: &'a str) -> Self {
        TaConfig {
            keybox_xml,
            security_level: SecurityLevel::TrustedEnvironment as i32,
            os_version: 160000,
            os_patchlevel: 202508,
            vendor_patchlevel: 20250805,
            boot_patchlevel: 20240101,
            verified_boot_key: vec![0u8; 32],
            verified_boot_hash: vec![0u8; 32],
            device_boot_locked: true,
            verified_boot_state: VerifiedBootState::Verified as i32,
            attest_version_tee: 400,
            attest_version_strongbox: 400,
            attestation_ids: None,
        }
    }
}

impl Ta {
    /// Build a TA with the historical defaults, attesting with `keybox_xml`.
    pub fn new(keybox_xml: &str) -> Result<Self, String> {
        Self::new_ex(TaConfig::defaults(keybox_xml))
    }

    /// Build a TA from a fully resolved profile configuration.
    pub fn new_ex(cfg: TaConfig) -> Result<Self, String> {
        let sign_info = attest::CertSignInfo::new(cfg.keybox_xml)?;

        let security_level = match cfg.security_level {
            0 => SecurityLevel::Software,
            2 => SecurityLevel::Strongbox,
            _ => SecurityLevel::TrustedEnvironment,
        };
        let hw_info = HardwareInfo {
            version_number: 1,
            security_level,
            impl_name: "TEESimulator KeyMint",
            author_name: "TEESimulator",
            unique_id: "TEESimulator KeyMint TA",
        };
        let rpc_info = RpcInfoV3 {
            author_name: "TEESimulator",
            unique_id: "TEESimulator KeyMint TA",
            fused: false,
            supported_num_of_keys_in_csr: MINIMUM_SUPPORTED_KEYS_IN_CSR,
        };

        // Device-ID attestation is offered only when the profile supplies IDs.
        let attest_ids: Option<Box<dyn RetrieveAttestationIds>> = cfg
            .attestation_ids
            .map(|ids| Box::new(device::AttestIds(ids)) as Box<dyn RetrieveAttestationIds>);

        let dev = Implementation {
            keys: Box::new(device::Keys),
            sign_info: Some(Box::new(sign_info.clone())),
            attest_ids,
            // Rollback-resistant keys are declined (no secure-deletion store).
            sdd_mgr: None,
            bootloader: Box::new(BootloaderDone),
            sk_wrapper: None,
            tup: Box::new(TrustedPresenceUnsupported),
            legacy_key: None,
            rpc: Box::new(device::NoRpc),
        };

        let mut inner = KeyMintTa::new(hw_info, RpcInfo::V3(rpc_info), crypto_impls(), dev);

        let verified_boot_state = match cfg.verified_boot_state {
            1 => VerifiedBootState::SelfSigned,
            2 => VerifiedBootState::Unverified,
            3 => VerifiedBootState::Failed,
            _ => VerifiedBootState::Verified,
        };
        // Precompute the root of trust patch mode splices into a real leaf, from the same values the
        // generation path feeds into kmr-ta's boot info (below), so both modes report it identically.
        let patch_rot = resign::build_root_of_trust(
            &cfg.verified_boot_key,
            cfg.device_boot_locked,
            cfg.verified_boot_state,
            &cfg.verified_boot_hash,
        );
        // These fields double as the attestation record's root of trust and as
        // inputs to the KEK derivation. The daemon supplies the device's real,
        // frozen values, so the KEK stays stable across reboots and every profile
        // derives the same one (blobs are cross-decryptable).
        inner
            .set_boot_info(BootInfo {
                verified_boot_key: cfg.verified_boot_key,
                device_boot_locked: cfg.device_boot_locked,
                verified_boot_state,
                verified_boot_hash: cfg.verified_boot_hash,
                boot_patchlevel: cfg.boot_patchlevel,
            })
            .map_err(|e| format!("set_boot_info: {e:?}"))?;

        inner.set_hal_info(HalInfo {
            os_version: cfg.os_version,
            os_patchlevel: cfg.os_patchlevel,
            vendor_patchlevel: cfg.vendor_patchlevel,
        });

        Ok(Ta {
            inner,
            sign_info,
            patch_rot,
            attest_version_tee: cfg.attest_version_tee,
            attest_version_strongbox: cfg.attest_version_strongbox,
        })
    }

    /// Feed a serialized kmr_wire request to the TA and return the serialized
    /// response.
    pub fn process(&mut self, req: &[u8]) -> Vec<u8> {
        self.inner.process(req)
    }

}

/// A failed per-method operation: a KeyMint error code plus a message.
pub struct OpError {
    pub code: i32,
    pub msg: String,
}

/// Apply the routing marker to a key blob.
pub(crate) fn mark_blob(blob: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(BLOB_MARKER.len() + blob.len());
    v.extend_from_slice(BLOB_MARKER);
    v.extend_from_slice(blob);
    v
}

/// Strip the routing marker if present.
pub(crate) fn strip_marker(blob: &[u8]) -> &[u8] {
    blob.strip_prefix(BLOB_MARKER).unwrap_or(blob)
}

/// Interpret a CBOR value as an array of the expected length.
pub(crate) fn as_array(
    value: kmr_wire::cbor::value::Value,
    len: usize,
) -> Result<Vec<kmr_wire::cbor::value::Value>, String> {
    match value {
        kmr_wire::cbor::value::Value::Array(a) if a.len() == len => Ok(a),
        other => Err(format!("expected CBOR array of {len}, got {other:?}")),
    }
}
