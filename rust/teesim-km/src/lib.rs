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

use kmr_common::crypto;
use kmr_crypto_boring::{
    aes::BoringAes, aes_cmac::BoringAesCmac, des::BoringDes, ec::BoringEc, eq::BoringEq,
    hmac::BoringHmac, rng::BoringRng, rsa::BoringRsa, sha256::BoringSha256,
};
use kmr_ta::device::{BootloaderDone, Implementation, TrustedPresenceUnsupported};
use kmr_ta::{HalInfo, HardwareInfo, KeyMintTa, RpcInfo, RpcInfoV3};
use kmr_wire::keymint::{BootInfo, SecurityLevel, VerifiedBootState};
use kmr_wire::rpc::MINIMUM_SUPPORTED_KEYS_IN_CSR;

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
}

impl Ta {
    /// Build a TA that attests with the keys from `keybox_xml`.
    ///
    /// `set_boot_info` is fed constant values so that the key-encryption keys the
    /// TA derives are reproducible across reboots; without that, blobs stored in
    /// keystore2's database would fail to decrypt after a restart.
    pub fn new(keybox_xml: &str) -> Result<Self, String> {
        let sign_info = attest::CertSignInfo::new(keybox_xml)?;

        let hw_info = HardwareInfo {
            version_number: 1,
            security_level: SecurityLevel::TrustedEnvironment,
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

        let dev = Implementation {
            keys: Box::new(device::Keys),
            sign_info: Some(Box::new(sign_info)),
            // Attestation IDs are not populated.
            attest_ids: None,
            // Rollback-resistant keys are declined (no secure-deletion store).
            sdd_mgr: None,
            bootloader: Box::new(BootloaderDone),
            sk_wrapper: None,
            tup: Box::new(TrustedPresenceUnsupported),
            legacy_key: None,
            rpc: Box::new(device::NoRpc),
        };

        let mut inner = KeyMintTa::new(hw_info, RpcInfo::V3(rpc_info), crypto_impls(), dev);

        // A constant root of trust keeps the derived key-encryption keys stable
        // across restarts, so blobs kept in keystore2's database stay usable.
        inner
            .set_boot_info(BootInfo {
                verified_boot_key: vec![0u8; 32],
                device_boot_locked: true,
                verified_boot_state: VerifiedBootState::Verified,
                verified_boot_hash: vec![0u8; 32],
                boot_patchlevel: 20240101,
            })
            .map_err(|e| format!("set_boot_info: {e:?}"))?;

        // OS and patch levels reported in attestation records.
        inner.set_hal_info(HalInfo {
            os_version: 160000,
            os_patchlevel: 202508,
            vendor_patchlevel: 20250805,
        });

        Ok(Ta { inner })
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
