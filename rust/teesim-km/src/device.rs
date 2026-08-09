// Device trait implementations for the software TA.
//
// The root key material is fixed, which is what makes the derived key-encryption
// keys reproducible across restarts. Remote key provisioning is not intercepted,
// so its artifacts only need to exist.

use kmr_common::crypto::{self, Hkdf};
use kmr_common::{km_err, Error};
use kmr_ta::device::{
    DiceInfo, RetrieveAttestationIds, RetrieveKeyMaterial, RetrieveRpcArtifacts, RpcV2Req,
};
use kmr_wire::types::AttestationIdInfo;

/// Fixed root key material.
pub struct Keys;

impl RetrieveKeyMaterial for Keys {
    fn root_kek(&self, _context: &[u8]) -> Result<crypto::OpaqueOr<crypto::hmac::Key>, Error> {
        Ok(crypto::hmac::Key::new([0; 16].to_vec()).into())
    }
    fn kak(&self) -> Result<crypto::OpaqueOr<crypto::aes::Key>, Error> {
        Ok(crypto::aes::Key::Aes256([0; 32]).into())
    }
    fn unique_id_hbk(&self, _ckdf: &dyn crypto::Ckdf) -> Result<crypto::hmac::Key, Error> {
        crypto::hmac::Key::new_from(b"MustBeRandomBits")
    }
}

/// Monotonic clock backed by `CLOCK_BOOTTIME`.
pub struct Clock;

impl crypto::MonotonicClock for Clock {
    fn now(&self) -> crypto::MillisecondsSinceEpoch {
        let mut time = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // Safety: `time` is a valid structure that the call fills in.
        let rc = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) };
        if rc < 0 {
            return crypto::MillisecondsSinceEpoch(0);
        }
        crypto::MillisecondsSinceEpoch(((time.tv_sec * 1000) + (time.tv_nsec / 1_000_000)).into())
    }
}

/// Stub remote-provisioning artifacts. The interceptor never routes
/// IRemotelyProvisionedComponent calls here, so only `derive_bytes_from_hbk`
/// needs to work (and only to be deterministic).
pub struct NoRpc;

impl RetrieveRpcArtifacts for NoRpc {
    fn derive_bytes_from_hbk(
        &self,
        hkdf: &dyn Hkdf,
        context: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, Error> {
        hkdf.hkdf(&[], b"teesim-rpc-hbk", context, output_len)
    }

    fn get_dice_info(&self, _test_mode: kmr_wire::rpc::TestMode) -> Result<DiceInfo, Error> {
        Err(km_err!(Unimplemented, "remote provisioning is not supported"))
    }

    fn sign_data(
        &self,
        _ec: &dyn crypto::Ec,
        _data: &[u8],
        _rpc_v2: Option<RpcV2Req>,
    ) -> Result<Vec<u8>, Error> {
        Err(km_err!(Unimplemented, "remote provisioning is not supported"))
    }
}

/// Device-ID attestation values for a profile. `get` hands back a clone; the TA
/// vouches for exactly these when an app requests device-ID attestation.
/// `destroy_all` is a no-op — provisioned IDs are never wiped.
pub struct AttestIds(pub AttestationIdInfo);

impl RetrieveAttestationIds for AttestIds {
    fn get(&self) -> Result<AttestationIdInfo, Error> {
        Ok(self.0.clone())
    }

    fn destroy_all(&mut self) -> Result<(), Error> {
        Ok(())
    }
}
