// Per-method shims over the TA.
//
// Each method mirrors one IKeyMintDevice / IKeyMintOperation call: it builds the
// kmr_wire request, runs it through the TA, and returns the typed response. Blob
// arguments coming from keystore2 have our marker stripped before they reach the
// TA; blobs we hand back get the marker applied so later operations route here.

use crate::{as_array, mark_blob, strip_marker, OpError, Ta};
use kmr_wire::keymint::{
    AttestationKey, HardwareAuthToken, KeyCharacteristics, KeyCreationResult, KeyFormat, KeyParam,
    KeyPurpose, SecurityLevel,
};
use kmr_wire::secureclock::TimeStampToken;
use kmr_wire::{
    cbor, read_to_value, AbortRequest, AbortResponse, AsCborValue, BeginRequest, BeginResponse,
    Code, DeleteKeyRequest, DeleteKeyResponse, FinishRequest, FinishResponse, GenerateKeyRequest,
    GenerateKeyResponse,
    GetKeyCharacteristicsRequest, GetKeyCharacteristicsResponse, ImportKeyRequest, ImportKeyResponse,
    InternalBeginResult, KeyMintOperation, UpdateAadRequest, UpdateAadResponse, UpdateRequest,
    UpdateResponse, UpgradeKeyRequest, UpgradeKeyResponse,
};

/// KeyMint `ErrorCode::UnknownError`, used for local (non-TA) failures.
const ERR_UNKNOWN: i32 = -1000;

impl Ta {
    /// Encode `req`, run it through the TA, and decode the typed response.
    ///
    /// Mirrors kmr-hal's channel framing: the request is `[opcode, req]` and the
    /// reply is `[error_code, [[op_type, rsp]]]`.
    fn perform<Req, Rsp>(&mut self, req: Req) -> Result<Rsp, OpError>
    where
        Req: AsCborValue + Code<KeyMintOperation>,
        Rsp: AsCborValue + Code<KeyMintOperation>,
    {
        let local = |m: String| OpError { code: ERR_UNKNOWN, msg: m };

        let req_arr = cbor::value::Value::Array(vec![
            <Req>::CODE.to_cbor_value().map_err(|e| local(format!("{e:?}")))?,
            req.to_cbor_value().map_err(|e| local(format!("{e:?}")))?,
        ]);
        let mut req_data = Vec::new();
        cbor::ser::into_writer(&req_arr, &mut req_data).map_err(|e| local(format!("encode: {e:?}")))?;

        let rsp = self.inner.process(&req_data);

        let mut top = as_array(read_to_value(&rsp).map_err(|e| local(format!("{e:?}")))?, 2)
            .map_err(&local)?;
        let opt_response = top.remove(1);
        let error_code = i32::from_cbor_value(top.remove(0)).map_err(|e| local(format!("{e:?}")))?;
        if error_code != 0 {
            return Err(OpError { code: error_code, msg: format!("TA error {error_code}") });
        }
        let mut one = as_array(opt_response, 1).map_err(&local)?;
        let mut inner = as_array(one.remove(0), 2).map_err(&local)?;
        let resp_value = inner.remove(1);
        let op_type =
            KeyMintOperation::from_cbor_value(inner.remove(0)).map_err(|e| local(format!("{e:?}")))?;
        if op_type != <Rsp>::CODE {
            return Err(local(format!("unexpected op_type {op_type:?}")));
        }
        Rsp::from_cbor_value(resp_value).map_err(|e| local(format!("{e:?}")))
    }

    /// Apply a per-request attestation identity — security level and KeyMint HAL version — to the
    /// inner TA for the duration of one generateKey/importKey, returning the previous pair to restore
    /// afterwards. The record's `attestationSecurityLevel` / `keymasterSecurityLevel` and the
    /// KeyCharacteristics `securityLevel` follow `hw_info.security_level`; its `attestationVersion` /
    /// `keymintVersion` follow the TA's `aidl_version`. Overriding both makes the record reflect the
    /// real HAL the request came through: `security_level` picks the level (0 Software, 1
    /// TrustedEnvironment, 2 StrongBox) and the version harvested at that level (StrongBox falling
    /// back to the TEE version). A level outside the known set leaves the TA's defaults in place.
    fn override_attestation_identity(&mut self, security_level: i32) -> Option<(SecurityLevel, i32)> {
        let level = match security_level {
            0 => SecurityLevel::Software,
            1 => SecurityLevel::TrustedEnvironment,
            2 => SecurityLevel::Strongbox,
            _ => return None,
        };
        let prev = (self.inner.security_level(), self.inner.aidl_version());
        self.inner.set_security_level(level);
        let version = match level {
            SecurityLevel::Strongbox => self.attest_version_strongbox,
            _ => self.attest_version_tee,
        };
        self.inner.set_aidl_version(version);
        Some(prev)
    }

    /// generateKey. The returned key blob carries our marker. `security_level` is
    /// the level of the HAL the request came through; the attestation is emitted
    /// at that level (see `override_security_level`).
    pub fn generate_key(
        &mut self,
        key_params: Vec<KeyParam>,
        attestation_key: Option<AttestationKey>,
        security_level: i32,
    ) -> Result<KeyCreationResult, OpError> {
        let restore = self.override_attestation_identity(security_level);
        let resp: Result<GenerateKeyResponse, OpError> =
            self.perform(GenerateKeyRequest { key_params, attestation_key });
        if let Some((level, version)) = restore {
            self.inner.set_security_level(level);
            self.inner.set_aidl_version(version);
        }
        Ok(marked_result(resp?.ret))
    }

    /// importKey. The returned key blob carries our marker. `security_level` is
    /// the level of the HAL the request came through; the attestation is emitted
    /// at that level (see `override_security_level`).
    pub fn import_key(
        &mut self,
        key_params: Vec<KeyParam>,
        key_format: KeyFormat,
        key_data: Vec<u8>,
        attestation_key: Option<AttestationKey>,
        security_level: i32,
    ) -> Result<KeyCreationResult, OpError> {
        let restore = self.override_attestation_identity(security_level);
        let resp: Result<ImportKeyResponse, OpError> =
            self.perform(ImportKeyRequest { key_params, key_format, key_data, attestation_key });
        if let Some((level, version)) = restore {
            self.inner.set_security_level(level);
            self.inner.set_aidl_version(version);
        }
        Ok(marked_result(resp?.ret))
    }

    /// begin. `key_blob` is a marked blob; the marker is stripped before use.
    pub fn begin(
        &mut self,
        purpose: KeyPurpose,
        key_blob: &[u8],
        params: Vec<KeyParam>,
        auth_token: Option<HardwareAuthToken>,
    ) -> Result<InternalBeginResult, OpError> {
        let resp: BeginResponse = self.perform(BeginRequest {
            purpose,
            key_blob: strip_marker(key_blob).to_vec(),
            params,
            auth_token,
        })?;
        Ok(resp.ret)
    }

    /// update on an in-progress operation.
    pub fn update(
        &mut self,
        op_handle: i64,
        input: Vec<u8>,
        auth_token: Option<HardwareAuthToken>,
        timestamp_token: Option<TimeStampToken>,
    ) -> Result<Vec<u8>, OpError> {
        let resp: UpdateResponse =
            self.perform(UpdateRequest { op_handle, input, auth_token, timestamp_token })?;
        Ok(resp.ret)
    }

    /// updateAad on an in-progress operation.
    pub fn update_aad(
        &mut self,
        op_handle: i64,
        input: Vec<u8>,
        auth_token: Option<HardwareAuthToken>,
        timestamp_token: Option<TimeStampToken>,
    ) -> Result<(), OpError> {
        let _: UpdateAadResponse =
            self.perform(UpdateAadRequest { op_handle, input, auth_token, timestamp_token })?;
        Ok(())
    }

    /// finish an operation.
    pub fn finish(
        &mut self,
        op_handle: i64,
        input: Option<Vec<u8>>,
        signature: Option<Vec<u8>>,
        auth_token: Option<HardwareAuthToken>,
        timestamp_token: Option<TimeStampToken>,
        confirmation_token: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, OpError> {
        let resp: FinishResponse = self.perform(FinishRequest {
            op_handle,
            input,
            signature,
            auth_token,
            timestamp_token,
            confirmation_token,
        })?;
        Ok(resp.ret)
    }

    /// abort an operation.
    pub fn abort(&mut self, op_handle: i64) -> Result<(), OpError> {
        let _: AbortResponse = self.perform(AbortRequest { op_handle })?;
        Ok(())
    }

    /// deleteKey. `key_blob` is a marked blob.
    pub fn delete_key(&mut self, key_blob: &[u8]) -> Result<(), OpError> {
        let _: DeleteKeyResponse =
            self.perform(DeleteKeyRequest { key_blob: strip_marker(key_blob).to_vec() })?;
        Ok(())
    }

    /// upgradeKey. Consumes a marked blob and returns a freshly marked one.
    pub fn upgrade_key(
        &mut self,
        key_blob: &[u8],
        upgrade_params: Vec<KeyParam>,
    ) -> Result<Vec<u8>, OpError> {
        let resp: UpgradeKeyResponse = self.perform(UpgradeKeyRequest {
            key_blob_to_upgrade: strip_marker(key_blob).to_vec(),
            upgrade_params,
        })?;
        Ok(mark_blob(&resp.ret))
    }

    /// getKeyCharacteristics. `key_blob` is a marked blob.
    pub fn get_key_characteristics(
        &mut self,
        key_blob: &[u8],
        app_id: Vec<u8>,
        app_data: Vec<u8>,
    ) -> Result<Vec<KeyCharacteristics>, OpError> {
        let resp: GetKeyCharacteristicsResponse = self.perform(GetKeyCharacteristicsRequest {
            key_blob: strip_marker(key_blob).to_vec(),
            app_id,
            app_data,
        })?;
        Ok(resp.ret)
    }
}

/// Apply our marker to the key blob inside a creation result.
fn marked_result(mut r: KeyCreationResult) -> KeyCreationResult {
    r.key_blob = mark_blob(&r.key_blob);
    r
}
