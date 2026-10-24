"""The provisioning-information extension, OID 1.3.6.1.4.1.11129.2.1.30.

Google writes this map into every certificate it issues through RKP. Only two of its keys
are documented; the rest were established by measurement and are recorded in
`rkp/4-measurements.md` §3.1-3.4.

The field worth reading is key 1, `certs_issued` — AOSP describes it as the approximate
number of certificates issued for the device in the last 30 days, and says a value "greater
than average by some orders of magnitude" is an abuse signal. It sits inside the signature,
so a relying party can read it and the presenter cannot change it. What the documentation
never supplied was the average: a stock Redmi K70E measured **8**. Both leaked samples read
512, which is 64x that. See `rkp/4-measurements.md` §3.3.

Keys 5.1 and 5.3 carry the server's provisioning verdict. A certificate whose verdict is
NOT_APPROVED verifies perfectly and is worthless, so the verdict has to be gated on
explicitly and unknown keys have to be preserved rather than dropped — dropping them is
exactly how one documented acceptance checker passed a NOT_APPROVED certificate.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import cbor

OID = "1.3.6.1.4.1.11129.2.1.30"

# The stock baseline this toolkit compares against, and where it came from.
STOCK_CERTS_ISSUED = 8
STOCK_BASELINE_NOTE = "stock Redmi K70E (duchamp), measured before any patching"
# Flag anything an order of magnitude above the stock baseline, per AOSP's own wording.
CERTS_ISSUED_SUSPICIOUS_AT = STOCK_CERTS_ISSUED * 10

_KEY_NAMES = {
    1: "certs_issued",
    3: "oem",
    4: "validated_attested_entity",
    5: "device_record",
}
_RECORD_NAMES = {1: "verdict_1", 2: "build_digest", 3: "verdict_3", 4: "fingerprint"}


@dataclass
class DeviceRecord:
    """Key 5: the server's record of the device/build, present only on some certificates."""

    verdict_1: str | None = None
    build_digest: str | None = None
    verdict_3: str | None = None
    fingerprint: str | None = None
    unknown: dict[int, object] | None = None

    @property
    def verdicts(self) -> list[str]:
        return [v for v in (self.verdict_1, self.verdict_3) if v is not None]

    @property
    def approved(self) -> bool | None:
        """True if every verdict present says APPROVED, None if no verdict is present."""
        if not self.verdicts:
            return None
        return all(v == "APPROVED" for v in self.verdicts)


@dataclass
class ProvisioningInfo:
    certs_issued: int | None = None
    oem: str | None = None
    validated_attested_entity: str | None = None
    device_record: DeviceRecord | None = None
    unknown: dict[int, object] | None = None
    raw: bytes = b""

    # -- derived readings, each one a judgement the docs justify ------------------------

    @property
    def fingerprint_bound(self) -> bool:
        """Whether the certificate pins a build fingerprint in a signed field.

        An anonymous keybox (no key 5) constrains nothing and pairs with any profile. One
        carrying key 5.4 pins the identity the profile must present. Bound-ness is a
        property of the *request* that produced it, not of any donor device.
        """
        return bool(self.device_record and self.device_record.fingerprint)

    @property
    def provisioning_ok(self) -> bool | None:
        return self.device_record.approved if self.device_record else None

    @property
    def certs_issued_ratio(self) -> float | None:
        if self.certs_issued is None:
            return None
        return self.certs_issued / STOCK_CERTS_ISSUED

    def findings(self) -> list[tuple[str, str]]:
        """(severity, message) pairs, severity in {"fail", "warn", "info"}."""
        out: list[tuple[str, str]] = []

        if self.provisioning_ok is False:
            verdicts = ", ".join(self.device_record.verdicts)
            out.append(
                (
                    "fail",
                    f"provisioning status is not approved ({verdicts}) — this certificate "
                    "can pass every cryptographic check and still be worthless",
                )
            )
        elif self.provisioning_ok is None:
            out.append(
                ("info", "no provisioning verdict in this certificate (no key 5 record)")
            )

        if self.certs_issued is None:
            out.append(("info", "no certs_issued value (key 1 absent)"))
        elif self.certs_issued >= CERTS_ISSUED_SUSPICIOUS_AT:
            out.append(
                (
                    "warn",
                    f"certs_issued = {self.certs_issued}, "
                    f"{self.certs_issued_ratio:.0f}x the stock baseline of "
                    f"{STOCK_CERTS_ISSUED} ({STOCK_BASELINE_NOTE}) — Google's own abuse "
                    "signal, readable by any relying party",
                )
            )
        else:
            out.append(
                (
                    "info",
                    f"certs_issued = {self.certs_issued}, consistent with the stock "
                    f"baseline of {STOCK_CERTS_ISSUED} ({STOCK_BASELINE_NOTE})",
                )
            )

        if self.fingerprint_bound:
            out.append(
                (
                    "warn",
                    "fingerprint-bound: a verifier reading key 5.4 sees "
                    f"{self.device_record.fingerprint!r}, so the profile must present that "
                    "device or contradict itself in a signed field",
                )
            )

        if self.unknown:
            out.append(
                (
                    "info",
                    "unknown top-level keys preserved: "
                    + ", ".join(str(k) for k in sorted(self.unknown)),
                )
            )
        return out


def parse(extension_bytes: bytes) -> ProvisioningInfo:
    """Decode the extension's DER OCTET STRING contents (a CBOR map)."""
    value = cbor.load(extension_bytes)
    if not isinstance(value, cbor.Map):
        raise ValueError(f"provisioning extension is {type(value).__name__}, not a map")

    info = ProvisioningInfo(raw=extension_bytes)
    unknown: dict[int, object] = {}

    for key, val in value.pairs:
        name = _KEY_NAMES.get(key)
        if name == "certs_issued":
            info.certs_issued = val
        elif name == "oem":
            info.oem = val
        elif name == "validated_attested_entity":
            info.validated_attested_entity = val
        elif name == "device_record":
            info.device_record = _parse_record(val)
        else:
            # Preserved, never dropped: the map is documented as unversioned and new
            # optional fields may be added, and a dropped status field is a real bug class.
            unknown[key] = val

    info.unknown = unknown or None
    return info


def _parse_record(value: object) -> DeviceRecord:
    if not isinstance(value, cbor.Map):
        raise ValueError(f"key 5 is {type(value).__name__}, not a map")
    record = DeviceRecord()
    unknown: dict[int, object] = {}
    for key, val in value.pairs:
        name = _RECORD_NAMES.get(key)
        if name:
            setattr(record, name, val)
        else:
            unknown[key] = val
    record.unknown = unknown or None
    return record
