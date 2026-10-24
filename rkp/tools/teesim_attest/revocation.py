"""Google's attestation revocation list, with both serial encodings checked.

Leaf revocation for Android attestation does not go through a CRL -- it goes through a JSON
status list at `https://android.googleapis.com/attestation/status`, keyed by certificate
serial number.

The schema says the key is the serial "in lowercase hex", and Google's own reference verifier
does `revokedSerials.contains(cert.serialNumber.toString(16))`. Measured against the live
list, that matches only part of it: a large share of entries contain no `a`-`f` digit at all
and read as decimal. They are *syntactically* valid lowercase hex, which is why nothing
rejects them and why the problem is silent. A verifier that renders each serial only as hex
therefore fails to match roughly half the revoked population -- most likely including the
older factory-keybox entries that matter most.

So every lookup here tests both `format(serial, 'x')` and `str(serial)`, and the result
records which form matched. `summarise` prints the per-form counts, because a decimal-match
counter stuck at zero over a large sample means revocation is probably not being enforced for
that population at all.

See `docs/attestation-key-compromise.md` section 6.3.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

STATUS_URL = "https://android.googleapis.com/attestation/status"
DEFAULT_TIMEOUT = 15


class RevocationUnavailable(RuntimeError):
    pass


@dataclass
class Entry:
    serial: int
    matched_as: str | None  # "hex", "decimal", or None when not revoked
    status: str | None = None
    reason: str | None = None

    @property
    def revoked(self) -> bool:
        return self.matched_as is not None


@dataclass
class StatusList:
    entries: dict[str, dict]
    source: str

    def __len__(self) -> int:
        return len(self.entries)

    def look_up(self, serial: int) -> Entry:
        for form, key in (("hex", format(serial, "x")), ("decimal", str(serial))):
            record = self.entries.get(key)
            if record is not None:
                return Entry(
                    serial=serial,
                    matched_as=form,
                    status=record.get("status"),
                    reason=record.get("reason"),
                )
        return Entry(serial=serial, matched_as=None)

    def shape(self) -> list[str]:
        """Describe the two populations, so the mixed encoding is visible in any report."""
        hex_like = [k for k in self.entries if any(c in "abcdef" for c in k)]
        digits_only = [k for k in self.entries if k.isdigit()]
        return [
            f"{len(self.entries)} entries from {self.source}",
            f"{len(hex_like)} contain a-f (unambiguously hex)",
            f"{len(digits_only)} are digits only (hex-valid, but read as decimal by Google's "
            "own tooling for at least part of this population)",
        ]


def fetch(cache: Path | None = None, *, offline: bool = False) -> StatusList:
    """Fetch the list, falling back to `cache` and refreshing it on success."""
    if not offline:
        try:
            request = urllib.request.Request(
                STATUS_URL, headers={"User-Agent": "teesim-attest/1"}
            )
            with urllib.request.urlopen(request, timeout=DEFAULT_TIMEOUT) as response:
                raw = response.read()
            data = json.loads(raw)
            if cache is not None:
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_bytes(raw)
            return StatusList(entries=data.get("entries", {}), source=STATUS_URL)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            if cache is None or not cache.is_file():
                raise RevocationUnavailable(f"{STATUS_URL}: {exc}") from exc

    if cache is None or not cache.is_file():
        raise RevocationUnavailable("offline and no cached status list")
    data = json.loads(cache.read_text())
    return StatusList(entries=data.get("entries", {}), source=f"{cache} (cached)")


@dataclass
class Report:
    checked: list[Entry] = field(default_factory=list)

    @property
    def revoked(self) -> list[Entry]:
        return [e for e in self.checked if e.revoked]

    def counts_by_form(self) -> dict[str, int]:
        out = {"hex": 0, "decimal": 0}
        for entry in self.revoked:
            out[entry.matched_as] += 1
        return out

    def summarise(self) -> list[str]:
        out = [f"{len(self.revoked)} of {len(self.checked)} serial(s) revoked"]
        for form, count in self.counts_by_form().items():
            out.append(f"  matched as {form}: {count}")
        if self.revoked and self.counts_by_form()["decimal"] == 0:
            out.append(
                "  note: no decimal matches. Over a large sample that would suggest the "
                "older keybox population is not being checked at all"
            )
        return out


def check(serials: list[int], status: StatusList) -> Report:
    return Report(checked=[status.look_up(s) for s in serials])
