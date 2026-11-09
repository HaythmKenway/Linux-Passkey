"""Read official Bitwarden JSON exports without logging private vault data.

Only modern discoverable ES256 passkeys with a zero signature counter are
supported. A file import is an independent local copy, not a connected vault.
"""

import base64
import binascii
import fcntl
from dataclasses import dataclass, field
from datetime import datetime
import json
import os
import re
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec

from . import keys
from .store import b64e
from .webauthn import public_suffix_list

MAX_EXPORT_BYTES = 16 * 1024 * 1024
MAX_CREDENTIALS = 1000
MAX_ID_BYTES = 1023
_SEALS = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL


def create_import_fd(data):
    """Put a bounded export in an immutable memfd; caller closes the result."""
    if not isinstance(data, bytes) or len(data) > MAX_EXPORT_BYTES:
        raise ImportError("Export exceeds the 16 MiB limit")
    fd = os.memfd_create("passkey-import", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        with os.fdopen(os.dup(fd), "wb") as stream:
            stream.write(data)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, _SEALS)
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_import_fd(fd):
    """Read only sealed, bounded descriptors; never accept a caller's path."""
    try:
        if fcntl.fcntl(fd, fcntl.F_GET_SEALS) & _SEALS != _SEALS:
            raise ImportError("An immutable import descriptor is required")
        if os.fstat(fd).st_size > MAX_EXPORT_BYTES:
            raise ImportError("Export exceeds the 16 MiB limit")
        return os.pread(fd, MAX_EXPORT_BYTES + 1, 0)
    except OSError:
        raise ImportError("An immutable import descriptor is required") from None


class ImportError(ValueError):
    """A sanitized, user-facing import error, never containing input values."""


@dataclass(frozen=True)
class ImportedCredential:
    """Validated key material; private bytes are excluded from representations."""

    id: bytes
    rp_id: str
    user_id: bytes
    user_name: str
    display_name: str
    rp_name: str
    created: int
    private_key: bytes = field(repr=False)
    alg: int = keys.ES256


@dataclass
class ImportBatch:
    """Valid candidates and positional rejection reasons for a single file."""

    credentials: list = field(default_factory=list, repr=False)
    errors: list = field(default_factory=list)

    def summary(self):
        """Return only public preview data, never keys or the original export."""
        return {
            "credentials": [dict(rp_id=c.rp_id, user_name=c.user_name,
                                 display_name=c.display_name) for c in self.credentials],
            "errors": list(self.errors),
        }


def _decode(value, maximum):
    if not isinstance(value, str) or len(value) > maximum * 2:
        raise ImportError("Invalid base64url field")
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        raise ImportError("Invalid base64url field") from None
    if not 0 < len(raw) <= maximum or b64e(raw) != value:
        raise ImportError("Invalid base64url field")
    return raw


def _text(obj, name, default=""):
    value = obj.get(name, default)
    if not isinstance(value, str) or len(value) > 256 or any(ord(c) < 32 for c in value):
        raise ImportError("Invalid account metadata")
    return value


def _map(entry):
    if not isinstance(entry, dict):
        raise ImportError("Invalid passkey object")
    if (entry.get("keyType"), entry.get("keyAlgorithm"), entry.get("keyCurve")) != (
        "public-key", "ECDSA", "P-256"
    ):
        raise ImportError("Only ES256 / P-256 passkeys are supported")
    if entry.get("counter") != "0":
        raise ImportError("Nonzero or missing signature counter is unsupported")
    if entry.get("discoverable") != "true":
        raise ImportError("Only discoverable passkeys are supported")
    # The examined Bitwarden producer signs with BE=BS=true. It does not
    # export these fields; if supplied, contradictory states are rejected.
    if entry.get("backupEligible", True) is not True or entry.get("backupState", True) is not True:
        raise ImportError("Incompatible credential backup state")
    ident = entry.get("credentialId")
    if not isinstance(ident, str):
        raise ImportError("Missing credential ID")
    if ident.startswith("b64."):
        cred_id = _decode(ident[4:], MAX_ID_BYTES)
    else:
        try:
            parsed = uuid.UUID(ident)
            if str(parsed) != ident.lower():
                raise ValueError()
            cred_id = parsed.bytes
        except (ValueError, AttributeError):
            raise ImportError("Invalid credential ID") from None
    rp = _text(entry, "rpId")
    if (not rp or len(rp) > 253 or rp != rp.lower()
            or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", s) for s in rp.split("."))):
        raise ImportError("Invalid relying party ID")
    if public_suffix_list().is_public_suffix(rp):
        raise ImportError("Relying party ID is a public suffix")
    raw = _decode(entry.get("keyValue"), 4096)
    try:
        key = serialization.load_der_private_key(raw, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise ImportError("Invalid PKCS#8 private key") from None
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ImportError("Private key does not match ES256 / P-256")
    created = entry.get("creationDate")
    try:
        if not isinstance(created, str) or len(created) > 40:
            raise ValueError()
        stamp = datetime.fromisoformat(created.replace("Z", "+00:00"))
        if stamp.tzinfo is None or stamp.year < 1970 or stamp.year > 9998:
            raise ValueError()
        created = int(stamp.timestamp())
    except (ValueError, OverflowError):
        raise ImportError("Missing or invalid creation date") from None
    return ImportedCredential(
        cred_id, rp, _decode(entry.get("userHandle"), 64),
        _text(entry, "userName"), _text(entry, "userDisplayName"),
        _text(entry, "rpName", rp), created, keys.private_bytes(keys.ES256, key),
    )


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ImportError("Duplicate JSON fields")
        result[key] = value
    return result


def parse_export(data):
    """Validate a bounded JSON export, returning valid keys and safe rejections.

    Invalid entries do not become credentials. Committing the valid subset is
    a separate, explicitly authorized operation owned by the daemon.
    """
    if not isinstance(data, bytes) or len(data) > MAX_EXPORT_BYTES:
        raise ImportError("Export exceeds the 16 MiB limit")
    try:
        root = json.loads(data, object_pairs_hook=_object)
    except (ValueError, UnicodeError, RecursionError):
        raise ImportError("Invalid export JSON") from None
    if not isinstance(root, dict) or root.get("encrypted", False) is not False:
        raise ImportError("An unencrypted Bitwarden JSON export is required")
    items = root.get("items")
    if not isinstance(items, list) or len(items) > 10000:
        raise ImportError("Invalid export items")
    batch = ImportBatch()
    count = 0
    for item in items:
        login = item.get("login") if isinstance(item, dict) else None
        entries = login.get("fido2Credentials", []) if isinstance(login, dict) else []
        if not isinstance(entries, list):
            raise ImportError("Invalid passkey list")
        for entry in entries:
            count += 1
            if count > MAX_CREDENTIALS:
                raise ImportError("Export exceeds the 1000 passkey limit")
            try:
                batch.credentials.append(_map(entry))
            except ImportError as e:
                batch.errors.append("%d: %s" % (count, e))
            except OSError:
                raise ImportError("Public Suffix List is unavailable") from None
    return batch
