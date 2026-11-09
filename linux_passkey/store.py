"""Credential storage.

Every credential ID is self-contained: it carries the credential's private
key encrypted (AES-256-GCM) under a key derived from the master key, bound to
the relying party's ID hash. This is the same "key wrapping" approach used by
hardware security keys and allows an unlimited number of non-discoverable
credentials.

Discoverable credentials (passkeys) additionally have a metadata record
(relying party, user handle, account name, ...) in an encrypted file so that
they can be found without an allow list, listed and deleted. A wrapped
credential marked as discoverable is only honoured while its record exists,
so deleting a passkey really revokes it.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import threading
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import cbor, keys, paths

CRED_ID_VERSION = 1
STORE_VERSION = 1
log = logging.getLogger(__name__)


def b64e(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64d(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _derive(master, info):
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=info
    ).derive(master)


class Credential:
    """A credential recovered from its ID (and its record, if discoverable)."""

    __slots__ = (
        "id", "alg", "private_key", "resident", "cred_protect", "hmac_seed", "record"
    )

    def __init__(self, cred_id, alg, private_key, resident, cred_protect, hmac_seed,
                 record):
        self.id = cred_id
        self.hmac_seed = hmac_seed
        self.alg = alg
        self.private_key = private_key
        self.resident = resident
        self.cred_protect = cred_protect
        self.record = record


class CredentialStore:
    FILENAME = "credentials.enc"

    @classmethod
    def default_path(cls):
        return os.path.join(paths.data_dir(), cls.FILENAME)

    def __init__(self, master_key, directory=None):
        self.directory = directory or paths.data_dir()
        self.path = os.path.join(self.directory, self.FILENAME)
        self._lock = threading.RLock()
        self._listeners = []
        self._set_master(master_key)
        self._load()

    # -- keys -------------------------------------------------------------

    def _set_master(self, master_key):
        # These labels date from the project's first name. They are part of
        # the key derivation: changing them would make every stored passkey
        # unreadable, so they stay as they are.
        self._wrap = AESGCM(_derive(master_key, b"ubuntu-passkey credential wrap"))
        self._seal = AESGCM(_derive(master_key, b"ubuntu-passkey store"))

    # -- persistence ------------------------------------------------------

    def _load(self):
        self._version = STORE_VERSION
        self._records = {}
        self._counter = 0
        try:
            with open(self.path, "rb") as f:
                blob = f.read()
        except FileNotFoundError:
            return
        if len(blob) < 13 or blob[0] not in (1, 2):
            raise ValueError("unsupported credential store format")
        self._version = blob[0]
        try:
            plain = self._seal.decrypt(blob[1:13], blob[13:], blob[:1])
        except InvalidTag:
            raise ValueError(
                "credential store cannot be decrypted with the current master key"
            )
        data = json.loads(plain)
        self._counter = int(data.get("counter", 0))
        for rec in data.get("credentials", []):
            self._records[rec["id"]] = rec

    def _save(self):
        self._persist(self._records, self._version)
        self._notify()

    def _persist(self, records, version):
        """Write a candidate without changing live records or notifying clients."""
        data = {
            "counter": self._counter,
            "credentials": sorted(records.values(), key=lambda r: r["created"]),
        }
        nonce = os.urandom(12)
        header = bytes([version])
        blob = header + nonce + self._seal.encrypt(
            nonce, json.dumps(data).encode(), header
        )
        paths.atomic_write(self.path, blob)

    def _notify(self):
        for listener in list(self._listeners):
            try:
                listener()
            except Exception:
                # Notification failure must not turn a committed transaction
                # into an apparent failure, or expose private exception data.
                log.warning("credential change notification failed")

    def add_listener(self, callback):
        self._listeners.append(callback)

    # -- credential IDs ---------------------------------------------------

    def create(self, rp_id_hash, alg, resident, cred_protect=1):
        """Generate a key pair; return (credential_id, private_key)."""
        private_key = keys.generate(alg)
        payload = cbor.encode(
            {
                1: alg,
                2: keys.private_bytes(alg, private_key),
                3: bool(resident),
                4: cred_protect,
                5: os.urandom(32),  # hmac-secret CredRandom seed
            }
        )
        nonce = os.urandom(12)
        header = bytes([CRED_ID_VERSION])
        cred_id = header + nonce + self._wrap.encrypt(
            nonce, payload, header + rp_id_hash
        )
        return cred_id, private_key

    def lookup(self, rp_id_hash, cred_id):
        """Return the Credential for ``cred_id`` or None if it is not ours."""
        with self._lock:
            rec = self._records.get(b64e(cred_id))
            if rec is not None and rec.get("source") == "bitwarden":
                if not hmac.compare_digest(hashlib.sha256(rec["rp_id"].encode()).digest(), rp_id_hash):
                    return None
                return Credential(cred_id, rec["alg"], keys.load(rec["alg"], b64d(rec["private_key"])),
                                  True, 3, None, self._public_record(rec))
        if len(cred_id) < 1 + 12 + 16 or cred_id[0] != CRED_ID_VERSION:
            return None
        try:
            payload = cbor.decode(
                self._wrap.decrypt(
                    cred_id[1:13], cred_id[13:], cred_id[:1] + rp_id_hash
                )
            )
            alg, raw, resident = payload[1], payload[2], payload[3]
            cred_protect = payload.get(4, 1)
            hmac_seed = payload.get(5)
            private_key = keys.load(alg, raw)
        except (InvalidTag, cbor.CBORError, KeyError, TypeError, ValueError):
            return None
        record = None
        if resident:
            with self._lock:
                record = self._records.get(b64e(cred_id))
            if record is None:
                return None  # deleted passkey
        return Credential(
            cred_id, alg, private_key, resident, cred_protect, hmac_seed, record
        )

    # -- discoverable credentials ----------------------------------------

    def add_resident(self, cred_id, rp, user, alg, cred_protect):
        now = int(time.time())
        rec = {
            "id": b64e(cred_id),
            "rp_id": rp["id"],
            "rp_name": rp.get("name") or rp["id"],
            "user_id": b64e(user["id"]),
            "user_name": user.get("name") or "",
            "display_name": user.get("displayName") or "",
            "alg": alg,
            "cred_protect": cred_protect,
            "created": now,
            "last_used": None,
            "use_count": 0,
        }
        with self._lock:
            # A new credential for the same account replaces the old one.
            for key, old in list(self._records.items()):
                if (old.get("source", "local") == "local"
                        and old["rp_id"] == rec["rp_id"] and old["user_id"] == rec["user_id"]):
                    del self._records[key]
            self._records[rec["id"]] = rec
            self._save()
        return rec

    def residents_for(self, rp_id):
        with self._lock:
            recs = [self._public_record(r) for r in self._records.values() if r["rp_id"] == rp_id]
        # Most recently used/created first.
        recs.sort(key=lambda r: (r["last_used"] or 0, r["created"]), reverse=True)
        return recs

    def list(self):
        with self._lock:
            return [self._public_record(r) for r in self._records.values()]

    @staticmethod
    def _public_record(rec):
        """Project only known metadata, never external key material."""
        fields = (
            "id", "rp_id", "rp_name", "user_id", "user_name", "display_name",
            "alg", "cred_protect", "created", "last_used", "use_count", "source",
            "counter", "backup_eligible", "backup_state",
        )
        return {key: rec[key] for key in fields if key in rec}

    def import_credentials(self, credentials):
        """Commit a validated Bitwarden batch atomically, preserving local keys.

        The caller owns authorization. A conflicting ID aborts the whole batch;
        disk failures leave live records unchanged. A v1 ciphertext snapshot is
        retained before the first format upgrade, for an explicit downgrade.
        """
        with self._lock:
            records = dict(self._records)
            added = 0
            for cred in credentials:
                ident = b64e(cred.id)
                existing = records.get(ident)
                if existing is not None:
                    if (existing.get("source") != "bitwarden"
                            or existing["rp_id"] != cred.rp_id
                            or existing["user_id"] != b64e(cred.user_id)
                            or existing["alg"] != cred.alg
                            or not hmac.compare_digest(existing["private_key"], b64e(cred.private_key))):
                        raise ValueError("Credential ID conflict; no changes saved")
                    continue
                # A foreign ID must never shadow even a nonresident local ID.
                if self.lookup(hashlib.sha256(cred.rp_id.encode()).digest(), cred.id) is not None:
                    raise ValueError("Credential ID conflict; no changes saved")
                records[ident] = {
                    "id": ident, "rp_id": cred.rp_id, "rp_name": cred.rp_name,
                    "user_id": b64e(cred.user_id), "user_name": cred.user_name,
                    "display_name": cred.display_name, "alg": cred.alg,
                    "cred_protect": 3, "created": cred.created, "last_used": None,
                    "use_count": 0, "source": "bitwarden", "counter": 0,
                    "backup_eligible": True, "backup_state": True,
                    "private_key": b64e(cred.private_key),
                }
                added += 1
            if not added:
                return 0
            if self._version == 1 and os.path.exists(self.path):
                backup = self.path + ".pre-import"
                if not os.path.exists(backup):
                    with open(self.path, "rb") as source:
                        paths.atomic_write(backup, source.read())
            self._persist(records, 2)
            self._records, self._version = records, 2
            self._notify()
            return added

    def record(self, cred_id_b64):
        with self._lock:
            rec = self._records.get(cred_id_b64)
            return self._public_record(rec) if rec else None

    def update_user(self, cred_id_b64, name, display_name):
        with self._lock:
            rec = self._records.get(cred_id_b64)
            if rec is None:
                return False
            rec["user_name"] = name
            rec["display_name"] = display_name
            self._save()
            return True

    def delete(self, cred_id_b64):
        with self._lock:
            if cred_id_b64 not in self._records:
                return False
            records = dict(self._records)
            del records[cred_id_b64]
            self._persist(records, self._version)
            self._records = records
            self._notify()
            return True

    def mark_used(self, cred_id):
        with self._lock:
            rec = self._records.get(b64e(cred_id))
            if rec is not None:
                rec["last_used"] = int(time.time())
                rec["use_count"] = rec.get("use_count", 0) + 1
                self._save()

    def next_counter(self):
        with self._lock:
            self._counter += 1
            self._save()
            return self._counter

    def reset(self, new_master_key):
        """Forget every credential and switch to a new master key."""
        with self._lock:
            self._set_master(new_master_key)
            self._records = {}
            self._counter = 0
            self._save()
