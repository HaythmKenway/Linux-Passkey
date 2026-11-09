"""Synthetic Bitwarden exports; no personal vault or credentials are used."""

import copy
import hashlib
import json
import os
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestedCredentialData, AuthenticationResponse, PublicKeyCredentialRpEntity,
)

from linux_passkey import keys, webauthn
from linux_passkey.bitwarden import ImportError, parse_export
from linux_passkey.ctap2 import Request, describe_record
from linux_passkey.store import CredentialStore, b64e


@pytest.fixture
def exported():
    key = ec.generate_private_key(ec.SECP256R1())
    ident = uuid.uuid4()
    entry = {
        "credentialId": str(ident), "keyType": "public-key",
        "keyAlgorithm": "ECDSA", "keyCurve": "P-256",
        "keyValue": b64e(key.private_bytes(serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())),
        "rpId": "example.com", "userHandle": b64e(b"test-user"),
        "userName": "alice", "userDisplayName": "Alice", "rpName": "Example",
        "counter": "0", "discoverable": "true", "creationDate": "2026-01-01T00:00:00.000Z",
    }
    data = {"encrypted": False, "items": [{"id": "synthetic-item", "type": 1,
            "login": {"fido2Credentials": [entry]}}]}
    return data, entry, key, ident.bytes


def batch(exported):
    return parse_export(json.dumps(exported[0]).encode())


def test_mapper_preserves_original_material(exported):
    result = batch(exported)
    assert not result.errors and len(result.credentials) == 1
    cred = result.credentials[0]
    assert cred.id == exported[3]
    assert keys.cose_public_key(cred.alg, keys.load(cred.alg, cred.private_key)) == keys.cose_public_key(-7, exported[2])
    assert cred.user_id == b"test-user"
    assert exported[1]["keyValue"] not in repr(result)


@pytest.mark.parametrize("field,value", [
    ("keyValue", "PRIVATE-INVALID"), ("rpId", "https://evil.com"),
    ("rpId", "com"), ("rpId", "example.com:443"), ("userHandle", ""),
    ("counter", "9"), ("counter", "nonsense"), ("discoverable", "false"),
    ("keyAlgorithm", "EdDSA"), ("credentialId", "not-an-id"),
    ("backupEligible", False), ("backupState", False),
])
def test_incompatible_item_is_rejected(exported, field, value):
    exported[1][field] = value
    result = batch(exported)
    assert not result.credentials and len(result.errors) == 1
    assert "PRIVATE-INVALID" not in str(result.errors)


def test_partial_import_and_raw_id(exported):
    raw = os.urandom(200)
    exported[1]["credentialId"] = "b64." + b64e(raw)
    bad = copy.deepcopy(exported[1])
    bad["keyValue"] = "bad"
    exported[0]["items"][0]["login"]["fido2Credentials"].append(bad)
    result = batch(exported)
    assert result.credentials[0].id == raw and len(result.errors) == 1


@pytest.mark.parametrize("data", [b'{}', b'{"encrypted":true,"items":[]}', b'[]',
                                  b'{"items":[],"items":[]}', b'not-json'])
def test_invalid_envelope(data):
    with pytest.raises(ImportError):
        parse_export(data)


def test_import_preserves_local_and_is_idempotent(store, master_key, exported):
    rp = hashlib.sha256(b"example.com").digest()
    local, _ = store.create(rp, -7, True)
    store.add_resident(local, {"id": "example.com"}, {"id": b"test-user"}, -7, 1)
    original = open(store.path, "rb").read()
    assert original[0] == 1
    assert store.import_credentials(batch(exported).credentials) == 1
    assert store.import_credentials(batch(exported).credentials) == 0
    assert len(store.list()) == 2 and store.lookup(rp, local)
    again = CredentialStore(master_key)
    assert again.lookup(rp, exported[3])
    assert not again.lookup(hashlib.sha256(b"evil.com").digest(), exported[3])
    assert open(store.path, "rb").read()[0] == 2
    assert all("private_key" not in r for r in again.list())
    assert all("private_key" not in describe_record(r) for r in again.list())
    assert exported[1]["keyValue"].encode() not in open(store.path, "rb").read()
    assert again.delete(b64e(exported[3]))
    assert not again.lookup(rp, exported[3]) and again.lookup(rp, local)


def test_import_disk_failure_rolls_back(store, exported, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("test disk failure")
    monkeypatch.setattr("linux_passkey.paths.atomic_write", fail)
    with pytest.raises(OSError):
        store.import_credentials(batch(exported).credentials)
    assert store.list() == []
    assert not os.path.exists(store.path)


def test_conflict_does_not_replace_key(store, exported):
    store.import_credentials(batch(exported).credentials)
    other_key = ec.generate_private_key(ec.SECP256R1())
    exported[1]["keyValue"] = b64e(other_key.private_bytes(serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    before = open(store.path, "rb").read()
    with pytest.raises(ValueError, match="conflict"):
        store.import_credentials(batch(exported).credentials)
    assert open(store.path, "rb").read() == before


def test_local_creation_does_not_delete_imported_copy(store, exported):
    store.import_credentials(batch(exported).credentials)
    rp = hashlib.sha256(b"example.com").digest()
    ident, _ = store.create(rp, -7, True)
    store.add_resident(ident, {"id": "example.com"}, {"id": b"test-user"}, -7, 1)
    assert store.lookup(rp, exported[3]) and store.lookup(rp, ident)


def test_imported_credential_authenticates_with_known_public_key(authenticator, store, exported, ui):
    # The RP's expected key exists BEFORE import. No local registration occurs.
    known = AttestedCredentialData.create(bytes(16), exported[3], keys.cose_public_key(-7, exported[2]))
    server = Fido2Server(PublicKeyCredentialRpEntity(id="example.com", name="Example"))
    store.import_credentials(batch(exported).credentials)
    for _ in range(2):
        options, state = server.authenticate_begin([known], user_verification="required")
        response = AuthenticationResponse.from_dict(webauthn.get(authenticator,
            "https://example.com", json.loads(json.dumps(dict(options.public_key))), Request()))
        server.authenticate_complete(state, [known], response)
        assert response.raw_id == exported[3]
        auth_data = response.response.authenticator_data
        assert auth_data.counter == 0 and int(auth_data.flags) == 0x1D
        assert response.response.user_handle == b"test-user"
    assert ui.verifications == 2
    with pytest.raises(webauthn.WebAuthnError):
        webauthn.get(authenticator, "https://evil.com", {"rpId": "example.com", "challenge": "eA"}, Request())


def test_sealed_transport_rejects_mutation(exported):
    from linux_passkey.bitwarden import create_import_fd, read_import_fd

    data = json.dumps(exported[0]).encode()
    fd = create_import_fd(data)
    try:
        assert read_import_fd(fd) == data
        with pytest.raises(OSError):
            os.write(fd, b"tamper")
    finally:
        os.close(fd)


def test_unsealed_transport_is_rejected(tmp_path):
    from linux_passkey.bitwarden import ImportError, read_import_fd

    fd = os.open(tmp_path / "untrusted", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        with pytest.raises(ImportError):
            read_import_fd(fd)
    finally:
        os.close(fd)


def test_failed_batch_preserves_existing_file(store, exported, monkeypatch):
    rp = hashlib.sha256(b"example.com").digest()
    local, _ = store.create(rp, -7, True)
    store.add_resident(local, {"id": "example.com"}, {"id": b"old"}, -7, 1)
    original = open(store.path, "rb").read()
    write = __import__("linux_passkey.paths", fromlist=["atomic_write"]).atomic_write

    def fail_commit(path, data, *args, **kwargs):
        if path == store.path:
            raise OSError("test disk failure")
        return write(path, data, *args, **kwargs)

    monkeypatch.setattr("linux_passkey.paths.atomic_write", fail_commit)
    with pytest.raises(OSError):
        store.import_credentials(batch(exported).credentials)
    assert open(store.path, "rb").read() == original
    assert len(store.list()) == 1 and store.lookup(rp, local)
    assert open(store.path + ".pre-import", "rb").read() == original


def test_imported_credential_works_over_ctaphid(hid_device, store, exported):
    from fido2.client import DefaultClientDataCollector, Fido2Client

    known = AttestedCredentialData.create(bytes(16), exported[3], keys.cose_public_key(-7, exported[2]))
    store.import_credentials(batch(exported).credentials)
    server = Fido2Server(PublicKeyCredentialRpEntity(id="example.com", name="Example"))
    options, state = server.authenticate_begin([known], user_verification="required")
    client = Fido2Client(hid_device, DefaultClientDataCollector("https://example.com"))
    response = client.get_assertion(options.public_key).get_response(0)
    server.authenticate_complete(state, [known], response)
    assert response.raw_id == exported[3]
    assert response.response.authenticator_data.counter == 0
    assert int(response.response.authenticator_data.flags) == 0x1D


def dbus_import(daemon, exported):
    from gi.repository import Gio, GLib
    from conftest import connect
    from linux_passkey import DBUS_INTERFACE, DBUS_NAME, DBUS_PATH
    from linux_passkey.bitwarden import create_import_fd

    fd = create_import_fd(json.dumps(exported[0]).encode())
    try:
        descriptors = Gio.UnixFDList.new()
        index = descriptors.append(fd)
        result, _ = connect().call_with_unix_fd_list_sync(
            DBUS_NAME, DBUS_PATH, DBUS_INTERFACE, "ImportBitwarden",
            GLib.Variant("(h)", (index,)), GLib.VariantType.new("(u)"),
            Gio.DBusCallFlags.NONE, 10000, descriptors, None)
        return result.unpack()[0]
    finally:
        os.close(fd)


def allow_import(daemon, monkeypatch):
    daemon.config.override("verification", "polkit")
    monkeypatch.setattr(daemon.keys, "_recorded_backend", lambda: "keyring")
    monkeypatch.setattr(daemon.keys._keyring_backend(), "available", lambda: True)
    monkeypatch.setattr(daemon.broker, "confirm", lambda *args: 0)
    monkeypatch.setattr(daemon.broker.verifier, "available", lambda: True)


def test_dbus_import_denied_without_keyring(daemon, exported):
    from gi.repository import GLib

    with pytest.raises(GLib.Error):
        dbus_import(daemon, exported)
    assert daemon.store.list() == []


def test_dbus_import_requires_verification(daemon, exported, monkeypatch):
    from gi.repository import GLib

    allow_import(daemon, monkeypatch)
    monkeypatch.setattr(daemon.broker.verifier, "verify", lambda cancel: False)
    with pytest.raises(GLib.Error):
        dbus_import(daemon, exported)
    assert daemon.store.list() == []


def test_dbus_import_authorized_and_public_projection(daemon, exported, monkeypatch, caplog):
    from conftest import call, connect

    allow_import(daemon, monkeypatch)
    verified = []
    monkeypatch.setattr(daemon.broker.verifier, "verify", lambda cancel: verified.append(True) or True)
    assert dbus_import(daemon, exported) == 1
    assert verified == [True]
    public = call(connect(), "ListCredentials")[0]
    assert public[0]["source"] == "bitwarden"
    assert "private_key" not in public[0]
    assert exported[1]["keyValue"] not in caplog.text
    assert b64e(keys.private_bytes(-7, exported[2])) not in repr(public)


def test_listener_error_does_not_report_committed_import_as_failed(store, exported, caplog):
    def fail():
        raise ValueError(exported[1]["keyValue"])

    store.add_listener(fail)
    assert store.import_credentials(batch(exported).credentials) == 1
    assert len(store.list()) == 1
    assert exported[1]["keyValue"] not in caplog.text


def test_large_id_is_preserved_over_platform_authentication(authenticator, store, exported):
    raw = os.urandom(512)
    exported[1]["credentialId"] = "b64." + b64e(raw)
    known = AttestedCredentialData.create(bytes(16), raw, keys.cose_public_key(-7, exported[2]))
    store.import_credentials(batch(exported).credentials)
    server = Fido2Server(PublicKeyCredentialRpEntity(id="example.com", name="Example"))
    options, state = server.authenticate_begin([known], user_verification="required")
    reply = webauthn.get(authenticator, "https://example.com",
                        json.loads(json.dumps(dict(options.public_key))), Request())
    assert reply["id"] == b64e(raw)
    server.authenticate_complete(state, [known], AuthenticationResponse.from_dict(reply))


def test_store_v1_snapshot_can_still_open(env, store, master_key, exported, tmp_path):
    rp = hashlib.sha256(b"example.com").digest()
    ident, _ = store.create(rp, -7, True)
    store.add_resident(ident, {"id": "example.com"}, {"id": b"old"}, -7, 1)
    store.import_credentials(batch(exported).credentials)
    old = tmp_path / "old-reader"
    old.mkdir()
    (old / "credentials.enc").write_bytes(open(store.path + ".pre-import", "rb").read())
    restored = CredentialStore(master_key, directory=str(old))
    assert restored._version == 1 and restored.lookup(rp, ident)
    assert len(restored.list()) == 1


def test_dbus_import_rejects_concurrent_jobs(daemon, exported, monkeypatch):
    import queue
    import threading
    from gi.repository import GLib

    allow_import(daemon, monkeypatch)
    monkeypatch.setattr(daemon.broker.verifier, "verify", lambda cancel: True)
    entered, release = threading.Event(), threading.Event()
    result = queue.Queue()

    def confirm(*args):
        entered.set()
        assert release.wait(5)
        return 0

    def first():
        try:
            result.put(dbus_import(daemon, exported))
        except Exception as e:
            result.put(e)

    monkeypatch.setattr(daemon.broker, "confirm", confirm)
    worker = threading.Thread(target=first)
    worker.start()
    try:
        assert entered.wait(5)
        with pytest.raises(GLib.Error, match="already running"):
            dbus_import(daemon, exported)
        assert daemon.store.list() == []
    finally:
        release.set()
        worker.join(5)
    assert result.get(timeout=1) == 1


def test_dbus_import_requires_explicit_consent(daemon, exported, monkeypatch):
    from gi.repository import GLib
    from linux_passkey.ctap2 import Denied

    allow_import(daemon, monkeypatch)
    verified = []

    def deny(*args):
        raise Denied()

    monkeypatch.setattr(daemon.broker, "confirm", deny)
    monkeypatch.setattr(daemon.broker.verifier, "verify", lambda cancel: verified.append(True) or True)
    with pytest.raises(GLib.Error, match="not authorized"):
        dbus_import(daemon, exported)
    assert daemon.store.list() == [] and verified == []


def test_dbus_import_does_not_accept_disabled_verification(daemon, exported, monkeypatch):
    from gi.repository import GLib

    allow_import(daemon, monkeypatch)
    daemon.config.override("verification", "none")
    with pytest.raises(GLib.Error, match="requires"):
        dbus_import(daemon, exported)
    assert daemon.store.list() == []


def test_graphical_client_uses_sealed_async_transport(daemon, exported, monkeypatch):
    import queue
    from linux_passkey.app.client import DaemonClient

    allow_import(daemon, monkeypatch)
    monkeypatch.setattr(daemon.broker.verifier, "verify", lambda cancel: True)
    results = queue.Queue()
    client = DaemonClient()
    client.import_bitwarden(json.dumps(exported[0]).encode(), lambda value, error: results.put((value, error)))
    value, error = results.get(timeout=5)
    assert error is None and value == (1,)


def test_cancelled_authorization_does_not_commit(daemon, exported, monkeypatch):
    from gi.repository import GLib

    allow_import(daemon, monkeypatch)

    def cancel(request_cancel):
        request_cancel.set()
        return True

    monkeypatch.setattr(daemon.broker.verifier, "verify", cancel)
    with pytest.raises(GLib.Error, match="not authorized"):
        dbus_import(daemon, exported)
    assert daemon.store.list() == []
