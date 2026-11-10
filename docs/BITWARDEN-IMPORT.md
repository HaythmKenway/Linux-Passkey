# Importing Bitwarden passkeys

## Integration status

This first increment implements **graphical import of local copies** from an
official JSON export. It does not implement login, a connected account,
persistent synchronization history, or scheduling. Linux Passkey does not
access Bitwarden in this version, so there is no Bitwarden master password,
token, or session to store. Installing `bw` is not required.

The blockers for connected synchronization remain documented in the
[official interface research](BITWARDEN-INTERFACES.md): the CLI can write
unencrypted tokens to JSON, and its state does not establish whether the
desktop app is locked. These issues have not been bypassed with private
endpoints or presented as resolved.

## Installation on CachyOS/Arch with Niri

Dependencies already used by the project:

```sh
sudo pacman -S --needed python python-gobject python-cryptography gtk4 libadwaita libsecret publicsuffix-list polkit make gettext
```

A Secret Service provider, such as GNOME Keyring, must be unlocked in the
session, and Niri must have a working polkit agent. The GNOME extension is not
required. If existing credentials use the file backend, import will be
unavailable: this version does not migrate the master key or switch its backend.

Install the application and daemon **from the same revision**, then reload the unit:

```sh
sudo make install-app install-locale
systemctl --user daemon-reload
systemctl --user restart linux-passkey.service
linux-passkey
```

A new UI connected to an old daemon cannot call `ImportBitwarden`. Close and
reopen the application after installation. Installing or updating the program
does not import credentials automatically.

## How to import

1. In the official Bitwarden application, export your individual vault data as
   **unencrypted JSON**. CSV does not carry passkey private keys.
2. Open Linux Passkey and choose **Settings → Integrations → Bitwarden**.
3. Select **Choose JSON…** and choose the local file. Reading and validation
   run outside the UI thread, with limits of 16 MiB and 1000 passkeys.
4. Review the sites/accounts in the preview and the reasons for rejected
   entries. The preview displays up to 20 entries per category and reports
   the total batch size.
5. Confirm **Import Compatible Passkeys**, approve the import prompt, and
   verify your identity through the polkit agent. Denying or cancelling does
   not import the batch. Biometrics depend on your PAM/fprintd configuration.
6. Copies appear in the list with an import icon and **Bitwarden (local copy)**
   as their source in the details. The operation result remains on the
   integrations page while that window is open.

The exported JSON contains private keys and may contain passwords and other
vault data. The program does not create another copy of that file on disk.
Remove the export after use according to your storage policy; do not submit
it to issues, logs, tests, or this repository. The application does not promise
to retroactively erase copies, backups, or blocks already written by the exporter.

## Compatibility and validation

- Base64url-encoded PKCS#8 DER private key, ES256/ECDSA P-256.
- UUID or `b64.` credential ID in Bitwarden's representation, preserved as the
  original bytes, up to 1023 bytes. A replacement ID is never generated.
- Valid RP ID that is not a public suffix, a 1–64 byte user handle, a timestamp
  with a timezone, bounded metadata, and a discoverable credential.
- Only signature counter `"0"` is supported. Older credentials with a positive
  counter are rejected to avoid divergence between authenticators.
- The Bitwarden producer verified in the research uses BE=BS=true; copies
  preserve that meaning. Explicitly contradictory flags are rejected. This is
  not a generic importer for files from other vendors.
- EdDSA/Ed25519, encrypted JSON, CXF/CXP, ZIP, and positive counters are not
  supported by this importer. Local EdDSA passkeys continue to work.
- The original PRF/hmac-secret seed is not exported in this format; PRF
  continuity is not claimed for imported copies.

Import enforces credProtect=3: using the copy requires local verification.
CTAP requests without UV may not find these credentials; the client must
request UV. Origin and RP checks still apply to every WebAuthn operation.
Linux password/biometric verification does not unlock Bitwarden.

## Duplicates, conflicts, and deletion

Reimporting the same identity, RP, handle, and key does not create another copy
or overwrite local metadata/statistics. An existing ID with a different key,
RP, handle, or source aborts the entire batch; the message contains no keys.
Conflicts are never resolved by automatic destructive changes.

Entries with incompatible formats are rejected individually and shown in the
preview. The valid subset is written only after confirmation, in one transaction.
Failures before the atomic file replacement preserve the previous state in
memory and on disk. A failure after commit can be handled by reimporting the
same batch, since the operation is idempotent.

Existing passkeys are preserved, including those for the same RP and user.
Use the list's delete button to remove an imported copy. This does not delete
the original in Bitwarden or revoke its registration with the website.
A later manual import can recreate a deleted copy; remote reconciliation,
tombstones, and removal detection are not implemented yet.

There is no connection to disconnect in this version. Locking Bitwarden,
removing a remote item, or revoking a session **does not revoke copies already
imported**. These are syncable passkeys copied into encrypted local storage,
not private keys bound to the laptop's hardware.

## Storage, authorization, and migration

The same `~/.local/share/linux-passkey/credentials.enc` file stores external
records and normalized private keys, inside the existing AES-256-GCM envelope
and under the same master key in the keyring. There is no separate key database.
Public metadata uses an explicit projection; keys do not appear in
`ListCredentials`, status, UI details, or import responses.

IPC uses a sealed, immutable memfd sent as a Unix file descriptor. Keys and
vault contents are not shell arguments or strings in D-Bus calls. The daemon
reads a bounded batch, requires its own consent prompt and polkit verification,
rejects concurrent jobs, and watches for the sender disconnecting. An
authorization boolean never comes from the client. Cryptographic errors are
sanitized; exports, keys, and sessions are not logged.

Before the first import, the reader accepts the existing v1 format. The first
commit of external data writes format **v2**, keeping local IDs unchanged and
saving the previous v1 ciphertext as `credentials.enc.pre-import` (0600), if a
file already existed. No snapshot is created if the vault was empty and had
no file yet. This does not rotate the master key.

The original program cannot read v2 and fails closed. Do not run both versions
as writers to the same vault. To downgrade, stop the daemon and preserve a copy
of the current v2 file before any restoration. Restoring the snapshot removes
later changes from the restored view and works only if the master key has not
been rotated; this requires an explicit decision. The program does not downgrade
or restore automatically. Previous local records remain usable in the new
program without migrating their IDs.

The store lock is per process, and the D-Bus name limits the daemon to one
instance per bus. Writers on separate buses sharing the same directory are
not supported. Writing uses the existing atomic helper, without claiming a
new power-loss guarantee beyond that helper's persistence behavior.

Secret Service and polkit do not fully isolate hostile processes running under
the same UID, root, or a compromised desktop. Keys must exist in memory during
use; Python does not guarantee zeroization of every copy. Locking the keyring
after opening the store does not remove keys already loaded by the daemon.

## Validation and security review

Tests use only credentials generated for testing. The `Fido2Server` receives
the known public key **before** import and verifies assertions through both the
platform and CTAPHID paths: original ID, signature, RP, user handle, UP/UV,
BE/BS, and a zero counter. This demonstrates use of the imported key rather
than a newly generated replacement credential. No test against a disposable
Bitwarden account or a real website has been performed yet; universal
interoperability is not claimed.

Tests also cover parsing and rejection, partial imports, duplicates, conflicts,
coexistence with local passkeys, store reopening, the v1 snapshot, rollback on
disk failure, immutable descriptors, public projections, absence of keys in
logs, denied confirmation, denied/disabled verification, cancellation,
concurrency, and the UI's asynchronous client.

Security review for this increment:

| Area | Result |
|---|---|
| Authorization | Daemon-side checks, explicit approval, mandatory keyring and polkit, cancellation before commit |
| Cryptography | Reuses AES-GCM/HKDF and `cryptography` parsing; no new algorithm or backend |
| Exposure | No CLI, master password, or tokens; sealed FD, explicit public projection, sanitized exceptions |
| Integrity | Validated batch, conflicts abort the transaction, encrypted snapshot, memory replaced after persistence |
| Injection | No shell, endpoints, or execution of imported data; bounded JSON and duplicate fields rejected |
| UI | Worker-thread reading, escaped labels in the list, preview without markup or private material |
| Network/SSRF | No remote access in this increment; daemon sandbox retained |
| Dependencies | No runtime dependency added; no claim of a complete CVE audit of existing dependencies |

Run `make check` and `make lint` in the development environment. The GTK startup
test on Niri opens only the page, without authorizing import or using the user's
credentials. The automated polkit test uses a test verifier; it does not prove
that a physical biometric reader works.

Results of this review: `make check` passed with **168 tests** (43 GLib/PyGObject
deprecation warnings); `make lint` passed, with the existing warning about the
external polkit DTD reference, validated using the local DTD. The GTK page was
initialized in the Niri session without importing data. No runtime dependency
was added.
