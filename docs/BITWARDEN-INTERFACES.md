# Bitwarden interfaces: feasibility of importing real passkeys

Phase 1 research on 2026-11-09. Only public documentation and official source code were examined; no user vault, account, or credential was accessed. No implementation or authenticated test was performed during this research. **Confirmed** means explicit documentation or behavior verifiable in the pinned code; **inference** is an integration conclusion; **unknown** requires further validation.

## Conclusion

**Confirmed:** JSON exports and item responses from the official CLI carry actual private material. `login.fido2Credentials[].keyValue` is not merely metadata: the client imports it as a PKCS#8 private key. A Linux import is therefore technically plausible without inventing an endpoint or OAuth flow. **Inference:** the initial path with the fewest dependencies is importing JSON explicitly exported by the user; a later integration could run the official CLI with an unlocked session. This does not establish compatibility with the local authenticator or provide ready-made bidirectional synchronization.

## Pinned sources and reproducible evidence

The `bitwarden/clients` code was examined at commit [`15b835e1efc9e0903cd52f901f57cbae197a403f`](https://github.com/bitwarden/clients/tree/15b835e1efc9e0903cd52f901f57cbae197a403f), obtained from public HEAD. The `bitwarden/sdk-internal` code was examined at commit [`839c6ca06110a7c1fde14fda086dcac096a8d675`](https://github.com/bitwarden/sdk-internal/tree/839c6ca06110a7c1fde14fda086dcac096a8d675). HEAD is not a promise about a distributed release: the integration must pin and verify a published CLI version before claiming supported compatibility.

| Evidence | Pinned official source |
| --- | --- |
| CLI lists decrypted objects and serializes `CipherResponse` | [`apps/cli/src/commands/list.command.ts`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/apps/cli/src/commands/list.command.ts) |
| Item response constructs `LoginResponse` | [`apps/cli/src/vault/models/cipher.response.ts`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/apps/cli/src/vault/models/cipher.response.ts) |
| `LoginResponse` inherits `LoginExport`; viewing restrictions redact password/TOTP | [`apps/cli/src/models/response/login.response.ts`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/apps/cli/src/models/response/login.response.ts) |
| `LoginExport` copies the passkey array | [`libs/common/src/models/export/login.export.ts`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/libs/common/src/models/export/login.export.ts) |
| Serialization includes `keyValue` and the other fields below | [`libs/common/src/models/export/fido2-credential.export.ts`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/libs/common/src/models/export/fido2-credential.export.ts) |
| Individual JSON constructs `CipherWithIdExport`; removes the item key, preserves login | [`individual-vault-export.service.ts`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/libs/tools/export-vault-core/src/services/individual-vault-export.service.ts) and [`cipher.export.ts`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/libs/common/src/models/export/cipher.export.ts) |

### Actual format

**Confirmed in code:** both the JSON exporter and the `bw list items` response chain preserve `keyValue`. The envelope differs: an export contains `items[]`, while listing returns an array of items. Removing `CipherResponse.key` protects the item's encryption key; it does not remove the nested passkey private key.

Fields in `fido2Credentials[]`: `credentialId`, `keyType`, `keyAlgorithm`, `keyCurve`, `keyValue`, `rpId`, `userHandle`, `userName`, `counter`, `rpName`, `userDisplayName`, `discoverable`, `creationDate`. `counter` and `discoverable` are **strings in the export format**, although the client's view uses a numeric counter and boolean discoverability. Optional fields may be absent. The parser must not turn a missing key into a usable credential.

**Confirmed:** [`createKeyView` and `getPrivateKeyFromFido2Credential`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/libs/common/src/platform/services/fido2/fido2-authenticator.service.ts) export/import `pkcs8`; they create an ECDSA P-256 key with an initial counter of zero. [`Fido2Utils.arrayToString`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/libs/common/src/platform/services/fido2/fido2-utils.ts) encodes bytes as base64url **without padding**. In this path, `keyValue` is therefore base64url-encoded PKCS#8 DER, not PEM, JWK, COSE, or a public key. `userHandle` also represents base64url-encoded bytes. Other algorithms/formats have not been verified and must be explicitly rejected until supported.

**Confirmed:** [`parseCredentialId`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/libs/common/src/platform/services/fido2/credential-id-utils.ts) accepts a UUID converted to bytes or the `b64.` prefix followed by base64url. Those bytes are the identifier known to the RP; using the UUID's UTF-8 characters or generating another ID breaks the credential.

**Unknown:** the output of a specific published CLI version with a test vault. `bw login`, `bw list`, and `bw export` were not executed. The confirmation above is static analysis, not an end-to-end authentication demonstration.

## Interfaces and limitations

| Interface | Result for native Linux |
| --- | --- |
| Official JSON export | **Confirmed:** contains passkeys; viable as manual input. CSV loses passkey material. |
| Password Manager CLI | **Confirmed:** available on Linux; `login`, `unlock`, `sync`, `list items`, and `export` are documented interfaces. **Inference:** it could serve as a helper process to retrieve authorized items. |
| Vault Management API | **Confirmed:** local HTTP interface provided by the CLI through `bw serve`, not a public remote OAuth service for user vaults. Adds an HTTP surface; not required for file import or CLI execution. |
| Public API | **Confirmed:** manages organizational resources; does not provide individual vault item management. |
| Password Manager SDK | Rust code and internal bindings exist; **not a stable or supported public SDK**. Not the initial choice for Python/Linux integration. |
| CXP/CXF | CXP is an exchange protocol; CXF is a format. Bitwarden documents an app-to-app flow on iOS 26+ and Android 10+. No official CXP exchange interface for Linux desktop was located. |

Official sources: [CLI](https://bitwarden.com/help/cli/), [Password Manager APIs](https://bitwarden.com/help/bitwarden-apis/), [Public API](https://bitwarden.com/help/public-api/), [Export Vault Data](https://bitwarden.com/help/export-your-data/), [SDK API docs](https://sdk-api-docs.bitwarden.com/).

The requested [Vault Management API](https://bitwarden.com/help/vault-management-api/) URL returned navigation content without a technical description during this research. The official **Password Manager APIs** page and the CLI's `serve` section confirm its local nature. This does not justify inferring cloud endpoints or a third-party OAuth flow.

### CLI export versus graphical clients

**Confirmed in the pinned code:** [`EXPORT_FORMATS`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/libs/tools/export-vault-core/src/services/vault-export.service.abstraction.ts) supports `csv`, `json`, `encrypted_json`, and `zip`; [`ExportCommand`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/apps/cli/src/tools/export.command.ts) defaults to CSV. Passing `--password` with the JSON format selects encrypted export in this code. Do not copy a documentation example containing a password and expect plaintext JSON.

**Confirmed in the current documentation:** web, extension, and desktop clients offer JSON, CSV, encrypted JSON, and ZIP; ZIP is for individual vault data. Mobile supports file export and CXP transfer on the versions listed above. Individual exports exclude organizational data; organizational exports depend on roles/permissions. Policies may prevent export. Do not assume capabilities in HEAD exist in older installed versions.

Account-restricted encrypted exports are not independent interchange files: they depend on the original account/key. The password-protected option supports migration between Bitwarden accounts, but an external importer would need to implement and verify its decryption. **Inference:** initially accepting only unencrypted JSON avoids promising unsupported functionality; the file still requires protected handling during the transfer.

### Login, MFA, and sessions

**Confirmed in the [official CLI documentation](https://bitwarden.com/help/cli/):** interactive email/password authentication requests MFA where applicable; listed methods include authenticator, email, and YubiKey. Personal API key login and organizational SSO login through the browser are available. FIDO2/Duo do not have the same interactive CLI support; the documentation points to personal API keys as an alternative. An API key does not replace the master password for decrypting data. Accounts relying exclusively on trusted devices may be unable to access data through the CLI.

`bw unlock` generates the session used to decrypt the vault. `BW_SESSION` is a local decryption secret, **not an OAuth token scoped to reading passkeys**; `bw lock`/`logout` invalidate the active session. `bw sync` updates the cache; it does not automatically synchronize a third-party store. No official flow was found for a third-party application to register a client ID, request passkey consent, and obtain limited vault access.

This invalidation is the operational guarantee described in the documentation, **not cryptographic revocation of every secret already copied**. [`LockCommand`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/apps/cli/src/auth/commands/lock.command.ts) calls the lock service and clears its own process's variable; [`LockService`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/libs/unlock/src/lock.service.ts) clears local keys/cache/state. A subprocess cannot erase variables in its parent shell or keys/passkeys already imported by another program. [`NodeEnvSecureStorageService`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/apps/cli/src/platform/services/node-env-secure-storage.service.ts) uses the bytes of `BW_SESSION` to protect/unprotect local storage. Replay of an earlier session after locking was not verified in this phase; do not promise global revocation or rely solely on clearing a variable.

**Requirement blocker:** [`status`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/apps/cli/src/commands/status.command.ts) queries CLI state and may attempt auto-unlock; this does not establish that the official desktop app is unlocked. HEAD includes [`unlock` through desktop biometrics](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/apps/cli/src/key-management/commands/unlock.command.ts), but no stable public subscription to lock events that revokes an external copy was demonstrated. Requiring the Linux copy to stop signing when the Bitwarden desktop app locks needs an additional verifiable mechanism; polling `bw status` alone does not meet that requirement. Persistent import creates an independent copy.

**Requirement blocker: tokens in JSON.** The CLI cannot automatically be considered compliant with “no authentication credentials in plaintext JSON/YAML.” [`CliPlatformUtilsService.supportsSecureStorage()`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/apps/cli/src/platform/services/cli-platform-utils.service.ts) returns false; [`ServiceContainer`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/apps/cli/src/service-container/service-container.ts) passes that value to `TokenService` and uses Lowdb. [`TokenService.determineStorageLocation`, `_setAccessToken`, `setRefreshToken`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/libs/common/src/auth/services/token.service.ts) choose disk when secure storage is unavailable, except for logout configured with a finite timeout; the disk path writes access/refresh tokens without encryption. [`LowdbStorageService`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/apps/cli/src/platform/services/lowdb-storage.service.ts) persists to `data.json`, created with mode 0600. Mode 0600 is not encryption. An in-memory timeout is not assumed to solve session reuse between subprocesses; that behavior would need proof. A future alternative could use ephemeral state in protected memory, but it has not been implemented or validated. Manual import avoids Linux Passkey managing Bitwarden login/tokens, although the exported JSON still temporarily contains plaintext private keys.

**Inference:** a CLI helper should have its own state directory, an in-memory session, shell-free execution, and no logging of stdout/secrets; it must not reuse the Bitwarden application's state or send secrets in visible arguments. This helper was not implemented in this phase.

## BE/BS, counters, and identity preservation

**Confirmed:** the examined client generates authenticator data with BE=true and BS=true; a comment explains that its credentials are synchronized. BE/BS fields are absent from the JSON export object analyzed. The client keeps a zero counter at zero, and increments/saves it on the server when the credential's counter is greater than zero. Source: [`fido2-authenticator.service.ts`](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/libs/common/src/platform/services/fido2/fido2-authenticator.service.ts). The [export documentation](https://bitwarden.com/help/export-your-data/) warns about counters from before 2024.3.1 and the risk of old backups being rejected.

**Inference:** copying a key without preserving its ID, RP ID, user handle, and counter/backup semantics is insufficient. Do not use a global counter or silently turn older positive-counter credentials into zero-counter credentials. Preserve zero for modern credentials; initially reject older ones or explicitly design coordination. Positive-counter copies used by two authenticators can diverge. An external copy's BS must not be inferred merely from the existence of an imported file: backup semantics and flag continuity need a decision and testing with the RP. UV/UP must also reflect actual verification/presence, not merely Bitwarden's flags.

**Additionally confirmed:** the [internal CXF converter](https://github.com/bitwarden/sdk-internal/blob/839c6ca06110a7c1fde14fda086dcac096a8d675/crates/bitwarden-exporters/src/cxf/login.rs) rejects positive counters and requires a user handle; the existence of this code does not establish Linux CXP transport support.

## SDK, languages, and licensing

The [pinned README](https://github.com/bitwarden/sdk-internal/blob/839c6ca06110a7c1fde14fda086dcac096a8d675/README.md) describes the Password Manager SDK as internal, unsupported for public use, and exposing an unstable interface. The core is Rust; WASM serves web clients, and UniFFI serves Swift/Kotlin mobile applications. Public Rust documentation is not an external Python SDK contract; the public Secrets Manager SDK is a separate product and does not thereby provide access to Password Manager passkeys.

The [SDK LICENSE](https://github.com/bitwarden/sdk-internal/blob/839c6ca06110a7c1fde14fda086dcac096a8d675/LICENSE) permits the GPLv3 alternative for eligible code, while `bitwarden_license` areas are available only under their own license. The [SDK v2 license](https://github.com/bitwarden/sdk-internal/blob/839c6ca06110a7c1fde14fda086dcac096a8d675/LICENSE_SDK.txt), §§3.1–3.5, restricts third-party use and distribution while preserving the rights of OSS portions under their licenses. Do not assume the entire SDK is permissively licensed or redistributable. The [Clients LICENSE](https://github.com/bitwarden/clients/blob/15b835e1efc9e0903cd52f901f57cbae197a403f/LICENSE.txt) also distinguishes GPLv3 code from the commercial directory. **Inference:** preferring the CLI process interface or a file format reduces technical coupling; packaging and redistribution still require checking the licenses of the selected artifacts.

## Blockers and remaining proof before implementation

1. Pin a published CLI version and verify serialization with an authorized disposable account and credentials; do not use a real personal vault for investigation.
2. Verify that local storage/authentication preserves external ID bytes, the P-256 private key, RP, user handle, per-credential counter, and BE/BS/UV policy; prove signatures against the public key registered with the RP.
3. Define idempotent import by credential identity, without silently replacing another passkey for the same user/RP; persistence must survive failure without partial success.
4. Separate import from synchronization: conflicts, deletion, multiple copies, and concurrent use have no ready-made solution in the examined formats. Do not initially promise bidirectionality.
5. Validate performance, size limits, strict parsing, permissions, and secret disposal; do not generate vault files in logs, tests, or the repository.

**Verdict:** there is sufficient evidence to propose real JSON/CLI import in Phase 2. Public OAuth integration limited to passkeys, a stable public Password Manager SDK, and Linux CXP transfer remain unconfirmed and must not be presented as delivered capabilities.
