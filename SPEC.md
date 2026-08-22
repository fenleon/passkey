# Passkey on the LP3 — product spec (LP3-only)

## Scope

The Passkey tool is developed **for the Light Phone 3 only**. Everything else is
explicitly out: no Credential Manager provider, no stock-Android variant, no
sync/export, no password storage, no other transports (USB-HID is vetoed —
needs root).

The product: *sign in to websites from the LP3, calmly.* The LP3 has no
browser, so passkeys are only ever **created or used through the hybrid flow**
— a desktop browser shows a QR, the tool scans it, the session signs.

## Current state (verified)

- caBLE v2 core, Keystore-bound authenticator, LightOS tool + merged companion
  (one APK, toolbox-launched). Real-Chrome interop passed on the LP3
  (register + login, live relay). `:cable:run` = 1179 asserts.
- **Manager shipped (2026-08-22, emulator-verified):** passkeys list screen
  (RP domain, user name, created/last-used dates), tap-to-delete with a
  confirm panel (Keystore key + metadata row), `createdAt`/`lastUsedAt`
  timestamps (legacy rows read as 0), and an account picker when a
  GetAssertion matches >1 credential for the RP.
- **How logins are stored** (`CredentialStore`): each registration = an EC
  P-256 keypair inside the Android Keystore (TEE, alias `passkey:<credId>`)
  + a non-secret metadata row in app-private `passkey_credentials.json`
  (credentialId, rpId, userName, userHandle, uvBound, signCount, createdAt,
  lastUsedAt). Keys never leave the Keystore. Assertion matches by
  rpId/allowList, signs through the Keystore, bumps signCount + lastUsedAt.
- **Enrollment gates mapped (2026-08-22, emulator probe):** a platform-signed
  probe holding `MANAGE_FINGERPRINT` calls the hidden API-34
  `enroll(byte[], CancellationSignal, int, EnrollmentCallback, int)` directly.
  The framework accepts it on a lockless device; the HAL rejects any non-
  Gatekeeper token (`onEnrollmentError(2, "Can't process fingerprint")`).
  Enrollment requires a credential to exist (to mint the HAT) — never a
  user-visible lock. (Probe build: `/tmp/enrollprobe`, APK `probe.enroll` on
  the emulator.)

## UV

**Blocker (the only one):** real Chrome forces `uv: required` for hybrid
regardless of the RP's preference (verified on the wire). UV needs Android's
secure-lock state — and the dependency chain is now mapped layer by layer
(testing: AOSP 34 emulator + real LP3):

- **Wizard gate (Settings UI) — tested:** on a lockless device the stock
  `FingerprintEnrollIntroduction` refuses to enroll: "Choose your backup
  screen lock method" (Pattern/PIN/Password, no skip). UI policy only.
- **Framework gate — tested absent:** a `MANAGE_FINGERPRINT` caller (platform-
  signed app) invokes the hidden `enroll()` on a lockless device and the
  service accepts it — no `isDeviceSecure` check. The lock requirement is the
  wizard's, not the framework's.
- **Hardware gate — tested present:** the HAL rejects any token that is not a
  Gatekeeper-minted hardware auth token (`onEnrollmentError(2, "Can't process
  fingerprint")`). A HAT only comes from a successful credential (or existing
  biometric) verification, so on a credential-less device **no HAT can ever be
  minted** — enrollment is impossible at the hardware level for any caller.
  (Same class of gate as probe 3's on-device keygen failure: "At least one
  biometric must be enrolled".)

**Consequence:** the credential must *exist* — it never has to be user-visible.
The Light-side fix is therefore: **LightOS provisions a hidden device
credential programmatically** (`setLockCredential` → verify → HAT → enroll →
suppress keyguard) **and keeps the AOSP keyguard off its own wake flow**. The
keyguard suppression is the genuinely hard part, and it is Light's alone: no
third-party API can suppress it (`requestDismissKeyguard` prompts for auth and
is per-app; `FLAG_SHOW_WHEN_LOCKED` only covers our own window; `wm
dismiss-keyguard` is shell-only and non-persistent; system_server drives the
keyguard from the credential state itself — verified on the LP3: PIN set →
tool button shows "Device locked").

**Fingerprint vs PIN — no dodge:** enrollment mandates the backing credential
and the HAT gate enforces it at the hardware layer, so fingerprint carries the
same keyguard dependency as PIN. No supported-API path to fingerprint without a
lock. (On the LP3: fingerprint wizard reachable via adb and runs with a PIN;
no lock → Keystore UV keygen fails, probe 3. Not yet tested: a completed
fingerprint ceremony on-device — it necessarily inherits the PIN's keyguard
breakage.)

**Until Light ships it:** keep the no-UV path working (uv=discouraged RPs, our
own clients). The tool now shows an honest **"UV unavailable — no secure lock
on this device"** status instead of the raw keygen failure (2026-08-22:
`CredentialStore.createCredential` and the GA gate check `isDeviceSecure` and
raise `UvUnavailableException`; the session maps it to that status line and
the outcome heading). When Light ships the lock, nothing here changes: the UV
gate already works through the platform prompt (PIN or fingerprint). Re-verify
the real-Chrome ceremony with a uv=true RP.

## The manager (the built-in part)

**Shipped + emulator-verified 2026-08-22** (the ceremony was already proven):

1. **Passkeys panel on the main screen** — the tool's top bar carries the
   app heading ("Passkey"); the idle state shows the list (user name, site in
   brackets — no dates in the list), with SCAN in the bottom bar. Tapping a
   passkey opens its **detail panel**: the top bar carries the account name,
   the body repeats the name, the site, the created date, and the last-used
   date (shown only once stored). A finished session's outcome screen keeps
   the top bar with a top-left back button that returns to the panel.
2. **Delete** — the detail panel's bottom-bar **REMOVE** → confirm panel →
   delete (Keystore key + metadata row). `CredentialStore.delete(id)`.
3. **Timestamps** — `createdAt` / `lastUsedAt` in the `Credential` metadata
   (JSON array schema; old rows without the fields read as 0 and re-save with
   them — no dates shown for legacy rows).
4. **Account picker** — when a GetAssertion matches >1 credential for the RP
   (no allowList), the server pauses the ceremony, the session state becomes
   `"pick"` with the candidate user names, the tool shows them, and
   `PickAccount(index)` resumes the sign. Cancel → CTAP_ERR_OPERATION_DENIED.
   (Fixing this path also fixed a latent bug: an absent GA allowList decoded
   as empty — now null = "all resident keys".)

## Non-goals (explicit)

- Credential Manager provider / unified sign-in integration (Firefox-Android
  path) — stock-Android play, not LP3.
- Passkey management beyond list+delete: no sync, export, backup, or
  multi-device recovery. Device-bound keys die with the device; recovery is
  the RP's job (standard WebAuthn).
- Password or OTP storage; any browser; any transport besides caBLE hybrid.

## Verification

- Existing: `:cable:run` (1179 asserts), DesktopClient ceremonies, real-Chrome
  interop on the LP3.
- Manager (2026-08-22, emulator): `CredentialCodec` unit tests (round-trip,
  legacy-row migration — pure JVM); end-to-end UI verification of list
  (rows + dates, legacy rows without), delete (5 → 4 rows, list reloads), and
  the account picker (multi-credential GA → picker shows all names → tap
  signs in with the picked key, 40 DesktopClient checks; CANCEL → denied).
- Final pass: `lightos-design` skill on the new screens (list, picker,
  confirm) — one flagged deviation (the list screen has no bottom bar: pure
  browse sub-screen, delete lives per-row).
