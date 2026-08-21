# passkey — LP3 passkey authenticator (LightOS tool: Truck 1 caBLE hybrid, interop gate next)

Transport-independent WebAuthn authenticator core for the Light Phone 3,
built in Kotlin. **Truck 1 (caBLE hybrid) chosen 2026-08-21** — the phase-0
probes vetoed Truck 2 (USB-HID) on the real LP3: it needs root (locked
bootloader, no su). Truck 1's app-level gates passed (BLE advert, camera,
device-credential UV).

## Status / Plan / Blockers (2026-08-21)

**Status — done and verified:**

- caBLE v2 protocol core (`:cable`), tunnel transport, and the CTAP2
  MakeCredential/GetAssertion ceremony, converted into a **LightOS tool**
  (scanner UI + merged companion, one APK, toolbox-launched).
- CTAP response framing aligned with Chromium (`[0x00][cbor]` success
  replies — previously the command byte, which Chrome reads as an error).
- Verified: `:cable:run` (1166 asserts) · DesktopClient ceremonies on the
  emulator (40 checks, uv=false and uv=true) · **on the real LP3** (no-UV
  40 checks; UV 40 checks with a temporary lock — real BLE advert).

**Plan:**

1. **Real-Chrome interop gate — run it no-UV:** desktop Chrome + a
   uv=discouraged test RP (e.g. webauthn.io) + the LP3 tool (BLE advert, no
   lock needed) to prove the protocol + framing against real Chrome. Real
   passkeys (RP requires uv=true) stay blocked on the UV gap below.
2. **UV on the LP3** once Light ships a native lock/enrollment path.
3. Optional polish: a clear "UV unavailable — no secure lock on this device"
   tool status instead of the raw keygen failure; a slim release APK.

**Blockers:**

- **UV on the LP3** requires an Android secure lock (`isDeviceSecure`); any
  such credential (PIN or fingerprint — `android.settings.FINGERPRINT_ENROLL`
  works on this firmware) activates the AOSP keyguard, which breaks the
  LP3's zero-unlock wake flow (standby clock → tool button → toolbox).
  Pending a LightOS-native lock/enrollment path (Light's product decision).
- Real passkeys (RPs demanding uv=true) therefore can't sign in on the LP3
  yet — the no-UV path works for uv=discouraged RPs.

## Modules

- `:cable` (`com.lightphone.passkey.cable`) — the caBLE v2 (hybrid) protocol
  core, pure JVM, zero dependencies:
  - `Qr` — the `FIDO:/` + digits QR payload (CBOR map: desktop identity
    pubkey, secret, request type), the 7-byte→17-digit codec.
  - `Eid` — the 20-byte BLE advert (AES-256-ECB EID ‖ HMAC-SHA256 tag) and
    its components (nonce, routing ID, tunnel-server domain).
  - `Cable` — `derive` (HKDF-SHA256), the Noise KNpsk0/NKpsk0/NK handshake
    (initiator + responder), and the post-handshake `Crypter` (padded
    AES-GCM, BE sequence nonces).
  - `Ec` / `Hkdf` / `CableCbor` — P-256 point math + BoringSSL-compatible
    seed→key derivation, RFC 5869 HKDF, minimal CBOR.
  - `Ctap2` — the CTAP2 wire codec for the hybrid flow: `decodeMakeCredential`
    / `decodeGetAssertion` (rpId, clientDataHash, ES256 param list, exclude/
    allow credential ids, `uv` option defaulting to **true**), the MC/GA
    response encoders (`fmt`/`authData`/`attStmt`, credential+authData+
    signature+userHandle+count), an authData parser (rpIdHash ‖ flags ‖
    signCount ‖ attested credential data), and a COSE EC2 key decoder (x/y).
  - `TunnelServer` / `Ws` / `TunnelCheck` — the tunnel transport: domain
    decode (assigned + hashed, Chromium's `266 → cable.wufkweyy3uaxb.com`
    vector), `/cable/new` + `/cable/connect` URLs, and a live check
    (`./gradlew :cable:tunnelCheck`) that runs a full QR-flow session —
    phone opens a tunnel, gets its routing ID from the `X-caBLE-Routing-ID`
    header, desktop connects, KNpsk0 handshake + encrypted CTAP frames over
    the real relay (verified 2026-08-21 against cable.ua5v.com).
  - Transcribed from Chromium `device/fido/cable/` (v2_handshake.cc,
    noise.cc, v2_constants.h); `./gradlew :cable:run` runs the self-check
    (`CheckKt`, 1166 asserts: Chromium's fixed vectors — digits "16736865",
    the known compressed QR point, the hashed tunnel domain — plus NK/KN
    handshakes with wrong-key rejection, EID tamper/domain checks, the CTAP2
    codec round-trips, and a full desktop-QR → phone-advert → handshake →
    encrypted-CTAP round trip).
- `:core` (`com.lightphone.passkey.core`) — the authenticator:
  - `Cbor` — minimal CBOR encoder (RFC 8949; attestationObject, COSE keys).
  - `AuthData` / `Cose` — authenticator-data assembly + COSE ES256 EC2 key.
  - `CredentialStore` — EC P-256 keypairs in the **Android Keystore** (TEE),
    resident-key metadata in app-private JSON; keys never leave the Keystore.
  - `UvGate` — user verification via `BiometricPrompt`: fingerprint (strong)
    **or** device credential (lock PIN) — the platform-authenticator choice.
  - `PasskeyAuthenticator` — `register` / `assert` (WebAuthn JSON out) with
    `attestation: none`, plus the CTAP2 raw-piece variants `registerCtap` /
    `assertCtap` (inputs take the precomputed `clientDataHash`, outputs return
    `credentialId` / `authData` / `signature` / `userHandle` pieces;
    credential-excluded and no-credentials surface as `CtapError(status)` with
    the CTAP2 status byte). The UV gate is **injected** (a suspend lambda) —
    the loopback passed `UvGate.authenticate(activity, …)`, the tool's
    companion passes the `UvPrompt` bridge.
- `:app` — **the LightOS tool** (`com.lightphone.passkey`, single APK with
  `:server` merged in; launched from the toolbox). `PasskeyScreen`
  (`@InitialScreen` `LightScreen`): idle = "Scan a passkey QR from your
  computer to sign in." with a Scan bottom-bar button; the SDK's
  `LightQrCodeScanner` full-screen for the actual scan (CAMERA via the SDK
  permission flow); while a session runs it polls `GetSessionState` (~400 ms,
  stops when the session is terminal) and renders the status lines + an
  outcome title ("Passkey created" / "Signed in" / "Couldn't sign in").
  Debug auto-QR bottom-bar button (generates a desktop-style QR key via
  `:cable`'s `Qr.encode`, logs the key for DesktopClient) — the emulator
  verification path; remove for a release.
- `:server` (`com.lightphone.passkey.server`) — **the companion, an Android
  library merged into the tool APK** (single-module build, 2026-08-21; the
  tool binds to itself — `lighttool.toml` `serverPackage = com.lightphone.passkey`):
  - `ServerBootstrapProvider` (ContentProvider) wires `LightSdkServer` at app
    start: `RelaySdkServerSettings` (haptics from `com.lightos`), dev-cert
    check, `customServiceMethodResolver` → `PasskeyServiceMethods`,
    `onDeviceKeyEvent` → **all keys relayed** to `com.lightos` (passkey
    consumes no hardware keys — `PLATFORM-RELAY.md`), `PlatformRelay.bind`.
  - `SessionManager` owns the session: parses the scanned QR, runs
    `HybridSession`, and folds its log into a `StateFlow<SessionState>`
    (idle/running/done/error + capped lines + summary) the tool polls.
  - `HybridSession` (moved from the old `:app`) — the caBLE v2 phone side:
    OkHttp tunnel → `X-caBLE-Routing-ID` → EID advert (BLE best-effort, the
    emulator has none) → KNpsk0 handshake → pushed getInfo → CTAP loop
    dispatching `0x01` MC / `0x02` GA through the authenticator; success =
    `[0x00 status][cbor]` (standard CTAP2 — Chrome reads the first byte as
    the status), error = bare CTAP2 status byte.
  - `UvPrompt` + `UvActivity` — the UV bridge: the session's suspended gate
    launches `UvActivity` (a FragmentActivity — the tool runtime forbids
    BiometricPrompt, so UV lives here) which shows the BiometricPrompt
    (`UvGate.authenticate`, fingerprint or device credential) and reports
    back; the CryptoObject for UV-bound keys rides along in-process.
  - `PasskeyServiceMethods` — the additive methods over the binder:
    `StartPasskeySession(qrPayload)` / `StopSession()` / `GetSessionState()`.
- `:rp` — the local WebAuthn4J relying party (host-side, JDK HttpServer).

## Running the tool

```bash
cd light-phone/passkey
source ../tools/env.sh
../tools/build --dir passkey :app:assembleDebug
adb -s emulator-5554 install -r app/build/outputs/apk/debug/app-debug.apk
adb -s emulator-5554 shell am start -n com.lightphone.passkey/com.thelightphone.sdk.LightActivity
```

The tool is a single APK (tool + companion): install once, launch from the
toolbox. Bottom-bar buttons: CAMERA = scan the desktop's QR, ADD (debug) =
generate a desktop-style QR key for the JVM DesktopClient (logged to
logcat). During a session the status view shows the live lines; UV prompts
are the companion's own `UvActivity` (lock PIN on the emulator). The old
Phase-1 loopback harness (`MainActivity` buttons 1–5, the `:rp` round-trip)
was removed with the tool conversion — `:cable:run` + the DesktopClient
ceremony cover the core.

## Verification status (2026-08-21)

### Truck 1 — caBLE v2 CTAP2 ceremony vs `DesktopClient` (live relay)

| Path | MakeCredential | GetAssertion |
|------|----------------|--------------|
| no-UV | `MakeCredential OK` (40 checks) | `signature verified (counter=1)` |
| UV (lock PIN) | `MakeCredential OK` (40 checks) | `signature verified (counter=1)` |

Verified **through the converted tool on the emulator** (2026-08-21): the
tool's debug auto-QR button starts the session, the companion's `UvActivity`
shows the BiometricPrompt (lock PIN entered twice — MC then GA), and the
tool's status view lands on "Signed in". Same 40 checks as the pre-conversion
baseline. **Also verified on the real LP3** (same day): the no-UV ceremony
(real BLE advert broadcasting) and the UV ceremony (with a temporarily
adb-set lock PIN) both pass 40 checks on-device.

The DesktopClient's 40 checks cover: advert decrypt → routing/PSK, KNpsk0
handshake, pushed getInfo, getInfo round-trip, then the ceremony — MC reply
fmt `none` + empty attStmt, authData rpIdHash match, UP+AT flags (UV flag
matching the request), COSE key parse, GA credential id matching the
registered one, UP/UV flags, signCount increment, and the **ECDSA signature
over `authData ‖ clientDataHash`** verified with the registered key (JDK
`SHA256withECDSA`, DER). App side logs `MakeCredential OK` / `GetAssertion OK`
per ceremony; the store then holds the resident credential
(`uvBound` true/false, `signCount` 1).

## Notes / next

- UV-bound keys require a secure lock screen (`KeyguardManager.isDeviceSecure`);
  the LP3 currently has none configured — set one (Android layer) to unlock UV.
- No fingerprint-enrollment path exists on the LP3 yet; UV falls back to the
  lock PIN via `DEVICE_CREDENTIAL`. A "Set up fingerprint" button that fires
  `Settings.ACTION_FINGERPRINT_ENROLL` is a candidate tool feature (enrollment
  itself is a system-only flow — an app can only hand off to the wizard).
- **Next: the real-Chrome interop gate — run it no-UV.** The CTAP2 ceremony is
  proven against our own DesktopClient and on the real LP3 (both ceremonies,
  40 checks each). What still needs proving against real Chrome is the
  protocol itself, especially the fixed `[0x00]` status framing: desktop
  Chrome + a **uv=discouraged test RP** (e.g. webauthn.io) + the LP3 tool
  (real BLE advert, no lock needed). Real passkeys (RP requires uv=true) are
  **blocked on the LP3**: UV needs `isDeviceSecure`, and any Android secure
  credential (PIN *or* fingerprint) activates the AOSP keyguard, which
  intercepts the LP3's wake flow (tool button → "Device locked", stock
  Android wakeup over the standby clock) — incompatible with the device's
  zero-unlock design. `android.settings.FINGERPRINT_ENROLL` works on this
  firmware (the phase-0 probe's "no enrollment path" was wrong) but requires
  the backing credential and doesn't remove the keyguard. The fix is
  Light-side: a LightOS-native lock/enrollment path that registers a
  credential while suppressing the AOSP keyguard. (Full session details +
  theories: WORKLOG 2026-08-21.)
- The old base64url `FIDO:/tunnelId/eidKey/psk` QR format is **not** the
  current protocol — Chrome ships the digits-encoded CBOR map format that
  `:cable` implements.

## Truck 1 status (2026-08-21) — CTAP2 ceremony DONE

Verified ground truth from Chromium's `device/fido/cable/` — do not re-derive.

### Current state (all green)

- `:cable` — caBLE v2 core: `Qr`, `Eid`, `Cable` (derive/Noise/Crypter/
  handshake), `Tunnel`/`Ws`, `Ctap` (command + status constants), **`Ctap2`**
  (MC/GA codec + authData/COSE parsers), `Check` (1166 asserts,
  `./gradlew :cable:run`). Live checks: `tunnelCheck` (self-contained
  phone+desktop through cable.ua5v.com) and `desktopClient`
  (`--args="<advertHex> <tunnelIdHex> <qrKeyHex> [uv]"`, plays the browser
  against the app; run it via `java -cp "$(./gradlew -q :cable:classpath)"`
  `com.lightphone.passkey.cable.DesktopClientKt …` to skip gradle startup —
  the tunnel's ~30s lifetime doesn't leave room for it).
- `:app` — **the tool** (single APK with `:server` merged): `PasskeyScreen`
  (`@InitialScreen` `LightScreen`; SDK `LightQrCodeScanner` + debug auto-QR
  button; polls `GetSessionState` while a session runs) — see Modules above.
- `:server` — **the companion** (merged library, `serverPackage =
  com.lightphone.passkey`): `HybridSession` (OkHttp tunnel → `X-caBLE-Routing-
  ID` → EID advert (BLE best-effort, logged) → KNpsk0 handshake → pushed
  getInfo → CTAP loop dispatching `0x01` MC / `0x02` GA through
  `PasskeyAuthenticator.registerCtap`/`assertCtap`; success replies are
  `[0x00 status][cbor]` (standard CTAP2), errors a bare CTAP2 status byte;
  `uv` defaults to the request option, **true when absent** —
  platform-authenticator posture),
  `SessionManager` (state machine), `UvActivity`+`UvPrompt` (UV), the
  additive `PasskeyServiceMethods`, `ServerBootstrapProvider` + PlatformRelay.
  Verified end-to-end on the emulator vs `DesktopClient`: handshake, pushed
  getInfo, getInfo round-trip, and the full MC/GA ceremony — 40 checks, with
  and without UV (PIN into the companion's BiometricPrompt via `adb input`).
- `:core` — `PasskeyAuthenticator.register/assert` (WebAuthn JSON out) +
  **`registerCtap`/`assertCtap`** (raw pieces, `clientDataHash` in; the UV
  gate is an injected suspend lambda), `CtapModels` (`CtapError(status)` for
  credential-excluded 0x19 / no-creds 0x2e / operation-denied 0x2f),
  `CredentialStore` (Keystore EC P-256, resident metadata), `UvGate`
  (BiometricPrompt, device-credential/PIN fallback).

### Protocol facts (verified from Chromium — don't re-derive)

- QR = `FIDO:/` + 7-byte→17-digit encoding of CBOR `{0: compressed desktop
  P-256 pubkey, 1: 16B secret, 2: numDomains, 3: ts, 4: supportsLinking,
  5: requestType("ga"/"mc")}`. Desktop derives identity from a 32B seed;
  seed→key = `EC_KEY_derive_from_secret` (HKDF info "derive EC key P-256").
- `derive(secret, nonce, type)` = HKDF-SHA256(ikm=secret, salt=nonce, info=4B
  LE type); `EID_KEY=1` (64B), `TUNNEL_ID=2` (16B), `PSK=3` (32B).
- EID plaintext 16B = `[0x00][10B nonce][3B routing][2B BE domain]`; advert =
  AES-256-ECB(16B) ‖ HMAC-SHA256(hmacKey, ct)[0:4] (20B). Domains: 0 =
  cable.ua5v.com, 1 = cable.auth.com, ≥256 hashed.
- Tunnel: phone `wss://<dom>/cable/new/<hex tunnel_id>` (subprotocol
  `fido.cable`), routing ID in the **`X-caBLE-Routing-ID` handshake header**
  (6 hex chars); desktop `wss://<dom>/cable/connect/<hex routing>/<hex id>`.
- Handshake = Noise **KNpsk0** (QR flow): `ck=h=protocol name`, prologue
  `[0x01]`, MixHash(desktop identity pub), MixKeyAndHash(psk); then
  eph mix/ECDH as in `Cable.kt`. `psk = derive(secret, plaintextEid, PSK)`.
- Phone pushes, right after the handshake response: encrypted CBOR
  `{1: getInfo, 3: ["ctap"]}` — **no MessageType byte** on this message.
- Post-handshake frames = `[MessageType][encrypted]`; CTAP = 1, Shutdown = 0.
  getInfo map (key 1) = `{1:["FIDO_2_0","FIDO_2_1"], 2:["prf"], 3:<16 zeros>,
  4:{"rk":true,"uv":true}, 9:["cable","hybrid","internal"]}`.
- Crypter: pad to 32B (`msg ‖ zeros ‖ [count]`), AES-256-GCM nonce = 8 zeros ‖
  4B BE counter, empty AAD. Noise nonce = 4B BE counter ‖ 8 zeros (differs!).

### Commands

```bash
source ../tools/env.sh
../tools/build --dir passkey --force --no-stop :cable:run :app:assembleDebug
./gradlew :cable:tunnelCheck                      # live, self-contained
./gradlew :cable:desktopClient --args="<adv> <tid> <qrKey> [uv]"   # vs the app
./gradlew -q :cable:classpath > cp.txt            # fast direct run (see gotchas)
java -cp "$(cat cp.txt)" com.lightphone.passkey.cable.DesktopClientKt <adv> <tid> <qrKey> [uv]
adb -s emulator-5554 install -r app/build/outputs/apk/debug/app-debug.apk
adb -s emulator-5554 shell am start -n com.lightphone.passkey/com.thelightphone.sdk.LightActivity
adb -s emulator-5554 logcat -s passkey            # QR key / routing / advert / session
```
(`tools/build` rejects `--args` — run `./gradlew` directly for DesktopClient.)

### Gotchas

- **The relay drops the tunnel ~30s after the desktop connects** (observed
  twice, 2026-08-21) — the whole ceremony must finish inside that window, and
  the desktop must connect within ~30s of `/cable/new` or you get **HTTP 418**.
  Run DesktopClient via `java -cp` (see Commands) — gradle's startup eats the
  window. Fresh session each time: grab all three hex values from logcat.
- **`HybridSession`'s coroutine scope must NOT be cancelled in `stop()`** —
  `start()` calls `stop()` first, so a cancelled scope silently no-ops every
  later `scope.launch` (the MC/GA dispatch). The scope is per-instance; let it
  die with the instance. (Found 2026-08-21: first MC attempts silently did
  nothing, only the synchronous getInfo path worked.)
- `DesktopClient` args are the **advert**, **tunnel id**, **QR key** (all
  hex) plus optional `uv` — the routing comes from decrypting the advert (the
  real BLE path). With `uv`, type the lock PIN into the BiometricPrompt twice
  (MC then GA). **The emulator's credential field ignores `input text` until
  it is tapped first** (found 2026-08-21): `input tap <field>` then
  `input text 1234 && input keyevent 66`, for each prompt. Keep the ceremony
  inside the ~30 s window — the responder resumes against a nulled crypter
  (NPE) if the tunnel drops while a UV prompt is still open.
- The emulator's BLE advertise fails with a SecurityException (missing
  runtime BLUETOOTH_ADVERTISE) — harmless; the advert is logged. `pm grant
  com.lightphone.passkey android.permission.BLUETOOTH_ADVERTISE` silences
  it, but the emulator has no BLE anyway.
- UV on the emulator needs a lock screen: `adb shell locksettings set-pin
  1234` (wipe-data resets it). `pm clear com.lightphone.passkey` resets
  the credential store. **After a reboot with a PIN set, the emulator boots
  locked — user-0 apps won't launch (`am start` = "Error type 3: does not
  exist", `ceDataInode=0`, `stopped=true`) until the PIN is entered:**
  `input keyevent 224` (wake) then `input text 1234 && input keyevent 66`.
- `UvPrompt`'s crypto map is a `ConcurrentHashMap` — it **rejects null
  values** (registration's CryptoObject-less prompt NPE'd there, 2026-08-21);
  null cryptos are simply not stored.
- Local `check(cond, msg)` helpers have no smart-cast contract — use `!!`
  after them; compose list state needs `mutableStateListOf`; the app needs
  `androidx.activity:activity-compose` (sdk:ui keeps it implementation-only);
  `ECPublicKey.parameters` is `params` in Kotlin (`ECKey.getParams()`).
