# passkey — LP3 passkey authenticator (LightOS tool, caBLE hybrid)

WebAuthn authenticator core for the Light Phone 3, in Kotlin.
**Truck 1 (caBLE hybrid) chosen 2026-08-21** — the phase-0 probes vetoed
Truck 2 (USB-HID): it needs root (locked bootloader, no su).

**Status: protocol + ceremony done and verified end-to-end, including real
Chrome on the real LP3. Sole remaining blocker: UV on the LP3** (needs a
LightOS-native lock — see Status).

## Status

**Done and verified:**

- caBLE v2 core (`:cable`), authenticator (`:core`), and the LightOS tool
  with the companion merged into one APK (`:app`/`:server`, toolbox-launched).
- **Real-Chrome interop on the LP3 through the live relay (2026-08-22):**
  webauthn.io register ("Success! Now try to authenticate…") and login
  ("You're logged in!") with UV (temporary lock PIN). The interop gate found
  and fixed four wire bugs (see Protocol facts).
- `:cable:run` (1178 asserts, incl. real-Chrome regression vectors);
  DesktopClient ceremonies (40 checks, uv=false and uv=true); on-device LP3
  ceremonies (40 checks each, real BLE advert).

**Blocker — UV on the LP3:**

- Real Chrome forces `uv: required` for hybrid regardless of the RP's
  preference (verified on the wire: webauthn.io sent `userVerification:
  discouraged`, Chrome's MC carried `uv: true`) — there is no no-UV path with
  real Chrome.
- UV requires an Android secure lock; any PIN or fingerprint activates the
  AOSP keyguard, breaking the LP3's zero-unlock wake flow (standby clock →
  tool button → toolbox). Pending a LightOS-native lock/enrollment path
  (Light's product decision).

## Modules

- `:cable` — caBLE v2 protocol core, pure JVM, zero deps: `Qr` (FIDO:/ digit
  payload), `Eid` (BLE advert), `Cable` (HKDF + Noise KNpsk0/NKpsk0 +
  Crypter), `Ctap2` (MC/GA codec, authData/COSE parsers), tunnel transport
  (`TunnelServer`/`Ws`/`TunnelCheck`).
- `:core` — the authenticator: `CredentialStore` (EC P-256 in Android
  Keystore, resident-key metadata in app-private JSON), `UvGate`
  (BiometricPrompt, injectable), `PasskeyAuthenticator` (WebAuthn JSON
  `register`/`assert` plus raw `registerCtap`/`assertCtap` pieces for the
  session).
- `:app` — the LightOS tool (`PasskeyScreen`, `@InitialScreen`): scans the
  desktop's QR (`LightQrCodeScanner`), polls `GetSessionState` (~400 ms),
  outcome titles ("Passkey created" / "Signed in" / "Couldn't sign in").
  Debug auto-QR button for the emulator path — remove for release.
- `:server` — companion library merged into the tool APK (`serverPackage =
  com.lightphone.passkey`): `SessionManager` (state machine),
  `HybridSession` (tunnel → EID advert → KNpsk0 handshake → pushed getInfo →
  CTAP loop dispatching 0x01 MC / 0x02 GA), `UvPrompt`+`UvActivity` (the UV
  bridge), `PasskeyServiceMethods` (StartPasskeySession/StopSession/
  GetSessionState), `ServerBootstrapProvider` + PlatformRelay (all keys
  relayed to `com.lightos`).
- `:rp` — local WebAuthn4J relying party (host-side).

## Build, install, verify

```bash
source ../tools/env.sh
../tools/build --dir passkey :app:assembleDebug        # build (use --force for tight RAM)
./gradlew :cable:run                                   # self-check (1178 asserts)
./gradlew :cable:tunnelCheck                           # live tunnel round-trip
adb -s emulator-5554 install -r app/build/outputs/apk/debug/app-debug.apk
adb -s emulator-5554 shell am start -n com.lightphone.passkey/com.thelightphone.sdk.LightActivity
adb -s emulator-5554 logcat -s passkey                 # QR key / routing / advert / session
```

DesktopClient ceremony (vs the app): take the advert/tunnel-id/QR-key hex from
logcat, then

```bash
java -cp "$(./gradlew -q :cable:classpath)" com.lightphone.passkey.cable.DesktopClientKt <adv> <tid> <qrKey> [uv]
```

Run via `java -cp`, not gradle — startup eats the tunnel's ~30 s window.
With `uv`, type the lock PIN into the BiometricPrompt twice (MC then GA).

## Protocol facts (verified from Chromium — don't re-derive)

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
  **Noise protocol names are zero-padded to 32 bytes** before use.
- Phone pushes, right after the handshake response: encrypted CBOR
  `{1: getInfo, 3: ["ctap"]}` — **no MessageType byte** on this message.
- Post-handshake frames = `[MessageType][encrypted]`; CTAP = 1, Shutdown = 0.
  **Replies must carry the MessageType byte as the first plaintext byte**
  (`[0x01 kCTAP][0x00 status][cbor]`) — Chromium's `fido_tunnel_device.cc`
  reads it after decryption; a reply without it parses as `kShutdown`.
- CTAP2 MakeCredential request (Chromium `ctap_make_credential_request.cc`,
  captured 219-byte real request): `{1: clientDataHash, 2: rp{id, name},
  3: user{id, name, displayName}, 4: [{alg, type}], 5: exclude[{id}],
  7: options{rk, uv}}` — **inner maps use TEXT keys**.
- CTAP2 GetAssertion request: `{1: rpId, 2: clientDataHash, 3: allow[{id}],
  5: options{uv}}` — allow entries use TEXT keys.
- CTAP2 GetAssertion response: `{1: credential{id, type}, 2: authData,
  3: signature, 4: user{id, name, displayName}, 5: numberOfCredentials}` —
  credential and user entities use TEXT keys; the signature stays **DER**
  (Chrome's own `kDeviceGetAssertionResponse` test vector is DER).
- **Map keys must be in canonical CBOR order** (RFC 8949 §4.2.1: by encoded
  byte length, then byte-wise lexical) — Chromium's `cbor::Reader` rejects
  non-canonical maps. The user entity therefore encodes `id`(2B), `name`(4B),
  `displayName`(11B) — NOT lexicographic order.
- **Chrome escalates UV for hybrid:** resident keys are required on hybrid and
  UV is upgraded to `required` for resident keys on non-platform
  authenticators (`make_credential_request_handler.cc`) — a uv=discouraged RP
  still gets `options: {uv: true}` on the wire. No-UV hybrid interop does not
  exist.
- getInfo map (key 1) = `{1:["FIDO_2_0","FIDO_2_1"], 2:["prf"], 3:<16 zeros>,
  4:{"rk":true,"uv":true}, 9:["cable","hybrid","internal"]}`.
- Crypter: pad to 32B (`msg ‖ zeros ‖ [count]`), AES-256-GCM nonce = 8 zeros ‖
  4B BE counter, empty AAD. Noise nonce = 4B BE counter ‖ 8 zeros (differs!).

## Gotchas

- **The relay drops the tunnel ~30s after the desktop connects** — the whole
  ceremony must finish inside that window, and the desktop must connect within
  ~30s of `/cable/new` or you get **HTTP 418**. Fresh session each time: grab
  all three hex values from logcat.
- **`HybridSession`'s coroutine scope must NOT be cancelled in `stop()`** —
  `start()` calls `stop()` first, so a cancelled scope silently no-ops every
  later `scope.launch` (the MC/GA dispatch). The scope is per-instance; let it
  die with the instance.
- The emulator's BLE advertise fails with a SecurityException (missing runtime
  BLUETOOTH_ADVERTISE) — harmless; the advert is logged. `pm grant
  com.lightphone.passkey android.permission.BLUETOOTH_ADVERTISE` silences it.
- UV on the emulator needs a lock screen: `adb shell locksettings set-pin
  1234` (wipe-data resets it). **After a reboot with a PIN set, the emulator
  boots locked — user-0 apps won't launch until the PIN is entered:**
  `input keyevent 224` (wake) then `input text 1234 && input keyevent 66`.
  The emulator's credential field ignores `input text` until tapped first.
- `UvPrompt`'s crypto map is a `ConcurrentHashMap` — it **rejects null
  values**; null cryptos are simply not stored.
- Local `check(cond, msg)` helpers have no smart-cast contract — use `!!`
  after them; compose list state needs `mutableStateListOf`; the app needs
  `androidx.activity:activity-compose`; `ECPublicKey.parameters` is `params`
  in Kotlin (`ECKey.getParams()`).
- On the LP3: never `locksettings set-pin` without a cleanup plan — any secure
  credential activates the AOSP keyguard over the wake flow. Cleanup:
  `locksettings clear --old <pin>` + `wm dismiss-keyguard`.
