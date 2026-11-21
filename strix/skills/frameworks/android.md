---
name: android
description: "Android APK security testing on a decompiled app (jadx Java + apktool manifest/resources) — exported-component authorization, deep-link / app-link hijack, WebView JS-bridge RCE, hardcoded secrets and backend-API extraction, insecure storage, weak crypto, cleartext/pinning network config, exported ContentProvider SQLi/traversal, and debuggable/backup flags. The highest-yield output is the backend API the app talks to: once extracted it becomes an in-scope web target for the existing executors. Static candidates are PROVEN dynamically on a connected device/emulator (see tooling/adb.md, tooling/frida.md)."
---

# Android APK Security (white-box over a decompiled app)

A staged `.apk` is decompiled at container start into `*-decompiled/` under
`/workspace/mobile-apps/`: `apk/` (apktool — `AndroidManifest.xml`, `res/`, smali,
`res/xml/network_security_config.xml`) and `java/` (jadx — readable Java). Treat it
as white-box source: `source_aware_discovery.md`/`source_aware_sast.md` apply, with
the Android-specific entry points, sinks and guards below. **Instance discipline
(`source_aware_discovery.md`): every exported component / deep link / WebView / bridge
/ provider is its own candidate — one root cause is not one candidate.**

## Mobile Assessment — Phase Order (run these in sequence; don't skip ahead)
A mobile assessment is a pipeline, not a scan. Each phase feeds the next; the big
wins are in phases 2 and 5.
1. **Acquire & decompile** — a file-staged `.apk` is already decompiled at container
   start. An `adb://<pkg>` target: bring up the bridge (`tooling/adb.md`), `pm path` +
   `adb pull` every split, then `apktool d` + `jadx -d` yourself.
2. **Framework triage (Step 0 below) — ALWAYS first after decompile.** It decides
   whether `java/` is the real source (native) or the logic lives in a JS bundle
   (React Native), `libapp.so` (Flutter), `assets/www/` (Cordova), or `.dll`s (Xamarin).
   Everything downstream depends on getting this right.
3. **Static backend-API extraction (the #1 win)** — pull every endpoint/param/auth
   scheme → `record_endpoint`/`ingest_recon_endpoints` (`discovery_source="apk"`). This
   alone usually yields the highest-severity bugs, because the backend is an ordinary
   web target the existing executors are elite at.
4. **Static app-surface sweep** — exported components, deep links, WebView bridges,
   providers, secrets, storage, crypto, network config (sections below). Each instance
   is its own candidate; `record_coverage` per surface.
5. **Dynamic confirmation (`tooling/adb.md` + `tooling/frida.md`)** — on the connected
   Genymotion: `am start`/`content` to prove exported-component/provider findings, and
   **Frida TLS-unpin + `adb reverse` proxy capture to turn the live backend into an
   in-scope web target** (phase 3's endpoints, now with real traffic/params/tokens).
6. **Hunt the backend with the web executors** — the captured/extracted API runs the
   normal black-box brain (sqli/oob/idor/authz/mass-assignment/graphql/...), hypotheses,
   coverage, counterevidence. This is where mobile findings actually get proven and filed.
7. **Chain** — a client-leaked secret/endpoint + a backend authz gap, a deep-link +
   OAuth token theft, an exported component + a provider read (per `root_agent.md`'s
   chaining pass).
Dynamic steps that can't run (no bridge, hardened RASP) are `blocked`, never
`ruled_out` — record and fall back to the static backend-API path, which stands alone.

## Step 0 — Detect the app framework FIRST (do this before anything else)
The decompiled Java is only the real source for **native Java/Kotlin** apps. A
cross-platform app's logic lives somewhere jadx won't show it — mis-triaging here
wastes the whole assessment. Fingerprint before you read:
```
ls apk/assets/ apk/lib/*/ ; rg -n "flutter|reactnative|cordova|xamarin|mono|unity" apk/AndroidManifest.xml apk/res/ 2>/dev/null
```
- **Native Java/Kotlin** — no cross-platform marker; `java/` IS the source. Proceed
  with the full methodology below as written.
- **React Native** — `lib/*/libreactnativejni.so` or `assets/index.android.bundle`.
  **The entire app logic is in that JS bundle** — treat it EXACTLY like a web JS
  bundle (`asset_discovery.md` JS-mining): `rg -n "https?://|/api/|fetch\(|axios|token|secret|AsyncStorage" apk/assets/index.android.bundle`.
  If Hermes-compiled (not readable text), decompile with `hermes-dec`/`hbctool` first.
  This is usually a *goldmine* of endpoints and secrets — the highest-yield RN output.
- **Flutter** — `lib/*/libflutter.so` + `lib/*/libapp.so`. Dart is AOT-compiled into
  `libapp.so`; jadx shows almost nothing. Extract strings/endpoints from `libapp.so`
  (`rg -a "https?://" apk/lib/*/libapp.so`), and know pinning lives in BoringSSL
  inside `libflutter.so` — the generic unpin hooks fail; see `frida.md`'s Flutter note
  (reFlutter / `ssl_verify_peer_cert` native hook). The backend API is still the win.
- **Cordova / Ionic / Capacitor (hybrid WebView)** — `assets/www/` holds HTML/JS/CSS.
  It's a web app in a WebView: grep `assets/www/` for endpoints/secrets and test the
  JS for DOM-XSS/`config.xml` whitelist bypass; the WebView bridge is the native edge.
- **Xamarin / .NET MAUI** — `assembly/*.dll` or `assemblies/` (sometimes LZ4-packed).
  Decompile the DLLs with `ilspycmd`/`monodis`; the logic and endpoints are there, not
  in `java/`.
- **Unity** — `assets/bin/Data/Managed/Assembly-CSharp.dll` (decompile with ilspy) or
  IL2CPP (`libil2cpp.so` + `global-metadata.dat` → Il2CppDumper). Usually a game; still
  mine for backend/API keys.
Record the detected framework in a note; it dictates the decompiler, the grep targets,
and the unpinning approach for the entire run.

## The #1 output — extract the backend API
A decompiled app is a map to the server. This is usually the fastest path to real
bugs (the §15 payoff ranking), because the app's backend is the same class of
target Strix is already elite at.
- Grep for base URLs and endpoints: `rg -n "https?://" java/ apk/res/` , Retrofit
  `@GET`/`@POST`/`@Path`/`@Query`/`@Body` interfaces, OkHttp `.url(`, `Request.Builder`,
  `strings.xml`/`BuildConfig` (`API_BASE_URL`, `BASE_URL`, `ENDPOINT`).
- Pull auth: header names, token storage, API keys, HMAC/signing schemes computed
  client-side (a client-computed signature over values the server also hands out is
  the mobile analogue of the courts.gov.az forgeable-hash finding).
- **Record every endpoint + param into the attack-surface inventory**
  (`record_endpoint` / `ingest_recon_endpoints`) with `discovery_source="apk"`, then
  hunt it with the web executors (sqli/oob/idor/authz/mass-assignment/...). Capture
  the app's live traffic through the proxy during the dynamic pass to confirm the
  real contract (Phase 2).

## Entry Points (enumerate each as its own candidate)
From `AndroidManifest.xml` (apktool-decoded):
- **Exported components** — every `<activity|service|receiver|provider
  android:exported="true">` reachable by any other app. Also *implicitly* exported:
  a component with an `<intent-filter>` and no explicit `exported` on older
  `targetSdk`. Enumerate: `rg -n 'exported="true"|<intent-filter' apk/AndroidManifest.xml`.
- **Deep links / app links** — `<data android:scheme=.. android:host=..>`. A scheme
  the app trusts for routing/auth (`myapp://oauth?token=`) is a hijack/redirect lead
  (cross-link `oauth.md`/`open_redirect.md`).
- **ContentProviders** — exported provider → SQL injection in `query()` selection,
  path traversal in `openFile()`, read/write of private data by any app.
- **Exported BroadcastReceivers / Services** — commands/intents accepted from any app.
- **WebViews** — `setJavaScriptEnabled(true)`, `addJavascriptInterface(obj,"name")`
  (JS→native bridge → RCE if the WebView loads untrusted/remote content),
  `setAllowFileAccess`/`AllowUniversalAccessFromFileURLs`, a weak
  `shouldOverrideUrlLoading`.

## Dangerous Sinks by class
- **Hardcoded secrets / keys** — API keys, cloud creds, Firebase config, signing
  keys, keystore passwords in `strings.xml`/`BuildConfig`/code. Run
  `trufflehog filesystem <decompiled> --results=verified` + `gitleaks detect --source
  <decompiled> --no-git`. A client-side Firebase/Maps key is not automatically a
  secret — classify it (cross-link `technologies/firebase.md`).
- **Insecure storage** — plaintext `SharedPreferences`, world-readable/external-storage
  writes, unencrypted SQLite, secrets in logs (`Log.d(...token...)`).
- **Weak / misused crypto** — `AES/ECB`, hardcoded keys/IVs, `MD5`/`SHA1` for
  passwords, `Cipher.getInstance("AES")` (defaults to ECB), insecure `Random` for
  tokens, static salts.
- **Network security** — `res/xml/network_security_config.xml`
  `cleartextTrafficPermitted="true"`, `<trust-anchors>` adding user CAs, **no cert
  pinning** (MITM lead), or pinning present but a custom `TrustManager`/
  `HostnameVerifier` that accepts all (grep `checkServerTrusted`/`verify` returning
  without checks).
- **Exported-component abuse** — intent redirection / `PendingIntent` mutability
  (implicit + `FLAG_MUTABLE`), SQLi/traversal in a provider, task hijacking.
- **Build flags** — `android:debuggable="true"`, `android:allowBackup="true"`
  (adb backup of private data), `usesCleartextTraffic="true"`.

## The real control — verify the guard, don't assume it
Apply `counterevidence.md` to Android guards specifically:
- `exported="true"` + a `permission` attribute is only a control if that permission's
  `protectionLevel` is `signature`/`dangerous` — a `normal` permission is granted to
  any app silently, so the component is effectively open. Check the `<permission>`
  definition's level, not just its presence.
- A WebView bridge "gated" by a URL allowlist in `shouldOverrideUrlLoading` is
  bypassable if the check is substring/prefix based, or if the bridge object is added
  before the URL check runs.
- Cert pinning that is present but overridden by a debug `TrustManager`, or only on
  one of several OkHttp clients, does not cover the reachable path.
- A permission check inside the component that runs AFTER a side effect, or only on
  one intent action, is a reachable-path gap.

## Testing Methodology
1. **Decompile is done for you** — read `apk/AndroidManifest.xml` first (package,
   `versionName`, `minSdk`/`targetSdk`, every component + export + permission).
2. **Extract the backend API** (above) → attack-surface inventory → web executors.
3. **Enumerate entry points** (exported comps, deep links, WebViews, providers),
   each a candidate; record coverage per instance.
4. **Trace each sink** source→sink in `java/` with `file:line` per hop (jadx line
   numbers; fall back to smali under `apk/` when jadx failed).
5. **Secrets pass** (trufflehog/gitleaks, verified).
6. **Dynamic confirmation on a device/emulator** — a static finding is a candidate;
   PROVE it at runtime (`am start` an exported activity with a crafted intent,
   `content query` a provider, a Frida pinning bypass to read live traffic). See
   `tooling/adb.md` and `tooling/frida.md`. Without runtime proof, a static-only
   finding is reported at reduced confidence with the missing runtime proof named in
   `confidence_rationale` (per `counterevidence.md`), never inflated.

## Validation
- An exported-component / provider / deep-link finding needs a working intent/`content`
  PoC (dynamic) OR a complete static trace with the guard-gap proven and the runtime
  reproduction named as the one missing step.
- A hardcoded secret needs live verification (does the key work? what scope?) — a
  client-side-public key is not a finding.
- A backend-API finding is proven by the web executors exactly like any web target.
- Cleartext/pinning/MITM: a static config is a lead; the finding is a demonstrated
  interception (Frida unpin + proxy capture).

## Reporting
- Affected `package` + `versionName` from the manifest; CWE-NNN.
- Full source-to-sink trace with `file:line` per hop (java/ or smali).
- A literal PoC: the exact `adb shell am start ...` / `content query ...` / the request.
- Android-context impact (which other app / any app / a MITM attacker).
- 0-day in first-party app code files via `create_vulnerability_report` (NOT
  `create_dependency_report` — that is for published-CVE lockfile scanning).

## Summary
Read the manifest, extract the backend API (the biggest win → web executors),
enumerate every exported component / deep link / WebView / provider as its own
candidate, trace sinks with `file:line`, verify every guard's real strength, and
prove the candidate dynamically on a connected emulator. Static finds it; runtime
proves it; the existing hypothesis/coverage/counterevidence brain tracks it.
