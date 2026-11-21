---
name: frida
description: "Frida runtime instrumentation of an Android app on the connected Genymotion emulator — push a matching frida-server, bypass TLS certificate pinning to capture the app's real backend traffic through the proxy (the highest-value dynamic step — it turns the app's API into an in-scope web target), and hook crypto/keystore/WebView-bridge/intent code to confirm static findings at runtime. Pairs with tooling/adb.md (the ADB bridge) and frameworks/android.md."
---

# Frida — runtime instrumentation (Android, on Genymotion)

Frida proves the dynamic half of an Android assessment. Prerequisite: the ADB
bridge is up (`tooling/adb.md`) and `adb devices` shows the emulator. `frida-tools`
is installed in the sandbox; Genymotion is x86/rooted.

## Start frida-server on the emulator (concrete — version match is mandatory)
The `frida-server` version MUST equal the sandbox client (`frida --version`); a
mismatch fails with "unable to communicate / version". Genymotion is x86_64. Download
the matching server, push, run:
```
FV=$(frida --version)                                   # e.g. 16.5.9
ABI=$(adb shell getprop ro.product.cpu.abi | tr -d "\r")   # x86_64 on Genymotion
curl -fsSL -o /tmp/fs.xz \
  "https://github.com/frida/frida/releases/download/${FV}/frida-server-${FV}-android-${ABI}.xz"
xz -d /tmp/fs.xz
adb root && adb push /tmp/fs /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c '/data/local/tmp/frida-server -D'"    # -D = daemonize; run in bg
frida-ps -U | head                                     # lists processes → server is up
```
If `frida-ps -U` is empty but `adb devices` shows the emulator, the server didn't
start (wrong ABI/version, or SELinux) — re-check `$FV`/`$ABI`, not the bridge.

## Route the app's traffic to the sandbox proxy — use `adb reverse` (the reachability fix)
The emulator runs on the operator's host; the proxy (Caido/Burp) listens **inside the
sandbox container**. The emulator cannot reach a container-internal port directly, and
it can't resolve `host.docker.internal`. Do NOT point the proxy at a host IP and hope.
Instead tunnel the proxy port back through the already-working ADB channel: `adb
reverse` forwards an emulator port to **the machine running the adb *client*** — which
is the sandbox container — so the emulator's own `127.0.0.1:<port>` lands on the
container's proxy:
```
adb reverse tcp:8080 tcp:8080                           # emulator 127.0.0.1:8080 -> container Caido/Burp :8080
adb shell settings put global http_proxy 127.0.0.1:8080 # system proxy -> the tunnel
# install the proxy CA as a *system* cert (user certs are ignored on targetSdk>=24):
adb root; adb remount
adb push <caido-ca>.pem /system/etc/security/cacerts/$(openssl x509 -inform PEM -subject_hash_old -in <caido-ca>.pem | head -1).0
adb shell reboot ; # re-run frida-server after reboot
```
Clear it when done: `adb shell settings delete global http_proxy ; adb reverse --remove-all`.
(Setting a user-CA + `network_security_config` trust-anchor works only if the app opts
in; the system-cert route above is the reliable one on a rooted Genymotion.)

## #1 — TLS unpinning → capture the real backend API
This is the highest-value dynamic step: with pinning bypassed and traffic routed
through the proxy (above), the app's backend becomes an ordinary in-scope web target
the existing executors (sqli/oob/idor/authz/mass-assignment/...) tear into.
1. Proxy + system CA are set (previous section); `frida-ps -U` works.
2. Disable pinning. Try the layered options in order of robustness:
   - **objection (fastest):** `objection -g <pkg> explore -s "android sslpinning disable"`.
   - **Frida universal script:** `frida -U -f <pkg> -l unpinning.js --no-pause` using a
     multi-method script (fetch the maintained one: `curl -fsSL -o unpinning.js
     https://codeshare.frida.re/@httptoolkit/android-disable-root-and-ssl-pinning/` or
     the classic `frida-multiple-unpinning`). These hook OkHttp `CertificatePinner`,
     `TrustManagerImpl.verifyChainOnly`/`checkTrustedRecursive`, Conscrypt, and the
     `X509TrustManager`/`HostnameVerifier` custom-override paths at once.
3. Drive the app (login, main flows) via `adb shell am start` / the UI; the proxy now
   sees cleartext API calls. **Record every endpoint + param** with `record_endpoint`
   / `ingest_recon_endpoints` (`discovery_source="apk-dynamic"`) and hunt with the web
   executors. Confirm client-computed signatures/HMACs here.

### When the generic unpin fails — framework-specific pinning
- **Flutter** — pinning is in BoringSSL inside `libflutter.so`; Java hooks do nothing.
  Patch the APK with `reFlutter` (rewrites the engine to disable verification + route
  to a proxy) OR hook the native `ssl_verify_peer_cert`/`session_verify_cert_chain`
  symbol offset in `libflutter.so` with a Frida native hook. Note it honestly as the
  harder path.
- **React Native** — usually standard OkHttp → the generic unpin works; if a custom
  pinning lib (`react-native-ssl-pinning`) is used, hook its module directly.
- **Native pinning (NDK/`libssl`)** — a custom native `SSL_CTX_set_custom_verify`/
  `SSL_get_verify_result` needs a native-symbol Frida hook, not the Java script.
- A pin that resists every method is `blocked`, not `ruled_out` — record it; fall back
  to the static backend-API extraction from `frameworks/android.md`.

## Hooks that confirm static findings
- **Crypto misuse:** hook `javax.crypto.Cipher.getInstance`/`doFinal`,
  `SecretKeySpec` to log algorithm/mode/key/IV → confirm hardcoded keys / ECB.
- **Keystore / storage:** hook `SharedPreferences`, `KeyStore`, SQLite to see what
  secrets are written and in what form.
- **WebView bridge:** hook `addJavascriptInterface` / the bridge object's methods →
  confirm an exposed native method is reachable (RCE lead) and with what input.
- **Intent handling:** hook `getIntent`/`onCreate` of an exported component to see
  whether a crafted intent (from `adb shell am start`) reaches a sensitive sink.
- **Root/anti-tamper/anti-Frida:** if the app detects Frida/root/emulator, that is
  a hardened app — note it honestly; bypassing heavy RASP is manual, not automatic
  (the stated ceiling in `frameworks/android.md`).

## Discipline
- Only the authorized app on the emulator, never a real device/user. No persistence
  beyond the test session; stop frida-server after.
- A hook/unpin that fails (pinning via a native lib, anti-Frida) is `blocked`, never
  `ruled_out` — record it; some apps genuinely resist and that is an honest limit.
- Dynamic confirmation upgrades a static candidate from reduced-confidence to a
  proven finding (`counterevidence.md`); a Frida callback/capture alone still needs
  the real-impact proof the class requires.
- `objection` and `MobSF`'s dynamic analyzer are higher-level alternatives; pick one
  driver per device (don't run MobSF and a direct Frida session on the same app at
  once).
