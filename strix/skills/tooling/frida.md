---
name: frida
description: "Frida runtime instrumentation of an Android app on the connected Genymotion emulator — push a matching frida-server, bypass TLS certificate pinning to capture the app's real backend traffic through the proxy (the highest-value dynamic step — it turns the app's API into an in-scope web target), and hook crypto/keystore/WebView-bridge/intent code to confirm static findings at runtime. Pairs with tooling/adb.md (the ADB bridge) and frameworks/android.md."
---

# Frida — runtime instrumentation (Android, on Genymotion)

Frida proves the dynamic half of an Android assessment. Prerequisite: the ADB
bridge is up (`tooling/adb.md`) and `adb devices` shows the emulator. `frida-tools`
is installed in the sandbox; Genymotion is x86/rooted.

## Start frida-server on the emulator
Version MUST match the sandbox `frida` client (`frida --version`). Download the
matching `frida-server` for `android-x86_64`, then:
```
adb root
adb push frida-server /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c '/data/local/tmp/frida-server &'"
frida-ps -U      # lists processes over USB/ADB — confirms the server is up
```

## #1 — TLS unpinning → capture the real backend API
This is the highest-value dynamic step: with pinning bypassed and traffic routed
through the proxy, the app's backend becomes an ordinary in-scope web target that
the existing executors (sqli/oob/idor/authz/mass-assignment/...) tear into.
1. Set the emulator's Wi-Fi HTTP proxy to the sandbox proxy (Caido/Burp) and
   install its CA (or use the app CA already trusted); Genymotion settings or
   `adb shell settings put global http_proxy <sandbox>:<port>`.
2. Disable pinning with a universal unpinning hook or objection:
   `frida -U -f <pkg> -l unpinning.js --no-pause` , or
   `objection -g <pkg> explore -s "android sslpinning disable"`.
3. Drive the app (login, main flows) via `adb shell am start` / the UI; the proxy
   now sees cleartext API calls. **Record every endpoint + param** with
   `record_endpoint` / `ingest_recon_endpoints` (`discovery_source="apk-dynamic"`)
   and hunt with the web executors. Confirm client-computed signatures/HMACs here.

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
