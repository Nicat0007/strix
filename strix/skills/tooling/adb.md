---
name: adb
description: "Driving a connected Android device/emulator from the sandbox over ADB for DYNAMIC Android testing — the container reaches the operator's host Genymotion via the host ADB server (ADB_SERVER_SOCKET=tcp:host.docker.internal:5037), then installs the APK, launches/injects intents into exported components, queries exported ContentProviders, reads logcat, and pulls app data (rooted emulator). This is how a static finding from frameworks/android.md is PROVEN at runtime."
---

# ADB — dynamic Android testing against the host emulator

The sandbox is a container; the emulator (Genymotion) runs on the operator's
host. The container drives it through the **host's ADB server**, not a device
inside the container — this sidesteps needing KVM/emulation inside Docker.

## The bridge (set up once; the host step is the operator's)

**Host (operator runs this — you cannot touch their host):** expose the ADB
server on the network and have Genymotion running:
```
adb kill-server
adb -a -P 5037 nodaemon server    # listen on all interfaces
# Genymotion open; `adb devices` on the host must list the emulator
```
**Container (you run this):** point the ADB client at the host server via the
already-present `host.docker.internal` → host-gateway mapping:
```
export ADB_SERVER_SOCKET=tcp:host.docker.internal:5037
adb devices          # the Genymotion device must appear; if empty, STOP — the
                     # host bridge is not up. Record `blocked`, ask the operator.
```
If `adb devices` is empty, dynamic testing is `blocked` (not `ruled_out`) — say
so and fall back to the static analysis (`frameworks/android.md`) until the
operator brings the bridge up. Genymotion is **rooted**, so `adb root` works —
use it only on the authorized emulator, never a real device with real data.

## Core idioms (prove the static findings)

- **Install the target APK:** `adb install -r /workspace/mobile-apps/<app>.apk`
  (the same APK that was decompiled statically).
- **Exported Activity launch / intent injection** (prove an exported-component
  or deep-link finding): `adb shell am start -n <pkg>/<.Activity> --es key val`,
  deep link `adb shell am start -a android.intent.action.VIEW -d "myapp://host/path?token=x"`,
  broadcast `adb shell am broadcast -a <ACTION> --es ...`. A component that acts on
  the crafted intent with no permission check is the confirmed BFLA/redirect PoC.
- **Exported ContentProvider** (prove provider SQLi / traversal / data read):
  `adb shell content query --uri content://<authority>/<path>`,
  `content query --uri content://<authority>/x --where "1=1) UNION SELECT ..."` (SQLi),
  `content read --uri content://<authority>/../../databases/x` (traversal). Any app
  reading private data this way is the finding.
- **Permissions:** `adb shell dumpsys package <pkg> | sed -n '/requested permissions/,/install permissions/p'`;
  `adb shell pm list permissions -g -d` to see a custom permission's protectionLevel
  (the "verify the guard" check — a `normal`-level permission is no control).
- **Runtime data (rooted):** `adb shell run-as <pkg> ls -R /data/data/<pkg>`,
  `adb pull /data/data/<pkg>/shared_prefs/` → confirm insecure-storage findings
  (plaintext tokens/secrets); `adb shell cat /data/data/<pkg>/databases/*`.
- **Logcat leaks:** `adb logcat -d | rg -i "token|password|secret|authorization|http"` —
  confirm sensitive logging while driving the app.
- **Live traffic:** drive the app and capture its backend calls through the proxy
  (set the emulator's HTTP proxy to the sandbox Caido/Burp, + Frida unpinning —
  see `tooling/frida.md`); every captured endpoint → `record_endpoint` /
  `ingest_recon_endpoints` → the web executors.

## Discipline
- Only the authorized app, only on the emulator (Genymotion), never a real device
  or real user data. No destructive device actions.
- A dynamic step that can't run (no bridge / app won't install) is `blocked`,
  never `ruled_out` — record it and continue with static.
- Record coverage per surface driven; file confirmed runtime findings with the
  exact `am start`/`content`/`pull` PoC (per `frameworks/android.md`'s reporting).
- `MobSF` is an alternative dynamic driver that connects to Genymotion itself; if
  used, let MobSF OR Strix drive the device, not both at once, and consume MobSF's
  JSON as an oracle (every lead still passes `counterevidence.md`).
