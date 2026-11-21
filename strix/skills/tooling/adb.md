---
name: adb
description: "Driving a connected Android device/emulator from the sandbox over ADB for DYNAMIC Android testing — the container reaches the operator's host Genymotion via the host ADB server (ADB_SERVER_SOCKET=tcp:host.docker.internal:5037), then installs the APK, launches/injects intents into exported components, queries exported ContentProviders, reads logcat, and pulls app data (rooted emulator). This is how a static finding from frameworks/android.md is PROVEN at runtime."
---

# ADB — dynamic Android testing against the host emulator

The sandbox is a container; the emulator (Genymotion) runs on the operator's
host. The container drives it through the **host's ADB server**, not a device
inside the container — this sidesteps needing KVM/emulation inside Docker.

## The bridge (set up once; the host step is the operator's)

**Host (operator runs this — you cannot touch their host).** The default adb
server binds `127.0.0.1` only, which the container CANNOT reach; it must be
rebound to all interfaces on 5037. A plain `adb kill-server` often does not free
the port (Genymotion / Android Studio keep an adb alive, and any `adb` command
re-spawns a `127.0.0.1` server), giving `cannot bind to 0.0.0.0:5037 ... (10048)`.
Kill ALL adb first, then start the exposed server, then attach the Genymotion
device to it:
```
# Windows (PowerShell) — kill every adb, then bind all interfaces (keep open):
taskkill /F /IM adb.exe
<path>\adb.exe -a -P 5037 nodaemon server
#   (Linux/mac host:  pkill -f adb ; adb -a -P 5037 nodaemon server )
# In a SECOND terminal, attach the Genymotion device to THIS server:
<path>\adb.exe connect 192.168.56.111:5555     # the IP from `adb devices`
<path>\adb.exe devices                          # must now list that device
```
Allow inbound TCP 5037 if Windows Firewall prompts. Keep the server using the
SAME adb binary Genymotion uses (Genymotion → Settings → ADB → custom SDK tools
pointed at the platform-tools folder) so client/server versions match — a version
mismatch to the container's adb shows as "adb server version doesn't match".

**Container (you run this):** the image already defaults
`ADB_SERVER_SOCKET=tcp:host.docker.internal:5037`; re-export it (survives the
entrypoint re-exec) and check:
```
export ADB_SERVER_SOCKET=tcp:host.docker.internal:5037
adb devices          # the Genymotion device must appear; if empty, STOP — the
                     # host bridge is not up (see the host steps above).
```
If `adb devices` is empty, dynamic testing is `blocked` (not `ruled_out`) — say
so and fall back to the static analysis (`frameworks/android.md`) until the
operator brings the bridge up. Genymotion is **rooted**, so `adb root` works —
use it only on the authorized emulator, never a real device with real data.

## Acquire the APK from the device (autonomous `adb://<package>` flow)

When the target is `adb://<package>` the operator installed the app from the Play
Store onto the emulator and Strix pulls it itself — do this first, then decompile
at runtime and analyse:
```
adb shell pm list packages | rg <name>            # find the exact package if unsure
adb shell pm path <package>                        # prints package:/data/app/.../base.apk
mkdir -p /workspace/mobile-apps
# pull EVERY line pm path prints (modern apps are split: base.apk + split_config.*.apk)
adb shell pm path <package> | sed 's/^package://' | while read p; do
  adb pull "$p" /workspace/mobile-apps/ ; done
# decompile at runtime (the entrypoint only auto-decompiles file-staged APKs):
for a in /workspace/mobile-apps/*.apk; do
  apktool d -f -o "${a%.apk}-decompiled/apk" "$a" || echo "apktool warn $a"
  jadx -d "${a%.apk}-decompiled/java" "$a" || echo "jadx warn $a"
done
```
If the app is split-APK, analyse `base.apk` as the primary and note the splits.
Then proceed exactly as `frameworks/android.md` (white-box over the decompiled
tree) + the dynamic steps below. A Play-protected/licensed app whose APK will not
pull is `blocked`, not `ruled_out`.

## Core idioms (prove the static findings)

- **Install the target APK** (if you have a file, not a device-installed app):
  `adb install -r /workspace/mobile-apps/<app>.apk`.
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
