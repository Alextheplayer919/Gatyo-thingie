# Does this APK steal passwords? — targeted credential-theft assessment

**Question:** can `Gatyo-1.21.111-Iris-build118.apk` steal passwords, accounts, or similar?
**Answer, up front: no credential-stealing mechanism was found.** The four classic Android
password-theft vectors are absent at both the manifest and the code level, and there is no
access to other apps' data, no keyboard hooking and no accessibility abuse.

**But** it is not a clean app: it reads the Android clipboard on demand, uploads device/usage
telemetry to an unknown destination over a config that permits cleartext HTTP, and it lies about
its own signing certificate. Those are real problems — just not password theft. Details and
residual risk in §5–§7.

Everything below was re-derived from the bytes in this session (full `.text` disassembly,
bytecode tracing of all six dex files, manifest parsing, whole-APK string sweeps).

---

## 1. Method, and why this answer is fairly strong

The useful property of this APK is that the injected code is **small and enumerable**: 98 classes
(`classes5.dex` = 83, `classes6.dex` = 15) versus 18,271 stock classes. That let me do a
*complete* inventory instead of sampling:

| Check | Scope | Method |
|---|---|---|
| Manifest surface | 1 AXML | parsed with `tools/axml.py`: all 14 permissions, 25 components, no `BIND_ACCESSIBILITY_SERVICE`, no `SYSTEM_ALERT_WINDOW`, no device-admin/autofill/IME receiver |
| Injected code | **98/98 classes** | every `invoke-*` in every method resolved to a platform class + method name → complete list of Android/Java APIs the payload can call (§2) |
| Native payload | 6.1 MB `.so` | all `android/*`, `java/*` JNI class strings enumerated (only 6), full string sweep, `.text` disassembled for cross-references |
| Whole APK | **33,397 files** | string sweep for exfiltration targets (Chrome `Login Data`, `keychain`, `accounts.db`, `.mozilla`, `content://sms`, `content://contacts`, `wifi_pass`, `createScreenCapture`, `Camera.open`, …) |
| Stock code hits | all 6 dex | every scary-looking API hit was traced to the owning class to prove it is library plumbing (§4) |
| Network reach | native + Java | native imports **0** socket/DNS functions; the only URL strings are a Discord invite, an Apache licence line and clang/LLVM links |

Caveat stated honestly: this is static analysis. It cannot see behaviour behind encryption or a
runtime-assembled destination, and the payload does contain an obfuscation routine (a rotate-XOR
keystream, §8 of the main document), so "string absent" is not proof for *that* specific path.
The JNI surface being just six class names, however, bounds what the native code can reach on the
Android framework side without generating class names at runtime.

---

## 2. The complete Android API surface of the injected code

Every platform class referenced by `classes5.dex` + `classes6.dex`, i.e. everything the payload
can do through the framework:

```
android.app.{Activity, AlertDialog(+Builder), Application, Dialog, Fragment, FragmentManager,
             FragmentTransaction}
android.content.{ClipData, ClipData$Item, ClipboardManager, ContentProvider, ContentResolver,
                 Context, Intent}
android.content.pm.{Signature, SigningInfo}
android.content.res.AssetManager
android.database.Cursor
android.graphics.{Bitmap, BitmapFactory(+Options), drawable.ColorDrawable}
android.net.Uri
android.opengl.GLSurfaceView
android.os.{Bundle, Handler, HandlerThread, Looper, Parcelable$Creator, SystemClock}
android.util.{Base64, Log}
android.view.{MotionEvent, PixelCopy, Surface, SurfaceHolder, SurfaceView, View, ViewGroup,
              Window, WindowManager, WindowManager$LayoutParams}
android.widget.EditText
```

What is **not** in that list — and therefore cannot happen through the injected Java code:

* **no `AccessibilityService`, `AccessibilityManager`, `AccessibilityNodeInfo`** → the #1 Android
  keylogger/password-scraper vector is not wired up. Also confirmed structurally: **no class in
  any dex extends `AccessibilityService` / `InputMethodService` / `DeviceAdminReceiver` /
  `AutofillService` / `NotificationListenerService`**, and the manifest declares none.
* **no `AccountManager`, `Authenticator`, `getAccounts`, `SigningInfo` beyond its own APK** → cannot
  enumerate or read Google/Microsoft accounts.
* **no `android.webkit.*` at all** → no WebView, so no injection into a sign-in page and no
  `addJavascriptInterface` bridge.
* **no `KeyEvent`, `InputMethodManager`, `TextWatcher`-on-foreign-fields** → no keystroke capture.
  The only text widget is `EditText` inside an `AlertDialog` the user opens deliberately, fed by
  native `pollTextRequest()` / `submitText()` (chat/command/number entry in the client menu).
* **no `TelephonyManager`, no `getDeviceId`/`getImei`/`getSubscriberId`, no `SmsManager`,
  no contacts/call-log APIs.**
* **no `MediaProjection`/`createScreenCapture`** → cannot read other apps' screens.
* **no `DexClassLoader` / `PathClassLoader` / `InMemoryDexClassLoader`** → no dynamic code loading
  in the injected layer; the native payload ships inside the APK (`lib/…/libReverseSigma.so` and
  the identical `assets/assets/icu/demo.dat`).
* **no file APIs outside its own sandbox types** (`getFilesDir`, `getDir`, SAF `openInputStream`/
  `openOutputStream` on a user-picked `Uri`, `ContentResolver.query` on that Uri).

The three things it *can* touch that matter: **the clipboard** (§5), **the game's own window
pixels** (`PixelCopy` on Minecraft's `SurfaceView`, for the blur effect), and **the two files the
ModsCraft patcher edits** (`external_servers.txt`, `options.txt`).

---

## 3. The native payload's JNI surface is six classes

Every `android/*` and `java/*` class name the `.so` can `FindClass`:

```
android/app/ActivityThread      android/content/Context     android/content/Intent
android/net/Uri                 java/net/URL                java/net/HttpURLConnection
```

`ActivityThread` + `Intent` + `Uri` sit next to a `(Landroid/content/Intent;)V` descriptor and
around the community Discord link — i.e. the plumbing to obtain a `Context` and `startActivity`
a link/chooser. `URL` + `HttpURLConnection` are the telemetry upload (§6). There is **no** class
reference to clipboard, accessibility, telephony, accounts, WebView or ContentResolver
observation from native — and native imports **zero** socket/DNS functions, so all traffic is
made through Java.

Its `/proc` access is confined to itself: `/proc/self/maps`, `/proc/self/status`,
`/proc/self/statm`, `/proc/meminfo` — memory/hook bookkeeping, not reconnaissance of the device.

---

## 4. The scary-looking hits in the *stock* code are library plumbing

Found by the sweep, and all resolved to their owner — none of it is payload code:

| Hit | Where | What it actually is |
|---|---|---|
| `MediaProjectionManager`, `AccountManager`, `DevicePolicyManager` | `classes4` | **`androidx.core.content.ContextCompat$LegacyServiceMapHolder`** — a static *map of service-name strings to class literals* used by `getSystemService`. The classes are named, never obtained or used. |
| `getPrimaryClip` | `classes2` | **`com.mojang.minecraftpe.TextInputProxyEditTextbox`** — Minecraft's own text-box paste, plus `androidx.appcompat.widget.AppCompatReceiveContentHelper`. |
| `AccessibilityNodeInfo*`, `AccessibilityServiceInfo*` | `classes`, `classes2`, `classes4` | androidx accessibility *compat* helpers (used for UI metadata, not as a service). |
| `UsernamePasswordCredentials`, `BCrypt`, cookies, `OpenJSSE`, `org.mozilla.firefox` | `classes2` | Apache HttpClient / conscrypt / jose4j **class-name registries** in the stock sign-in stack. |
| `/data/local/bin/su`, `/data/local/su`, `/data/local/xbin/su`, `/data/system/devices/keylayout/…` | `classes2` | a **root-detection** path list plus an input-device keylayout path from a stock library (App Center/Sentry). |
| `getAccountsByType`, `AudioRecord` | `libminecraftpe.so` | stock Xbox sign-in and voice chat in the real game binary. |

Also worth knowing: the *stock* app ships Firebase/DataTransport, Braze, App Center and Sentry
anyway, so there are conventional telemetry channels in this build independent of Gatyo.

---

## 5. The one capability that genuinely deserves attention: the clipboard

Traced exactly (not guessed). In `classes6.dex`, `Platform1$2.run()` — the handler runnable that
also updates the touch rectangles — does:

```
Platform2.pollIrisClipboard()      // native says: "I want the clipboard now"
  → getSystemService("clipboard")  → ClipboardManager
  → hasPrimaryClip() → getPrimaryClip() → ClipData → coerceToText()
  → Platform2.submitIrisClipboard(byte[])   // handed to native memory
```

So: **the app can read whatever is on the clipboard, whenever the native layer asks for it.** The
ask is gated (the native side has to request it, which in the shipped UI corresponds to the Iris
"NBT from clipboard" paste), and I found **no** path that writes clipboard content to a file or
into the telemetry JSON.

Why it still matters: clipboard is what password managers use for autofill, and it is what *you*
use to move a password. Anything on the clipboard while this process is running is readable by it,
and the same process owns the HTTP uploader described in §6. Capability ≠ observed behaviour, but
the two live in the same address space.

Practical mitigation if you run it anyway: never copy credentials while it's running, use a
password manager that clears the clipboard after a timeout, or disable the Iris NBT features.

---

## 6. What does leave the device (privacy, not credentials)

The "Gatyo Telemetry" uploader (§9 of the main document), proven by disassembly:

* **Destination: unknown.** Not present in plaintext/Base64/hex/reversed/XOR in the payload or the
  injected dexs; the only URLs in the binary are a Discord invite (used as a UI link — I checked
  the referencing code, it is an ImGui text/link call, not a request), an Apache licence line and
  clang/LLVM source links.
* **Transport:** `java.net.HttpURLConnection`, `POST`, multipart with `payload_json` + `files[0]`
  (`crash.txt`), `User-Agent: GatyoClient (telemetry, 1.0.0)`.
* **Content:** install id, device model/manufacturer/SoC/board, Android release+SDK, RAM/threads,
  FPS/tick timings, hook count `N/63`, active module list, crash stack scan, dump path.
* **Not included:** no account name, no Xbox/XUID/gamertag, no e-mail, no passwords, no server
  address, no clipboard. One clarification from the disassembly: the JSON key `"username"` is set
  to the literal **`"Gatyo Telemetry"`** — it is the Discord *bot display name*, not the player.
* `res/xml/network_security_config.xml` has `cleartextTrafficPermitted="true"`, so that POST can
  be plain HTTP — a real confidentiality problem, and it also weakens the whole app.

---

## 7. Other real risks (not credential theft)

1. **The app lies about its signer.** `KillerApplication` swaps `PackageInfo.CREATOR` and clears
   the package caches so `PackageManager` returns Mojang's certificate for a build actually signed
   with `CN=Android Debug` (`A7:25:AC:…`). Anything in-process that trusts a signature check is
   being deceived.
2. **It is a repackaged, debug-signed commercial app.** Updates over a Play Store install fail;
   whoever holds that debug key could ship a different build claiming to be "Gatyo".
3. **Cheat client.** Modules exist to defeat server-side checks; expect bans, and there is no
   reason to trust a cheat client's authors with anything you wouldn't hand a stranger.
4. **Unknown uploader endpoint** remains the single thing static analysis cannot clear. The app has
   a working POST channel and an unknown target; today the body is device/performance data, but
   the target is not mine to audit.

---

## 8. How to verify this yourself at runtime

```bash
# 1. watch clipboard access
frida -U -f com.mojang.minecraftpe -l - <<'EOF'
Java.perform(() => {
  const CM = Java.use('android.content.ClipboardManager');
  CM.getPrimaryClip.implementation = function () {
    console.log(new Error('getPrimaryClip').stack);
    return this.getPrimaryClip();
  };
});
EOF

# 2. catch the request URL (the UA is unique)
#    mitmproxy + user CA (config trusts user CAs only under debug-overrides — use a
#    rooted/debuggable sandbox or patch the network security config), then grep the
#    proxy log for "GatyoClient (telemetry"

# 3. confirm what the app opens
adb logcat | grep -E "Gatyo|Iris|ReverseSigma"
```

If you want, I can turn §5–§6 into a concrete runtime test plan, or write Snort/Zeek-style rules
for the `User-Agent: GatyoClient (telemetry, 1.0.0)` signature at the network edge.

---

## 9. Bottom line

| Question | Answer |
|---|---|
| Steals passwords via accessibility service? | **No** — no such service exists or is declared. |
| Keylogs? | **No** — no keyboard/IME hooks; one user-opened text dialog. |
| Reads other apps' data / Chrome saved passwords / accounts? | **No** — no such API use, no such path strings anywhere in 33,397 files. |
| SMS / contacts / call log? | **No** — no permissions, no code. |
| Screen-captures other apps? | **No** — only Minecraft's own surface, for blur. |
| Phishing overlay / WebView injection? | **No** — no overlay permission, no WebView. |
| Reads the clipboard? | **Yes** — on native request, in-process (NBT paste). Don't copy secrets while it runs. |
| Phones home? | **Yes** — device/performance telemetry (no credentials) to an **unknown** endpoint over HTTP-capable config. |
| Can be trusted as an app? | **No** — debug-signed, self-spoofing certificate, repackaged game, cheat client. |

The absence of credential theft is a real, checkable finding — but it does not make this a safe
build to install. If your goal is "is my account at risk from *this*", the honest answer is: not
through credential harvesting, but you are running an unidentified uploader with clipboard access
and a lied-about signature, and you have no way to verify future builds. Use a throwaway device,
a throwaway Microsoft account, and no real passwords.
