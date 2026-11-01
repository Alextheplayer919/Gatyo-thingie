# Gatyo (1.21.111 Iris build118) — full read-through, independent verification and consolidated findings

**Subject:** `Gatyo-1.21.111-Iris-build118.apk`, rebuilt from `Gatyo.7z.part_00…03`, plus the
`Gatyo_APK_Analysis.zip` package (`REPORT_Gatyo_APK_Analysis.txt` + 10 evidence files + 3 tools).
**Method:** static analysis only. Nothing was installed, executed or emulated as an Android app.
**Date of this pass:** 2026‑11‑01 (analysis package is dated 2026‑11‑01 as well).

This document does three things:

1. **Reads everything** in the analysis package — every section of the report, every evidence
   file, the helper scripts and the extracted binaries — and restates it in one place so nothing
   depends on opening the ZIP.
2. **Re-derives the claims from the original bytes**, so the report is not taken on trust.
   Every re-checked number is in the verification ledger (§3) and in
   [`analysis/verification.json`](analysis/verification.json).
3. **Adds what the package left out or got slightly wrong** — the v1+v2+v3 signature stack, the
   cleartext-HTTP network security config, the full manifest inventory, the ICU sibling files,
   the Discord-embed JSON that the native code builds, and an obfuscated rotate‑XOR string
   routine in the payload.

Corrections to the original report are marked **[CORRECTION]**; additions are marked **[NEW]**.

---

## 1. TL;DR

* It is a **repackaged Minecraft Bedrock 1.21.111 (arm64) APK** — same package name
  `com.mojang.minecraftpe`, same `MainActivity`, stock `libminecraftpe.so` (280,201,408 bytes,
  untouched, zero references to the payload).
* A cheat/utility client called **Gatyo** (with an "Iris" automation layer credited to
  **Gato Client**) is injected **entirely from Java**: an exported‑false `ContentProvider`,
  a swapped `Application` class and two new dex files. The game binary is not patched.
* The client itself is a **6,114,384‑byte native library** `lib/arm64-v8a/libReverseSigma.so`
  (Dear ImGui menu, ~63 inline/vtable hooks via an embedded Dobby, modules for PvP, movement,
  ESP and automation). It is shipped **twice**: as the real library and as
  `assets/assets/icu/demo.dat`, byte‑identical, used as a fallback load path.
* The APK is signed with a **generic Android debug key** (v1 + v2 + v3, all the same key,
  `A7:25:AC:5A:…:35:E8` **[NEW]**), and `KillerApplication` **makes `PackageManager` report
  Mojang's real certificate fingerprint** for the package (`31:BE:40:09:…:6F:9C`) by wrapping
  `PackageInfo.CREATOR` and clearing the package caches.
* A **telemetry uploader** exists in the payload ("Gatyo Telemetry", local copy
  `gatyo_telemetry.json`, install id `gatyo_install_id`). It posts **multipart/form-data**
  through `java.net.URL`/`HttpURLConnection` from native code. **[NEW]** the native code builds a
  JSON body with the keys `"Gatyo Telemetry"`, `"username"` and `"embeds"` and attaches a
  `crash.txt` file part — the shape of a **Discord webhook** execute‑with‑embed‑and‑file call.
* The **destination URL is still not recoverable statically**. I re‑ran every search the package
  ran, plus a full aarch64 disassembly pass: the only URLs in the binary are a Discord *invite*,
  an Apache licence line and clang/LLVM source links. **[NEW]** I did find a **rotate‑XOR
  "string" routine** (two 64‑bit keys) that initialises 120‑byte `.bss` buffers at runtime —
  deliberate obfuscation, but its output is a repeating key pattern, not a URL, so it is a
  dead/decoy path rather than the missing endpoint.
* Nothing malicious beyond the client itself was found: no `SYSTEM_ALERT_WINDOW`, no extra
  boot receivers/services/alarms, no second‑stage downloader, no account/Xbox/OAuth access, no
  screen capture of other apps. The manifest's only non‑stock additions are the replacement
  `application` class and the loader provider (plus the ModsCraft server-list patcher).
* **Using this on a multiplayer server is cheating** — the modules exist to defeat server‑side
  checks (rotations that hide the camera, "bypass phase" flight, mobEq slot packets). Bans and
  Mojang/Microsoft terms violations are the expected outcome, and updating over a Play Store
  install will fail because the signer differs.

---

## 2. Chain of custody — parts → 7z → APK → files

Everything below was recomputed in this pass.

| Step | Artifact | Size | SHA‑256 | Result |
|---|---|---|---|---|
| 1 | `Gatyo.7z.part_00…03` (4 files) | 313,204,017 B | — | concatenated in order |
| 2 | joined `Gatyo.7z` | 313,204,017 B | `9164084f2473c42b860fe0aff9103686d703a524302e93ad7b3d7fd5d01d5fea` | **matches** `evidence/01_hashes.txt` archive hash |
| 3 | `Gatyo-1.21.111-Iris-build118.apk` (single member of the 7z) | 330,178,175 B | `2d985a17b9885a6e3918b8b15c9f29aae593ed8662e9356297cf5af58ab7d45f` | **matches** `evidence/01_hashes.txt` |
| 4 | unzipped tree | 861 MB, **33,397 files**, 2,635 directories | — | matches report §2 |

The joined archive is a plain 7z (`37 7a bc af 27 1c`) whose only member is the APK, so the
"parts" are just a split, not an encrypted or nested container.

**Per-file hashes** — all 13 entries of `evidence/01_hashes.txt` reproduce exactly
(`analysis/verification.json → hash_ledger`):

| File | SHA‑256 (first 16 / full in JSON) | Note |
|---|---|---|
| `AndroidManifest.xml` | `6a2527f3 5035b46d…` | binary AXML, 22,744 B |
| `classes.dex` | `46ce0d15 71e12069…` | 8,692 classes |
| `classes2.dex` | `63776a55 12d17768…` | 8,876 classes (contains `MainActivity`) |
| `classes3.dex` | `52819d21 8978f69a…` | 158 classes |
| `classes4.dex` | `959476ee 3b317f41…` | 545 classes |
| `classes5.dex` | `9f9ea5a4 40ab66f2…` | **83 classes, all injected** (`amogus.*`, `com.modscraft.mcpepatch.*`) |
| `classes6.dex` | `816ed03a b02c2964…` | **15 classes, all injected** (`com.mojang.minecraftpe.platforms.*`) |
| `lib/arm64-v8a/libReverseSigma.so` | `ecb77981 2304c097…` | the payload |
| `assets/assets/icu/demo.dat` | `ecb77981 2304c097…` | **byte‑identical to the payload** |
| `lib/arm64-v8a/libminecraftpe.so` | `65b9a431 78a8b2cd…` | stock game, 280,201,408 B |
| `META-INF/MANIFEST.MF` | `7d1eaef6 b16ac715…` | 33,394 signed entries |
| `META-INF/ANDROIDD.SF` | `241bba8b 181a5f6e…` | signature file, non‑standard name |
| `META-INF/ANDROIDD.RSA` | `ee1bbe2f 118dfe24…` | PKCS#7, signer = Android Debug |

Class counts above are read straight from each dex header (`class_defs_size`) and are new
detail in this document **[NEW]**.

---

## 3. Verification ledger — what I re-checked and what came back

| # | Claim in the package | How I re-checked | Result |
|---|---|---|---|
| 1 | 7z/APK hashes (§2) | sha256 of joined parts, of APK, of 13 files | ✅ all match |
| 2 | 33,397 files, 6 dex, arm64‑v8a only | `os.walk` over the unzipped tree, `ls lib/` | ✅ |
| 3 | 119 "Gatyo/Gato" string hits in the payload | own regex scan of every printable run ≥5 chars, `gat[oy]`, offsets at match position | ✅ 119 hits, **identical offsets and texts**, zero differences |
| 4 | `demo.dat` byte-identical to the `.so` | sha256 both | ✅ |
| 5 | 264 postively classified hits across the APK (`evidence/07`) | re-ran the package's own scanner logic over all 33,397 files | ✅ **264 rows, same per-file counts** (238 payload, 20 Spanish/Portuguese "gato", 4 dex/manifest, 1 reversed public-suffix noise, 1 font glyph) |
| 6 | Bytecode traces `05`, `06` | re-ran `tools/dexlite.py` on the real dexs, diffed against the evidence files | ✅ **0-line diff** (both files reproduce byte-for-byte) |
| 7 | `MainActivity.onCreate` calls `Patches.patch(Context)` | traced `classes2.dex` | ✅ single call site |
| 8 | All 18 `Platform2` native methods exist in the `.so` | `readelf --dyn-syms` vs the Java declarations | ✅ 1:1, no missing/extra JNI symbol |
| 9 | Payload imports no socket/DNS code | dynsym scan (`socket|connect|send|recv|getaddrinfo|SSL_|`) | ✅ **0** network imports |
| 10 | Signer is a debug key | parsed `ANDROIDD.RSA` + the v2/v3 blocks with openssl | ✅ `CN=Android Debug`, sha256 `A7:25:AC:…`, notBefore 2026‑10‑23 |
| 11 | Embedded Mojang certificate | decoded the Base64 in `KillerApplication.<clinit>` (885 B, 5‑byte prefix) → DER | ✅ DER identical to `evidence/08b`, fp `31:BE:40:09:…:6F:9C` |
| 12 | APK is v1‑signed only | parsed the APK Signing Block | ❌ **[CORRECTION]** it is **v1 + v2 + v3**, all with the same debug cert |
| 13 | Archive integrity not checked | verified all 33,394 `SHA-256-Digest` entries of `MANIFEST.MF` against real bytes | ✅ **33,394/33,394 verified, 0 mismatches**, SF digest of the manifest ✔ |
| 14 | "No SYSTEM_ALERT_WINDOW" | parsed the manifest | ✅ 0 occurrences |
| 15 | No extra services/receivers | full component dump | ✅ (see §10 — the only new components are the payload's own) |
| 16 | Telemetry URL not present in any simple encoding | plaintext, base64, hex, reversed, XOR/shift — plus my own full-text URL extraction and aarch64 disassembly of the whole `.text` | ✅ **no URL**; only 3 http(s) strings exist (§9.4) |
| 17 | Manifest adds no extra permissions | enumerated `uses-permission` | ✅ 14 entries, all stock Minecraft/Google/Amazon ones |
| 18 | `libminecraftpe.so` has no payload references | string scan of the 280 MB library | ✅ 0 hits for `ReverseSigma`, 0 for `gatyo` |

What this means: the analysis package is **accurate and reproducible**, with one real
correction (§12) and several useful additions.

---

## 4. Identity of the artifact

| Property | Value | Source |
|---|---|---|
| Package | `com.mojang.minecraftpe` (collides with / replaces the real game) | AXML |
| versionName / versionCode | `1.21.111.1` / `952111101` | AXML |
| minSdk / targetSdk / compileSdk | 26 / 34 / 34 | AXML |
| Label | **`Gatyo`** — on `<application>` **and** on `MainActivity` | AXML string pool |
| Application class | `com.modscraft.mcpepatch.KillerApplication` (injected) | AXML |
| Main activity | `com.mojang.minecraftpe.MainActivity` (stock name) | AXML |
| Loader provider | `com.mojang.minecraftpe.platforms.Bootstrap`, `exported=false`, `authorities=com.mojang.minecraftpe.platforms.bootstrap`, `initOrder=100` | AXML |
| Files / dirs | 33,397 / 2,635 · 861 MB unpacked | tree |
| Dex | 6 files, last two **100 % injected** (83 + 15 classes) | dex headers |
| Native ABIs | **arm64‑v8a only** (7 libraries) | `lib/` |
| Signer | `C=US, O=Android, CN=Android Debug`, created 2026‑10‑23, valid to 2054 | v1/v2/v3 |
| Signature schemes | **v1 (JAR) + v2 + v3**, SHA‑256 (alg `0x103`), v3 minSdk 24 … maxSdk ∞ | **[NEW]** |

---

## 5. Location map — every place "Gatyo"/"Gato" appears, and what it does

All 33,397 files were scanned (ASCII *and* UTF‑16LE, case-insensitive). **No file name or path
contains "gato"/"gatyo".** Content hits only, in 10 files (reproduced exactly, §3 #5):

| ID | Location | What it is / does |
|---|---|---|
| **L1** | `AndroidManifest.xml` — pool entry `"Gatyo"` @0xaf6; `android:name=…KillerApplication`; `<provider …platforms.Bootstrap>` | home‑screen name; swapped Application class; loader provider created **before** `Application.onCreate`. No extra services/receivers added by the mod; **no `SYSTEM_ALERT_WINDOW`** (the overlay rides the game Activity's own `WindowManager`). |
| **L2** | `classes5.dex → com.modscraft.mcpepatch.KillerApplication.<clinit>` | (a) enables hidden‑API access via `amogus.W.b()` → `VMRuntime.setHiddenApiExemptions("Landroid/os/Parcel;","Landroid/content/pm","Landroid/app")`; (b) `AppGlobals.getInitialPackage()`; (c) builds an `android.content.pm.Signature` from the embedded Base64 **Mojang AB** cert and swaps `PackageInfo.CREATOR` for `amogus.e0`, so `PackageManager` reports Mojang's signature; (d) clears `PackageManager.sPackageInfoCache`, `Parcel.mCreators`, `Parcel.sPairedCreators`. This is a general "signature killer" patch from ModsCraft tooling, unrelated to the client's features. |
| **L3** | `classes5.dex → …mcpepatch.Patches` | Hard-coded servers `":• ModsCraft • 1.1-1.21:craft.pe:19132:1568120063"` and `":• GamePE • 1.1-1.21:gamepe.me:19132:1568120044"`; `patch(Context)` merges them into `games/com.mojang/minecraftpe/external_servers.txt` (rewriting the `^\d+` server index) and sets `has_dismissed_new_player_flow = 1` in `options.txt` (key/value map parsed and re-serialised). |
| **L4** | `classes5.dex → amogus.*` (81 of the 83 classes) | Kotlin‑stdlib fragments plus a copy of the open-source *AndroidHiddenApiBypass* technique (`sun.misc.Unsafe` + MethodHandles + `setHiddenApiExemptions`). Support code for L2, no Gatyo strings. |
| **L5** | `classes2.dex → com.mojang.minecraftpe.MainActivity.onCreate` | the **only** call from stock code into the injected code: `Lcom/modscraft/mcpepatch/Patches;->patch(Landroid/content/Context;)V`. The Gatyo loader does *not* depend on it. |
| **L6** | `classes6.dex → …platforms.Bootstrap`, `Bootstrap$1`, `Bootstrap$2` | the trigger: `onCreate()` registers `ActivityLifecycleCallbacks`; `Bootstrap$1.onActivityResumed → tryStart(activity)`; `tryStart` posts `Bootstrap$2` on the main looper; `Bootstrap$2.run()` calls `Platform1.initializeOverlay(activity)` and sets a one-shot flag. Strings here: `GatyoFileCopy`, `GatyoGlassBackdrop`, `gatyo_file_picker` (log tags / fragment tag). |
| **L7** | `classes6.dex → …platforms.Platform1 (+ $1…$6, $FilePickerFragment)` | `initializeOverlay`: `loadLib(ctx,"demo.dat")`, blur window, `Platform2` surface, two windows added through `WindowManager` (GL surface + invisible `vTouch` view forwarding `MotionEventClick(rawX,rawY)`), `startRectUpdater()` polling `getWindowRect()`/`getExtraRects()`. Also `pollTextInput()` (AlertDialog text box for native), `createBlurWindow()`/`updateBlurWindow()` (`isCrossWindowBlurEnabled`, `Window.setBackgroundBlurRadius`) for the "Liquid Glass" look, and a SAF `FilePickerFragment` (CREATE_DOCUMENT/OPEN_DOCUMENT) that copies the chosen file into app storage and returns it through `Platform2.fileResult()`. |
| **L8** | `classes6.dex → …platforms.Platform2 extends GLSurfaceView` | the JNI bridge: 18 native methods (`init`, `step`, `resize`, `imgui_Shutdown`, `MotionEventClick`, `pollFileRequest`, `fileResult`, `pollTextRequest`, `submitText`, `pollIrisClipboard`, `submitIrisClipboard`, `pollMapartClose`, `getWindowRect`, `getExtraRects`, `getBlurRadius`, `setBlurSupported`, `getGlassCaptureRate`, `submitGlassBackdrop`). `onDrawFrame → step()` draws the menu every frame; `onSurfaceCreated → init()`, `onSurfaceChanged → resize()`, `onDetachedFromWindow → imgui_Shutdown()`. |
| **L9** | `classes6.dex → …platforms.GlassBackdrop` | `PixelCopy.request` on the **game's own SurfaceView** into a `Bitmap`, pixels handed to native `submitGlassBackdrop()` (the blur backdrop). Captures the app's own window only. |
| **L10** | `lib/arm64-v8a/libReverseSigma.so` (6,114,384 B) | ***the payload*** — see §7. |
| **L11** | `assets/assets/icu/demo.dat` (6,114,384 B) | byte-identical fallback copy, disguised as ICU data (see §7.4). |
| **L12** | `META-INF/MANIFEST.MF`, `ANDROIDD.SF`, `ANDROIDD.RSA` | JAR signature; `lib/arm64-v8a/libReverseSigma.so` is listed as a signed entry. Base name `ANDROIDD` instead of `CERT`. |

---

## 6. Payload trace — how the client gets loaded and run

Confirmed at bytecode level (`evidence/06` reproduced exactly):

```
Android starts the process
   │
   ├─(1) <application android:name=com.modscraft.mcpepatch.KillerApplication>
   │       <clinit>: hidden-API bypass + Mojang signature spoof      [L2]
   │
   ├─(2) <provider …platforms.Bootstrap initOrder=100 exported=false>
   │       created before Application.onCreate;
   │       onCreate(): registerActivityLifecycleCallbacks(Bootstrap$1) [L6]
   │
   ├─(3) game Activity resumes → Bootstrap$1.onActivityResumed
   │       → Bootstrap.tryStart(activity) → Handler(main).postDelayed(Bootstrap$2)
   │
   ├─(4) Bootstrap$2.run() → Platform1.initializeOverlay(activity)     [L6→L7]
   │
   ├─(5) Platform1.loadLib(ctx, "demo.dat")
   │        try  : System.loadLibrary("ReverseSigma")
   │               → lib/arm64-v8a/libReverseSigma.so                [L10]
   │        catch: AssetManager.open("assets/icu/demo.dat")
   │               → copy to Context.getDir("lib", MODE_PRIVATE)/demo.dat
   │               → System.load(<abs path>)                          [L11]
   │
   ├─(6) JNI_OnLoad / static initialisers run (version gate:
   │       "Iris requiere Bedrock 1.21.111 arm64 y sus hooks compatibles.",
   │       "Dispatcher Iris incompatible en …")
   │
   ├─(7) the two overlay windows are added; every GL frame:
   │       Platform2.onDrawFrame → native step() → ImGui draws the menu  [L7,L8]
   │
   ├─(8) native code finds libminecraftpe.so in memory (/proc/self/maps,
   │       dl_iterate_phdr) and installs up to 63 hooks ("hooks %u/63"),
   │       inline hooks through Dobby + direct vtable-slot rewrites
   │       ("vtable no esta en una pagina de datos legible",
   │        "slot de vtable invalido", "restaurar permisos de vtable"),
   │       with hard-coded per-version offsets ("Hook Iris +0x…",
   │       "ClientInstance+0x%x")
   │
   └─(9) modules run inside the game process; menu ↔ Java services
           (file picker, text dialog, clipboard) go back out through Platform2
```

Key facts about the chain:

* `libminecraftpe.so` is **not** patched and does not list the payload as a dependency
  (no `NEEDED`, and 0 string references — re-verified).
* The two copies (`.so` and `demo.dat`) are identical: resilience/disguise.
* No services, boot receivers, alarms or accounts are added → no persistence beyond
  "the app is installed and launched".
* The only stock→injected call is `MainActivity.onCreate → Patches.patch`.

---

## 7. What the native payload contains

### 7.1 ELF facts **[NEW/confirmed]**

| Property | Value |
|---|---|
| Type | ELF64 AArch64, `DYN` (PIE shared object), `BIND_NOW`/`NOW` (full RELRO) |
| Size | 6,114,384 B; `.text` 0x299,9b0 ≈ 2.72 MB; `.rodata` 0x148,e9c |
| `NEEDED` | `liblog, libz, libandroid, libEGL, libGLESv2, libm, libdl, libc` — **no networking library** |
| Exports | `JNI_OnLoad`, `JNI_OnUnload`, 18 `Java_…_Platform2_*` (exact 1:1 match with the Java declarations), and the embedded hook engine: `DobbyHook`, `MSHookFunction`, `MSHookThumb`, `MSHookX86_64`, `A64HookFunction`, `A64HookFunctionV`, `CodePatch` |
| Imports of interest | `mprotect, mmap, dlopen, dlsym, dladdr, dl_iterate_phdr, process_vm_readv, prctl, syscall, fork, execlp, sigaction, signal, __system_property_get` |
| Network imports | **none** (0 matches for socket/connect/send/recv/getaddrinfo/SSL) |
| URL strings | exactly 3 kinds: `https://discord.gg/Hpzua3uQmV`, `http://www.apache.org/licenses/LICENSE-2.0`, clang/LLVM `android.googlesource.com` links |
| Gatyo/Gato strings | **119** (58 × `GatoClient`, 27 × `Gatyo`, 17 × `gatyo`, plus module names) |
| Branding | `"Gatyo is a client for Minecraft Bedrock 1.21.111 on Android."`, `Welcome to Gatyo` / `Bienvenido a Gatyo`, `Gatyo \| Minecraft 1.21.111 (%s)###GatyoMain`, `build: Gatyo %s #%d (%s)`, `GatyoBot`, `GatyoIntro`, `GatyoHudEditor`, `GatyoTelemetry`, `[Gatyo Liquid Glass] %s`, `/files/gatyo`, `gatyo/skybox`, `Gatyo.json`, `hud.png` |
| Credits | `Gato Client Iris port`, `Port de Iris de Gato Client`, ~25 lines "like GatoClient's …" |

### 7.2 Feature areas (from the UI strings, bilingual EN/ES)

* **Combat / PvP:** `GatoAuraX` (aura, 12–16 rotation modes, "+999 Killaura"), AutoCrystal,
  AutoTrap / SelfTrap-style traps, bed placing and exploding, FakePlayer (client-side dummy
  target), CounterRotation.
* **Movement:** `gatoFly` ("GatoClient flight", with a "bypass phase" while rising), Platform
  (block placement under/around the player).
* **Render / ESP:** AllESP, HoleESP, PopChams, PearlTracker, NoveraNametags, ShulkerPreview,
  NoRender, Ambience (sky/cloud/fog colour), CustomFov (1–359), ViewModel, DeathEffect,
  skybox images from `gatyo/skybox`, HUD image overlay.
* **World / automation:** PacketMine, AutoHotbar, PopCounter (totem pops announced in chat),
  Chat (message prefix/suffix, e.g. `" | Gatyo"`), keybind/quick-command buttons.
* **Iris layer:** auto-mapart builder (`automapart.json` projects, chest/shulker restocking,
  flight between zones), enchanting-table and grindstone windows/transactions, NBT editor and
  clipboard-NBT item spawning, "Eclipse" ping prediction ("Gatyo doesn't read your ping"),
  "Abysm's fast rots", rotation modes from "Snap" to "HvH God".

Several of these exist specifically to defeat server-side checks: rotations applied to sent
packets but not to the visible camera, slot-change (mobEq) packets, flight with a bypass phase,
and a message for "Flight blocked or corrected by the server". This is a multiplayer-advantage
client, not a mod.

### 7.3 Technical behaviours

Inline + vtable hooking (Dobby), self-inspection through `/proc/self/maps`, `/proc/self/status`,
`/proc/self/statm`, `/proc/meminfo`, `process_vm_readv`; Dear ImGui over GLES2 in an overlay;
signal handlers writing `gatyo_crash.txt` and dumps under `/data/user/0/com.mojang.minecraftpe/crash/`,
plus a shell line that copies dumps into
`/sdcard/Android/data/com.mojang.minecraftpe/files/games/com.mojang/crashdumps/` and `chmod 0664`s
them; device properties `ro.product.model`, `ro.product.manufacturer`, `ro.soc.model`,
`ro.board.platform`, `ro.arch`, `ro.build.version.release`, `ro.build.version.sdk`; a hard version
lock to Bedrock 1.21.111 arm64.

### 7.4 Why `demo.dat` is interesting **[NEW]**

`assets/assets/icu/` contains three files:

| File | Size | Header | Verdict |
|---|---|---|---|
| `full.dat` | 3,392,512 | `CmnD` + `icudt69l` | genuine ICU data |
| `partial.dat` | 2,640,272 | `CmnD` + `icudt69l` | genuine ICU data |
| `demo.dat` | 6,114,384 | `\x7fELF` | **the payload**, sitting in the same folder as real ICU data |

So the disguise is not a lone odd file but a payload parked among two legitimate ICU datasets
whose names follow the same pattern. `Platform1.loadLib` reads `assets/icu/<name>` as a generic
path, so any future drop can be renamed in place.

---

## 8. Obfuscated string routine in the payload **[NEW]**

While hunting for the telemetry endpoint I disassembled the whole `.text` (681,580
instructions) and mapped every `adrp`/`add` reference to interesting globals. That turned up a
**vectorised rotate‑XOR keystream** used to initialise two 120‑byte buffers:

* buffer `0x61d2b8` (key `0xe9cfff4b37a95fed`), buffer `0x61d234` (key `0xc177ebb56dc19985`);
* NEON code at `0x39ed78…0x39ee88` and `0x39eec0…0x39efcc`: counters 0…7 from `.rodata`
  (`0x704a0`, `0x70f40`, `0x711d0`, `0x71400`), a byte‑shuffle mask at `0x712c0`
  (`00 08 10 18 20 28 30 38 ff…`), `ushl` (shift‑right alias) of the 64‑bit key, `tbl`, `eor`;
* both buffers live in **`.bss`**, i.e. zero at load, and the "init‑once" flags guarding the
  loops are read but never written by any other code in the file.

Emulating the documented keystream (`tools/native_string_crypto.py`) reproduces the exact XOR
mask: for both keys the mask is **one repeating 8‑byte block** (the key in little‑endian), and
the resulting buffer is not printable. In other words the routine as it stands synthesises a
constant incompressible blob (the kind of thing that ends up as a multipart boundary) rather
than decoding a hidden string. **It is not the missing URL** — but it does show the author
obfuscates data at this level, which is consistent with the report's conclusion that the
endpoint is assembled at runtime.

---

## 9. Telemetry ("GatyoTelemetry")

### 9.1 What is proven

Strings (offsets in `evidence/03`/`04`):

```
0x5dfec  GatyoClient (telemetry, 1.0.0)      ← User-Agent
0x41dda  GatyoTelemetry
0x581db  Gatyo Telemetry                     ← JSON label/field value
0x4bb37  gatyo_install_id
0x5f90a  gatyo_telemetry.json
0x56b32  gatyo7f3a91c2e8d4                   ← constant used inside the JSON builder
0x4800a  Crash and performance reports       ← settings label
0x64f3b  "Sends crashes and client performance (FPS, timings, RAM, device and active
          modules) to the developer. Nothing about your account or server."  ← help text
0x6769b  Join a world to send it
0x41e31  Iris install: ABI %s, hooks %u/63, send %s
```

HTTP machinery reached from native code through JNI: `java/net/URL`, `java/net/HttpURLConnection`,
`<init>(Ljava/lang/String;)V`, `openConnection`, `setRequestMethod("POST")`, `setDoOutput`,
`setConnectTimeout`, `setReadTimeout`, `setFixedLengthStreamingMode`, `setRequestProperty`
(`User-Agent`, `Content-Type`), `getOutputStream`, `write`, `close`, `getResponseCode`,
`disconnect`.

Request shape: `multipart/form-data; boundary=…` with

* `Content-Disposition: form-data; name="payload_json"` + `Content-Type: application/json`
* `Content-Disposition: form-data; name="files[0]"; filename="…"` with `Content-Type: text/plain`
  (`text/csv` also present) and filename `crash.txt`

Content: session id, `gatyo_install_id`, device model/manufacturer/SoC/board, Android release +
SDK, RAM free/RSS, thread counts, FPS/tick statistics (`tickMaxMs`, `availMinMb`, `rssPerMinMb`,
`vmaMax`, `threadsMax`), hook count (`hooks N/63`), the active module list, a stack scan of
`minecraftpe`/client frames and a crash-dump path (`dump path:`, `terminated in crash`). A local
copy is kept in `gatyo_telemetry.json`.

### 9.2 New: the JSON body is a Discord embed **[NEW]**

Disassembling the two callers of the upload / multipart builder shows the body being assembled as:

```
outer JSON object
  "username" : …                 (key string @0x640b0)
  "embeds"   : [ { "title": "Gatyo Telemetry" (@0x581db), … } ]   (key string @0x4085b)
attachment part: files[0] filename "crash.txt" (@0x6b4fa), text/plain
```

Combined with `payload_json` + `files[0]` multipart layout, the `text/plain` attachment and the
Discord invite in the UI, the "Discord webhook" reading moves from *plausible* (report: medium
confidence) to **strongly indicated** — a Discord webhook `execute` call with an embed and one
attached file is exactly this shape. It is still an inference: any compatible endpoint would
accept the same body.

Note on the `"username"` key: the value stored into it is the literal string `"Gatyo Telemetry"`
(it is loaded immediately before the key lookup), i.e. it is the Discord *bot display name*, not
the player's account name. See `SECURITY_CREDENTIAL_RISK.md` for the full credential-theft
assessment.

### 9.3 What is not determined

* **Destination URL.** Not in plaintext, Base64, hex, reversed, XOR/shift in the payload, the
  injected dexs or the manifest (re-run in this pass), and not referenced by any `adrp`+`add`
  from `.text`. The only URLs in the library are a Discord invite, an Apache licence line and
  clang/LLVM source links.
* **Default on/off state.** The UI presents it as a setting ("Crash and performance reports");
  the default is not readable from strings.
* Purpose of the constant `gatyo7f3a91c2e8d4` — it is used inside the JSON builder (loaded
  verbatim as a quoted value in the same routine), i.e. a fixed field/key value rather than a
  salt, but its role is not proven.

### 9.4 How to obtain the endpoint (unchanged recommendation)

1. Run in an isolated device/emulator with a proxy: mitmproxy + user CA (**the app's
   `network_security_config` trusts user CAs under `debug-overrides` only, so use a
   debuggable/rooted sandbox or patch the config**) and capture while the telemetry toggle is on
   and a world is joined.
2. Hook `java.net.URL.<init>` (Frida/`Platform2`-style JNI hook) and read the first argument;
   the payload's own code path is `0x39f624` (upload) ← `0x39ea18` (multipart body builder) ←
   `0x39a8f0` / `0x39d3a4` (crash / session report).
3. Or watch for the file `gatyo_telemetry.json` and the `User-Agent: GatyoClient (telemetry, 1.0.0)`
   in outbound traffic — the UA is unique enough to grep at the network edge.

### 9.5 Not observed (confirmed absence, in static data)

Xbox/Microsoft/XUID/gamertag, OAuth/bearer/token/password/login, `AccountManager`,
`TelephonyManager`, `ANDROID_ID`, IMEI, contacts, SMS — none. The only "cookie" is a Minecraft
item name and "clipboard" belongs to the NBT-paste feature. No remote code download, no
second-stage loader, no capture of other apps' screens. (Absence of strings does not prove
absence of behaviour in packed/encrypted regions.)

Note for context **[NEW]**: the *stock* app already ships Firebase/DataTransport, Braze,
App Center, Sentry ANR metadata and billing — so third-party telemetry channels exist in this
build independently of Gatyo's.

---

## 10. Manifest deep dive **[NEW]**

Parsed with `tools/axml.py` (binary AXML, no aapt needed).

**Permissions (14 `uses-permission` elements, 14 unique):**

```
android.permission.INTERNET                            android.permission.ACCESS_NETWORK_STATE
android.permission.ACCESS_WIFI_STATE                   android.permission.CHANGE_WIFI_MULTICAST_STATE
android.permission.WAKE_LOCK                           android.permission.VIBRATE
android.permission.POST_NOTIFICATIONS                  android.permission.READ_MEDIA_IMAGES
android.permission.WRITE_EXTERNAL_STORAGE              android.permission.FOREGROUND_SERVICE
com.android.vending.CHECK_LICENSE                      com.android.vending.BILLING
com.google.android.c2dm.permission.RECEIVE             com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE
```

No `SYSTEM_ALERT_WINDOW` (0 occurrences) — consistent with the overlay being attached through the
Activity's own `WindowManager` rather than as a system overlay.

**Components (25):**

| Kind | Name | exported | notes |
|---|---|---|---|
| provider | `com.mojang.minecraftpe.platforms.Bootstrap` | false | **payload loader**, `initOrder=100`, authorities `com.mojang.minecraftpe.platforms.bootstrap` |
| activity | `com.mojang.minecraftpe.MainActivity` | true | label `Gatyo`, `hasFragileUserData`, `requestLegacyExternalStorage`, `preserveLegacyExternalStorage` |
| service | `com.mojang.minecraftpe.ImportService` | **true** | stock Minecraft service, no permission guard (pre-existing attack surface) |
| service | `com.mojang.minecraftpe.NotificationListenerService` | false | stock |
| provider | `androidx.core.content.FileProvider` | false | `com.mojang.minecraftpe.fileprovider` |
| provider | `com.google.firebase.provider.FirebaseInitProvider`, `androidx.startup.InitializationProvider` | false | library init |
| activity ×10 | `com.microsoft.xal.browser.*`, `com.android.billingclient.api.ProxyBillingActivity(V2)`, `com.braze.ui.*`, `com.braze.push.NotificationTrampolineActivity`, `com.google.android.gms.common.api.GoogleApiActivity` | 1 true (`IntentHandler`), rest false | stock libraries |
| receiver ×4 | `com.amazon.device.iap.ResponseReceiver` (true), `FirebaseInstanceIdReceiver` (true, `c2dm.permission.SEND`), `BrazePushReceiver`, `datatransport…AlarmManagerSchedulerBroadcastReceiver` | | stock libraries |
| service ×4 | FirebaseMessaging / ComponentDiscovery / TransportBackendDiscovery / JobInfoScheduler (`BIND_JOB_SERVICE`) | false | stock libraries |

**`res/xml/network_security_config.xml`** (referenced by `android:networkSecurityConfig`):

```xml
<network-security-config>
  <base-config cleartextTrafficPermitted="true">
    <trust-anchors><certificates src="system"/></trust-anchors>
  </base-config>
  <debug-overrides>
    <trust-anchors><certificates src="user"/></trust-anchors>
  </debug-overrides>
</network-security-config>
```

`cleartextTrafficPermitted="true"` means plain **HTTP** is allowed app-wide — consistent with a
native telemetry uploader that would otherwise be silently blocked on Android 9+, and worth
noting because it also weakens the app generally.

`application` attributes of note: `networkSecurityConfig`, `appComponentFactory=androidx.core.app.CoreComponentFactory`,
`appCategory=0`, `hasFragileUserData=true`, `requestLegacyExternalStorage=true`,
`preserveLegacyExternalStorage=true`.

---

## 11. Files the client creates / uses on the device

```
/data/data/com.mojang.minecraftpe/app_lib/demo.dat      fallback payload copy (L11)
<app files>/gatyo/                                      client folder ("/files/gatyo")
<app files>/gatyo/Gatyo.json                            config
<app files>/gatyo/hud.png | hud.jpg                     user HUD image
<app files>/gatyo/skybox/                               user skybox images
<app files>/gatyo/gatyo_telemetry.json                  local telemetry record
<app files>/gatyo/gatyo_install_id                      install identifier
<app files>/gatyo/gatyo_crash.txt                       crash text
/automapart.json                                        mapart project/state
/data/user/0/com.mojang.minecraftpe/crash/<name>        crash dumps
/sdcard/Android/data/com.mojang.minecraftpe/files/games/com.mojang/crashdumps/   dumps copied here (cp + chmod 0664)
games/com.mojang/minecraftpe/external_servers.txt       servers added by Patches (L3)
games/com.mojang/minecraftpe/options.txt                has_dismissed_new_player_flow=1 (L3)
```

---

## 12. Signing and integrity **[CORRECTION + NEW]**

* **Real signer of all three schemes:** `C=US, O=Android, CN=Android Debug`,
  `notBefore=2026-10-23 07:02:03Z`, `notAfter=2054-03-10`, SHA‑256
  `A7:25:AC:5A:CA:FC:03:29:FC:6A:CD:3C:C7:3F:D6:A0:95:CD:A4:31:66:7D:2F:69:B8:BC:D3:9D:65:AF:35:E8`.
* **[CORRECTION]** the package described only the JAR signature (`ANDROIDD.RSA`). The APK also
  carries a proper **APK Signing Block** (`APK Sig Block 42`, 4,088 B) with **v2** and **v3**
  signers (both SHA‑256, alg `0x103`) plus 1,132 B of verity padding, and both point at the same
  debug certificate (`a725ac5a…`). v3 declares `minSdk=24`, `maxSdk=2147483647`. No rotation
  lineage, no source-stamp block.
* **Archive integrity:** all **33,394** `SHA-256-Digest` entries in `META-INF/MANIFEST.MF`
  verify against the actual entry bytes (0 mismatches), and `ANDROIDD.SF`'s
  `SHA-256-Digest-Manifest` matches the manifest. So no file was swapped after signing — the
  payload is what was signed, by the debug key.
  *(Two entry names contain spaces, e.g. `…Achievements Animated-06cb….gif`, and are split with a
  72-byte continuation line; naive parsers mis-read them as missing — verified present.)*
* **Spoofed signer:** `KillerApplication` embeds Mojang AB's certificate (DER SHA‑256
  `31:BE:40:09:6F:93:1C:D7:F1:1D:5E:26:2D:2B:2C:43:7C:44:38:5F:B4:EC:BC:10:13:D9:5A:74:35:81:6F:9C`,
  identical to `evidence/08b_embedded_mojang_cert.pem`) and makes `PackageManager` report it.
* Implications: not an official Mojang/Play build; updating over a Play Store install fails
  (different signer); anything trusting `PackageManager` signatures inside this process is lied
  to by design.

---

## 13. Hits that are *not* Gatyo/Gato references (ruled out)

| Where | Text | Why it is noise |
|---|---|---|
| `assets/…/resource_packs/vanilla/texts/{es_ES,es_MX,pt_BR,pt_PT}.lang` (5 hits each) | `Gato`, `gatos` | Spanish/Portuguese for "cat" (`entity.cat.name`, record desc) |
| `assets/…/hbui/fonts/NotoSansMerged-Regular-*.ttf` | `gatouchsinh` | glyph-name table substring |
| `classes2.dex` @0x378f8b | reversed public-suffix list containing `gatop` | data noise |
| everywhere | `navigation`, `delegation`, `obligation`, … | naive `gat?o` matching |

The full raw table with a classification column is `evidence/07_all_apk_hits_raw.tsv`
(264 rows; reproduced exactly in this pass).

---

## 14. Limits of this analysis, and what is still open

1. **Static only.** No dynamic run, no Frida, no network capture. Behaviour in §7–§9 is derived
   from strings, imports/exports, parsed bytecode and targeted disassembly — the `.text`
   section was disassembled wholesale for cross-references and the telemetry/string paths were
   read function-by-function, but not every one of the ~30k functions was reviewed.
2. **No stock 1.21.111 APK to diff against**, so "vanilla assets/classes are unchanged" is
   assumed, not proven. (`libminecraftpe.so` shows no payload references, and its hash is
   recorded, so it can be compared later.)
3. **Telemetry destination and default state: still unknown** (§9.3). This is the one substantive
   gap; the suggested dynamic method is in §9.4.
4. **Strings can be absent for encrypted/packed data** — "not observed" ≠ "does not exist". The
   rotate‑XOR routine in §8 shows the author does obfuscate data; the *uploader* itself was read
   in detail and does not decrypt anything before the request, so the endpoint most likely
   arrives from a runtime-initialised global or the Java side, not from a decoder I missed.
5. Exact `postDelayed` delay and the exact fallback filename (`demo.dat` is the string passed to
   `loadLib`) come from code structure, not observation.

---

## 15. Handling notes

* This is a **modified, debug-signed copy of a paid game plus a cheat client**. Installing it
  replaces/conflicts with the real app; it exists to gain multiplayer advantage and defeats
  server-side checks by design.
* Using it on any server breaks that server's rules and Minecraft's terms; bans are the normal
  outcome. Distributing a repackaged Mojang APK is also a copyright problem.
* The signature-spoofing code and the loader provider are generic "pirate client" tooling
  ("ModsCraft mcpepatch"), not specific to Gatyo — treat them as indicators for other builds
  signed by the same people.
* If you must handle it, do it in a disposable emulator without a real Microsoft/Xbox account and
  without a Play/Amazon login, and capture traffic at the edge rather than trusting the app.

---

## Appendix A — reproduce this pass

```bash
# 1. join parts and check hashes
cat Gatyo.7z.part_0* > /tmp/Gatyo.7z
sha256sum /tmp/Gatyo.7z            # 9164084f…d5fea

# 2. unpack (py7zr is the only non-stdlib dependency, no system 7z needed)
python3 -m pip install --user py7zr
python3 -c "import py7zr;py7zr.SevenZipFile('/tmp/Gatyo.7z').extractall('/tmp/apkout')"
sha256sum /tmp/apkout/*.apk        # 2d985a17…d45f

# 3. unzip and run the verifier (produces the JSON ledger)
mkdir -p /tmp/apk && (cd /tmp/apk && unzip -q /tmp/apkout/*.apk)
python3 tools/verify_apk.py --apk /tmp/apkout/*.apk --tree /tmp/apk --json analysis/verification.json

# 4. inspect the manifest and the network config
python3 tools/axml.py /tmp/apk/AndroidManifest.xml
python3 tools/axml.py /tmp/apk/res/xml/network_security_config.xml

# 5. reproduce the bytecode traces of the analysis package
python3 <package>/tools/dexlite.py /tmp/apk/classes5.dex mcpepatch   # ≈ evidence/05
python3 <package>/tools/dexlite.py /tmp/apk/classes6.dex platforms    # ≈ evidence/06

# 6. native: keys/keystream, and where the telemetry strings are referenced
python3 -m pip install --user capstone
python3 tools/native_string_crypto.py /tmp/apk/lib/arm64-v8a/libReverseSigma.so \
        --xref 0x61d2b8 0x5dfec 0x5dfc7 0x65747
```

`analysis/verification.json` is the machine-readable result of step 3 (hashes, class counts,
manifest inventory, signature schemes, v1 digest verification, native facts).

---

## Appendix B — what was inside `Gatyo_APK_Analysis.zip` (25 files, 33.4 MB)

| File | Size | Read in this pass | Purpose |
|---|---|---|---|
| `README.txt` | 518 B | ✔ | points at report §3/§4/§6 |
| `REPORT_Gatyo_APK_Analysis.txt` | 29,388 B | ✔ (all 11 sections) | the analysis itself |
| `evidence/01_hashes.txt` | 1,382 B | ✔ | 13 file hashes + 2 archive hashes |
| `evidence/02_libReverseSigma_elf_imports_exports.txt` | 4,086 B | ✔ | NEEDED libs, JNI/hook exports, all imports |
| `evidence/03_libReverseSigma_gatyo_gato_hits.tsv` | 7,765 B | ✔ (119 rows, re-derived) | every hit + offset |
| `evidence/04_libReverseSigma_all_strings.txt` | 428,478 B | ✔ (25,048 lines) | full string dump, no offsets |
| `evidence/05_dex_trace_classes5_mcpepatch.txt` | 15,191 B | ✔ (reproduced, 0 diff) | bytecode of KillerApplication, Patches, amogus |
| `evidence/06_dex_trace_classes6_platforms.txt` | 42,023 B | ✔ (reproduced, 0 diff) | bytecode of Bootstrap, Platform1/2, GlassBackdrop |
| `evidence/07_all_apk_hits_raw.tsv` | 30,663 B | ✔ (264 rows, re-derived) | every APK hit + classification |
| `evidence/08_signing_certs.txt` | 804 B | ✔ | real signer vs spoofed Mojang cert |
| `evidence/08b_embedded_mojang_cert.pem` | 1,249 B | ✔ (DER identical to the dex copy) | the embedded cert |
| `evidence/09_telemetry_webhook_evidence.txt` | 5,387 B | ✔ | webhook-format evidence, negative searches (F sections) |
| `extracted/AndroidManifest.xml` | 22,744 B | ✔ (hash match) | binary manifest |
| `extracted/classes2.dex` | 10,300,688 B | ✔ | stock dex containing MainActivity |
| `extracted/classes5.dex` | 40,060 B | ✔ | injected: 83 classes |
| `extracted/classes6.dex` | 25,680 B | ✔ | injected: 15 classes |
| `extracted/lib/arm64-v8a/libReverseSigma.so` | 6,114,384 B | ✔ | payload |
| `extracted/assets/icu/demo.dat` | 6,114,384 B | ✔ | identical copy |
| `extracted/META-INF/{MANIFEST.MF,ANDROIDD.SF,ANDROIDD.RSA}` | 5.09 MB / 5.09 MB / 1,223 B | ✔ | v1 signature |
| `extracted/README_extracted.txt` | 798 B | ✔ | what was extracted and what was left out |
| `tools/dexlite.py` | 4,606 B | ✔ (re-run) | minimal DEX parser used for the traces |
| `tools/extract_7z_via_libarchive.py` | 1,741 B | ✔ | ctypes/libarchive 7z extractor (this pass used py7zr instead) |
| `tools/scan_gato_gatyo.py` | 1,082 B | ✔ (re-run, same 264 rows) | ASCII + UTF-16LE scanner |

Not in the package (by design): the full APK and the stock `libminecraftpe.so`. Both are
reproducible from the four parts in this repository, and their hashes are in `evidence/01`.

---

## Appendix C — tooling added in this pass

| File | What it does |
|---|---|
| `tools/axml.py` | dependency-free Android binary XML parser (manifest + `res/xml`) |
| `tools/verify_apk.py` | recomputes hashes, dex class counts, manifest inventory, signature schemes (v1 digest verification + v2/v3 parse), and native facts → JSON ledger |
| `tools/native_string_crypto.py` | emulates the payload's rotate‑XOR keystream (both keys) and, with capstone, lists `adrp`/`add` cross-references to any address |
| `analysis/verification.json` | the ledger produced by `verify_apk.py` |
