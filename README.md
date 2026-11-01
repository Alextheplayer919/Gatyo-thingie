# Gatyo-thingie

Contents
--------
* `Gatyo.7z.part_00 … part_03` — split 7z (313,204,017 bytes total) containing
  `Gatyo-1.21.111-Iris-build118.apk` (330,178,175 bytes,
  sha256 `2d985a17b9885a6e3918b8b15c9f29aae593ed8662e9356297cf5af58ab7d45f`).
  Join with `cat Gatyo.7z.part_0* > Gatyo.7z`; the joined archive's sha256 is
  `9164084f2473c42b860fe0aff9103686d703a524302e93ad7b3d7fd5d01d5fea`.
* `Gatyo_APK_Analysis.zip` — the original static-analysis package
  (report, 11 evidence files, 3 helper scripts, extracted payload binaries).
* `ANALYSIS_FULL_READTHROUGH.md` — everything in that package, read in full,
  re-verified against the actual bytes, and extended. **Start here.**
* `SECURITY_CREDENTIAL_RISK.md` — focused "does it steal passwords?" assessment
  (complete API inventory of the 98 injected classes, native JNI surface,
  clipboard finding, what does leave the device).
* `analysis/verification.json` — machine-readable verification ledger.
* `tools/` — the scripts used for the verification pass:
  * `axml.py` — dependency-free Android binary XML (manifest / res-xml) parser
  * `verify_apk.py` — hashes, dex class counts, manifest inventory, v1/v2/v3
    signature parsing, v1 digest verification, native-library facts
  * `native_string_crypto.py` — emulates the payload's rotate-XOR keystream and
    (with capstone) lists `adrp`/`add` cross-references

Summary of what this build is: a repackaged Minecraft Bedrock 1.21.111 (arm64)
APK with a debug/cheat client ("Gatyo", Iris layer credited to Gato Client)
injected from Java, loading a native payload (`libReverseSigma.so`, duplicated
as `assets/assets/icu/demo.dat`) that hook the game in memory and draw an ImGui
overlay. The APK is v1+v2+v3 signed with a generic Android debug key, and the
injected `Application` class makes `PackageManager` report Mojang's certificate
instead. Details, evidence and open questions: `ANALYSIS_FULL_READTHROUGH.md`.
