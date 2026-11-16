# YARA DocScan for Android

Android port of [yara-docscan](https://github.com/rifatismailov/yara-docscan): the same `docscan` YARA
module, the same policy and vendor rules, the same JSON verdict — on the phone.

The C sources are **not copied**: `yara-docscan/` is a git submodule, built with the NDK into
`libyaradocscan.so`. A fix in the PC version reaches Android with a submodule bump.

```sh
git clone --recurse-submodules https://github.com/rifatismailov/yara-docscan-android.git
# or, in an existing clone:
git submodule update --init
```

## What it does

- **Watcher** (the Android `docscan-watcher.ps1`): a foreground service watches the whole shared storage
  (inotify per directory + MediaStore as a second signal), scans every new or changed document, archive,
  script and APK, **cures documents in place** per `meta.disarm` (backup first) and quarantines what cannot
  be cured. A catch-up sweep on every start picks up what arrived while it was not running.
- **Sandbox**: the hostile file is parsed only in `IsolatedScanService` (`android:isolatedProcess`, no
  permissions, no file access, descriptors only) - the Windows broker / worker split. A parser crash marks
  the file ERROR; the watcher goes on.
- **Android packages**: APK files and every installed (non-system) app - manifest policy (accessibility
  service + SMS / overlay / device admin = banker profile, impersonation of an installed app with another
  signing key, malformed manifest, ...) plus vendor YARA rules over `classes*.dex` (`dex` module).
- **Device security**: screen lock, patch level, encryption, third-party accessibility services /
  notification listeners / device admins, unknown sources, USB debugging, root. Turning on an accessibility
  service, notification access or device admin for a third-party app alerts at once.
- **Results**: `files/results/docscan-results.json` - one JSON line per file / app / device change, the
  fields of the PC watcher (`timestamp, source, host, event, category, docfile, verdict, docscan,
  yara_file_matches, disarm, summary, errors`) plus `platform`, `apk`, `android_findings`.

Distribution: APK / MDM (uses `MANAGE_EXTERNAL_STORAGE` and `QUERY_ALL_PACKAGES`). On Meizu, Xiaomi,
Huawei & co. allow DocScan autostart, otherwise the firmware drops the boot / update broadcasts.

## How it fits together

| Piece | Where |
|---|---|
| libyara + docscan, same modules as the Windows build (pe + authenticode, hash, dotnet; OpenSSL from the NDK prefab package) | `app/src/main/cpp/CMakeLists.txt` |
| JNI bridge: the docscan parts of `cli/yara.c` (`--docscan-json`, Layer-2 re-scan of VBA and parts, `--file-vars`) building the JSON into a string | `app/src/main/cpp/docscan_jni.c` |
| Rules: `docscan-project/rules` → APK assets at build time; compiled on the first start and cached (`files/rules-<version>.yarc`) | `app/build.gradle.kts`, `DocScanner.java` |
| Scanning a `content://` URI (file picker, *Share → DocScan*, *Open with → DocScan*) | `DocScanner.java`, `MainActivity.java` |
| Sandboxed worker, disarm plan / apply, quarantine | `scan/IsolatedScanService.java`, `scan/Disarm.java`, `scan/Quarantine.java` |
| Watcher: service, observers, queue (settle 2 s, cooldown 60 s), pipeline, verdict merging + summary (Scan-File / Get-Summary) | `watch/*` |
| APK policy, device security | `apk/*`, `device/*` |
| Regression tests: verdicts and cures of the 42 inert documents must match `ci/expected-verdicts.tsv` | `VerdictParityTest`, `DisarmParityTest` |
| JVM tests: file filter, verdict merging, APK policy | `app/src/test/...` |
| Inert test package with a banker-profile manifest (no code) - expected HIGH | `testapk/` |

```sh
./gradlew :app:assembleDebug                # APK
./gradlew :app:testDebugUnitTest            # JVM tests
./gradlew :app:connectedDebugAndroidTest    # parity tests on a connected device
```

The JSON has the same fields as `yara64 --docscan-json`, plus `disarm_plan` (what the policy would cure).

## Not yet

- sending the results to the SIEM (Wazuh / collector over HTTPS), pass 3 (critical information)
- rule updates without a new APK; vendor YARA rules for Android malware (through `build_vendor_rules.py`)
- `ARCHIVE_*` policy rules ignore APKs on the Android side only - a `not APK` condition belongs upstream
