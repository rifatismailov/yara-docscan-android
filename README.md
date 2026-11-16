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

## How it fits together

| Piece | Where |
|---|---|
| libyara + docscan, same modules as the Windows build (pe + authenticode, hash, dotnet; OpenSSL from the NDK prefab package) | `app/src/main/cpp/CMakeLists.txt` |
| JNI bridge: the docscan parts of `cli/yara.c` (`--docscan-json`, Layer-2 re-scan of VBA and parts, `--file-vars`) building the JSON into a string | `app/src/main/cpp/docscan_jni.c` |
| Rules: `docscan-project/rules` → APK assets at build time; compiled on the first start and cached (`files/rules-<version>.yarc`) | `app/build.gradle.kts`, `DocScanner.java` |
| Scanning a `content://` URI (file picker, *Share → DocScan*, *Open with → DocScan*) | `DocScanner.java`, `MainActivity.java` |
| Regression test: the 42 inert documents of `test-samples/generated` must give the verdicts of `ci/expected-verdicts.tsv` | `app/src/androidTest/.../VerdictParityTest.java` |

```sh
./gradlew :app:assembleDebug                # APK
./gradlew :app:connectedDebugAndroidTest    # parity test on a connected device
```

The JSON has the same fields as `yara64 --docscan-json`, plus `disarm_plan` (what the policy would cure).

## Not yet

- disarm (cure) through the Storage Access Framework (`docscan_disarm_plan` is already in the library)
- parsing in an `isolatedProcess` service (the Android counterpart of the Windows broker / worker sandbox)
- watching folders, sending results to a SIEM, pass 3 (critical information), rule updates without a new APK
