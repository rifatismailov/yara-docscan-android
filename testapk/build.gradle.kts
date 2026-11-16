// Inert test package for the APK policy: no code at all, only a manifest that asks for what an
// Android banking trojan asks for (accessibility service + SMS + overlay + device admin).
// Expected verdict: HIGH (APK_BANKER_PROFILE). Never published.
plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "yara.docscan.testapk"
    compileSdk {
        version = release(36)
    }
    defaultConfig {
        applicationId = "yara.docscan.testapk"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "test"
    }
}
