import javax.inject.Inject


plugins {
    alias(libs.plugins.android.application)
}

// The YARA + DocScan fork lives in the git submodule; rules and test samples come from there.
val docscanRoot = rootProject.file("yara-docscan/docscan-project")

/** Copies files from the submodule into a generated assets directory (wired in via androidComponents). */
abstract class CopyDocscanAssets : DefaultTask() {
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val sources: ConfigurableFileCollection

    @get:Input
    abstract val mapping: MapProperty<String, String>   // source path -> target subdir

    @get:Inject
    abstract val fs: FileSystemOperations

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun copy() {
        fs.sync {
            into(outputDir)
            mapping.get().forEach { (src, dst) ->
                from(src) {
                    into(dst)
                    exclude("tools/**")       // rule generator scripts are not needed on the device
                }
            }
        }
    }
}

// Rules -> assets/rules
val copyRules by tasks.registering(CopyDocscanAssets::class) {
    val rules = File(docscanRoot, "rules")
    sources.from(rules)
    mapping.put(rules.path, "rules")
}

// Test documents + expected verdicts -> androidTest assets (regression test against the PC version)
val copyTestSamples by tasks.registering(CopyDocscanAssets::class) {
    val samples = File(docscanRoot, "test-samples/generated")
    val expected = File(docscanRoot, "ci/expected-verdicts.tsv")
    sources.from(samples, expected)
    mapping.put(samples.path, "samples")
    mapping.put(expected.path, ".")
}

androidComponents {
    onVariants { variant ->
        variant.sources.assets?.addGeneratedSourceDirectory(copyRules, CopyDocscanAssets::outputDir)
        variant.androidTest?.sources?.assets
            ?.addGeneratedSourceDirectory(copyTestSamples, CopyDocscanAssets::outputDir)
    }
}

android {
    namespace = "yara.docscan.android"
    compileSdk {
        version = release(36)
    }

    defaultConfig {
        applicationId = "yara.docscan.android"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    buildFeatures {
        prefab = true   // OpenSSL (libcrypto) for pe.imphash, pe.signatures and the hash module
        aidl = true     // IScanWorker: the sandboxed scan worker
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    defaultConfig.externalNativeBuild.cmake {
        arguments += "-DANDROID_STL=c++_shared"   // the OpenSSL prefab package is built against it
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

dependencies {
    implementation(libs.appcompat)
    implementation(libs.material)
    implementation(libs.openssl)
    testImplementation(libs.junit)
    androidTestImplementation(libs.ext.junit)
    androidTestImplementation(libs.espresso.core)
}
