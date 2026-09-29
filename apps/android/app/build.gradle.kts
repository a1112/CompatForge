plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "dev.compatforge.android"
    compileSdk = 36
    ndkVersion = "30.0.14904198"

    defaultConfig {
        applicationId = "dev.compatforge.android"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0-dev"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk {
            abiFilters += "arm64-v8a"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
        }
    }

    packaging {
        jniLibs.useLegacyPackaging = true
    }

    sourceSets.getByName("main").jniLibs.srcDir(layout.buildDirectory.dir("generated/rust-jni"))
    sourceSets.getByName("androidTest").assets.srcDir(layout.buildDirectory.dir("generated/acceptance-assets"))
}

val repositoryRoot = rootProject.projectDir.resolve("../..").canonicalFile
val androidNdk = android.sdkDirectory.resolve("ndk/${android.ndkVersion}")
val ndkToolchain = androidNdk.resolve(
    if (System.getProperty("os.name").startsWith("Windows"))
        "toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android26-clang.cmd"
    else
        "toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang"
)

val buildRustArm64 by tasks.registering(Exec::class) {
    workingDir = repositoryRoot
    environment("CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER", ndkToolchain.absolutePath)
    commandLine("cargo", "build", "-p", "compatforge-ffi", "--target", "aarch64-linux-android", "--locked")
}

val stageRustArm64 by tasks.registering(Copy::class) {
    dependsOn(buildRustArm64)
    from(repositoryRoot.resolve("target/aarch64-linux-android/debug/libcompatforge_ffi.so"))
    into(layout.buildDirectory.dir("generated/rust-jni/arm64-v8a"))
}

val packagedExecProbe = layout.buildDirectory.file("generated/rust-jni/arm64-v8a/libcompatforge_exec_probe.so")
val buildPackagedExecProbe by tasks.registering(Exec::class) {
    val source = file("src/main/cpp/exec_probe.c")
    inputs.file(source)
    outputs.file(packagedExecProbe)
    doFirst { packagedExecProbe.get().asFile.parentFile.mkdirs() }
    commandLine(
        ndkToolchain.absolutePath,
        "-fPIE", "-pie", "-Wl,-z,max-page-size=16384",
        "-o", packagedExecProbe.get().asFile.absolutePath,
        source.absolutePath,
    )
}

tasks.matching {
    it.name.startsWith("merge") &&
        (it.name.endsWith("NativeLibs") || it.name.endsWith("JniLibFolders"))
}.configureEach {
    dependsOn(stageRustArm64, buildPackagedExecProbe)
}

val sevenZipFixture = providers.gradleProperty("compatforgeSevenZip").orNull
val stageSevenZipFixture by tasks.registering(Sync::class) {
    if (sevenZipFixture != null) {
        from(sevenZipFixture)
        rename { "7z2601-x64.exe" }
    }
    into(layout.buildDirectory.dir("generated/acceptance-assets"))
}

tasks.matching { it.name.startsWith("merge") && it.name.endsWith("AndroidTestAssets") }.configureEach {
    dependsOn(stageSevenZipFixture)
}

dependencies {
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("junit:junit:4.13.2")
}
