import org.jetbrains.compose.desktop.application.dsl.TargetFormat
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.nio.file.FileSystems
import java.nio.file.Files

plugins {
    kotlin("multiplatform")
    id("com.android.application")
    kotlin("plugin.compose")
    id("org.jetbrains.compose")
    kotlin("plugin.serialization")
}

kotlin {
    androidTarget { compilerOptions { jvmTarget.set(JvmTarget.JVM_17) } }
    jvm("desktop") { compilerOptions { jvmTarget.set(JvmTarget.JVM_21) } }
    compilerOptions {
        optIn.add("kotlin.time.ExperimentalTime")
        optIn.add("androidx.compose.material3.ExperimentalMaterial3Api")
    }
    sourceSets {
        commonMain.dependencies {
            implementation(project(":core"))
            implementation(compose.runtime)
            implementation(compose.foundation)
            implementation(compose.material3)
            implementation(compose.ui)
            implementation(libs.coroutines.core)
            implementation(libs.serialization.json)
            implementation(libs.multipaz.doctypes)
        }
        androidMain.dependencies {
            implementation(libs.multipaz.compose)
            implementation(libs.multipaz.dcapi)
            implementation(libs.androidx.activity.compose)
            implementation(libs.androidx.fragment)
            implementation(libs.androidx.browser)
            implementation(libs.androidx.credentials)
            implementation(libs.androidx.credentials.registry)
            implementation(libs.ktor.client.okhttp)
            implementation(libs.coroutines.android)
            implementation(libs.bcprov)
        }
        val desktopMain by getting {
            dependencies {
                implementation(compose.desktop.currentOs)
                implementation(libs.ktor.client.java)
                implementation(libs.coroutines.swing)
                implementation(libs.sqlite.jdbc)
                implementation(libs.bcprov)
            }
        }
        val desktopTest by getting {
            dependencies {
                implementation(kotlin("test"))
                implementation(project(":test-servers"))
                implementation(libs.ktor.server.netty)
                implementation(libs.ktor.client.java)
            }
        }
    }
}

android {
    namespace = "diw.wallet.app"
    compileSdk = 36
    defaultConfig {
        applicationId = "diw.wallet.app"
        minSdk = 29
        targetSdk = 36
        // CI passes -Pdiw.versionCode=<run> and -Pdiw.versionName so each build installs over the previous one.
        versionCode = (findProperty("diw.versionCode") as String?)?.toInt() ?: 1
        versionName = (findProperty("diw.versionName") as String?) ?: "0.1.0-p1"
    }
    signingConfigs {
        // Release key from the environment (CI secrets); see docs/release.md.
        val store = System.getenv("DIW_KEYSTORE_FILE")?.let { file(it) }?.takeIf { it.exists() }
        if (store != null) {
            create("release") {
                storeFile = store
                storePassword = System.getenv("DIW_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("DIW_KEY_ALIAS")
                keyPassword = System.getenv("DIW_KEY_PASSWORD") ?: System.getenv("DIW_KEYSTORE_PASSWORD")
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    packaging {
        resources {
            excludes += setOf(
                "META-INF/versions/9/OSGI-INF/MANIFEST.MF",
                "META-INF/{AL2.0,LGPL2.1}",
                "META-INF/INDEX.LIST",
                "META-INF/DEPENDENCIES",
                "META-INF/io.netty.versions.properties",
                "META-INF/LICENSE.md",
                "META-INF/NOTICE.md",
                "META-INF/*.kotlin_module",
            )
        }
    }
    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // Without a release key the optimized APK is signed with the debug key, so it still installs for testing.
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
        }
    }
}

configurations.all {
    resolutionStrategy {
        force("org.bouncycastle:bcprov-jdk18on:1.85", "org.bouncycastle:bcpkix-jdk18on:1.85")
    }
}

compose.desktop {
    application {
        mainClass = "diw.wallet.app.desktop.MainKt"
        nativeDistributions {
            targetFormats(TargetFormat.Msi, TargetFormat.Exe, TargetFormat.Deb, TargetFormat.Rpm)
            packageName = "DIW-MY-WALLET"
            // CI passes -Pdiw.desktopVersion=0.1.<run> so each installer upgrades the previous one.
            packageVersion = (findProperty("diw.desktopVersion") as String?) ?: "0.1.0"
            description = "DIW MY WALLET"
            vendor = "DIW MY WALLET"
            modules("java.instrument", "java.management", "java.naming", "java.net.http", "java.sql", "jdk.crypto.ec", "jdk.httpserver", "jdk.unsupported")
            windows {
                menuGroup = "DIW MY WALLET"
                upgradeUuid = "5d0f4a52-8a3e-4b8e-9f0c-6c1d2b7e3a41"
                perUserInstall = true
                shortcut = true
            }
            linux {
                shortcut = true
            }
        }
        buildTypes.release.proguard {
            configurationFiles.from(project.file("compose-desktop.pro"))
            obfuscate.set(false)
        }
    }
}

// Bouncy Castle ships as a signed jar. ProGuard rewrites its classes and the uber jar replaces its manifest, so the
// signature no longer matches and the JVM refuses to start; both outputs drop the signature files.
val jarSignatures = listOf("META-INF/*.SF", "META-INF/*.RSA", "META-INF/*.DSA", "META-INF/*.EC")
tasks.withType<Jar>().matching { it.name.contains("UberJar") }.configureEach { exclude(jarSignatures) }
val proguardOutput = layout.buildDirectory.dir("compose/tmp/main-release/proguard")
tasks.matching { it.name == "proguardReleaseJars" }.configureEach {
    doLast {
        val signature = Regex(".*\\.(SF|RSA|DSA|EC)", RegexOption.IGNORE_CASE)
        proguardOutput.get().asFile.listFiles { f -> f.extension == "jar" }?.forEach { jar ->
            FileSystems.newFileSystem(jar.toPath()).use { fs ->
                val meta = fs.getPath("META-INF")
                if (Files.isDirectory(meta)) {
                    Files.list(meta).use { s -> s.toList() }
                        .filter { signature.matches(it.fileName.toString()) }
                        .forEach { Files.delete(it) }
                }
            }
        }
    }
}

tasks.named<Test>("desktopTest") {
    useJUnitPlatform()
    jvmArgs("-Dfile.encoding=UTF-8", "-Xmx3g")
    testLogging {
        events("passed", "failed", "skipped")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
