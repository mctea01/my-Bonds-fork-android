import org.jetbrains.kotlin.gradle.dsl.JvmTarget

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
        versionCode = 1
        versionName = "0.1.0-p1"
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
            isMinifyEnabled = false
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
            packageName = "DIW-MY-WALLET"
            packageVersion = "0.1.0"
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
