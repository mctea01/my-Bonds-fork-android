import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("multiplatform")
    id("com.android.library")
    kotlin("plugin.serialization")
}

kotlin {
    androidTarget { compilerOptions { jvmTarget.set(JvmTarget.JVM_17) } }
    jvm { compilerOptions { jvmTarget.set(JvmTarget.JVM_17) } }
    compilerOptions {
        optIn.add("kotlin.time.ExperimentalTime")
        optIn.add("kotlin.io.encoding.ExperimentalEncodingApi")
        freeCompilerArgs.add("-Xexpect-actual-classes")
    }
    sourceSets {
        val jvmCommonMain by creating { dependsOn(commonMain.get()) }
        androidMain.get().dependsOn(jvmCommonMain)
        jvmMain.get().dependsOn(jvmCommonMain)

        commonMain.dependencies {
            api(libs.multipaz)
            api(libs.multipaz.doctypes)
            api(libs.coroutines.core)
            api(libs.serialization.json)
            api(libs.kotlinx.io)
            api(libs.ktor.client.core)
        }
        jvmCommonMain.dependencies {
            implementation(libs.bcprov)
            implementation(libs.bcpkix)
        }
        androidMain.dependencies {
            implementation(libs.ktor.client.okhttp)
            implementation(libs.coroutines.android)
            implementation(libs.xerces.get().toString()) { exclude(group = "xml-apis") }
        }
        jvmMain.dependencies {
            implementation(libs.ktor.client.java)
            implementation(libs.sqlite.jdbc)
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.coroutines.test)
            implementation(libs.ktor.client.mock)
        }
    }
}

configurations.all {
    resolutionStrategy.eachDependency {
        if (requested.group == "org.bouncycastle") useVersion(libs.versions.bouncycastle.get())
    }
}

android {
    namespace = "diw.wallet.core"
    compileSdk = 36
    defaultConfig { minSdk = 28 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

tasks.withType<Test>().configureEach {
    jvmArgs("-Dfile.encoding=UTF-8", "-Xmx3g")
    testLogging {
        events("passed", "failed", "skipped")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        showStandardStreams = true
    }
}
