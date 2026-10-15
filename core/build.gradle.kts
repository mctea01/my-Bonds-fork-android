import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("multiplatform")
    id("com.android.library")
    kotlin("plugin.serialization")
}

/**
 * The DOM interfaces Xerces implements that Android does not ship (DOM events, ranges, traversal, views, HTML, CSS,
 * ElementTraversal, StAX). Only classes absent from android.jar are taken from xml-apis, so nothing shadows the
 * platform's own javax.xml and org.w3c.dom classes.
 */
val xmlApis: Configuration by configurations.creating { isTransitive = false }
dependencies { xmlApis(libs.xml.apis) }
val androidDomExtras by tasks.registering(Jar::class) {
    archiveFileName.set("android-dom-extras.jar")
    destinationDirectory.set(layout.buildDirectory.dir("android-dom"))
    from({ xmlApis.map { zipTree(it) } }) {
        include(
            "org/w3c/dom/ElementTraversal.class",
            "org/w3c/dom/bootstrap/**", "org/w3c/dom/css/**", "org/w3c/dom/events/**", "org/w3c/dom/html/**",
            "org/w3c/dom/ranges/**", "org/w3c/dom/stylesheets/**", "org/w3c/dom/traversal/**", "org/w3c/dom/views/**",
            "org/w3c/dom/xpath/**",
            "org/w3c/dom/ls/LSLoadEvent.class", "org/w3c/dom/ls/LSProgressEvent.class", "org/w3c/dom/ls/LSSerializerFilter.class",
            "javax/xml/stream/**", "javax/xml/transform/stax/**",
        )
    }
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
            implementation(files(androidDomExtras))
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
