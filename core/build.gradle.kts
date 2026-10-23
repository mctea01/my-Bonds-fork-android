import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("multiplatform")
    id("com.android.library")
    kotlin("plugin.serialization")
}

/**
 * How the ZK native library (native/build.sh) is built. "auto" (default) builds it when bash and cargo are installed
 * and otherwise leaves it out, so ZkNative reports zero-knowledge proofs as unavailable; "require" always builds and
 * fails without the tools (release CI); "skip" never builds. Set with -Pdiw.zkNative or DIW_ZK_NATIVE.
 */
val zkNativeMode = providers.gradleProperty("diw.zkNative").orElse(providers.environmentVariable("DIW_ZK_NATIVE"))
    .getOrElse("auto").also { require(it in setOf("auto", "require", "skip")) { "diw.zkNative must be auto, require or skip" } }

/** Optional native proof backends passed to native/build.sh: empty (runtime only) or a comma list of openac and tlsn. Set with -Pdiw.zkFeatures or DIW_ZK_FEATURES. */
val zkFeatures = providers.gradleProperty("diw.zkFeatures").orElse(providers.environmentVariable("DIW_ZK_FEATURES"))
    .getOrElse("").also { f ->
        require(f.isEmpty() || f.split(',').let { l -> l.all { it in setOf("openac", "tlsn") } && l.toSet().size == l.size }) {
            "diw.zkFeatures must be empty or a comma list of openac and tlsn"
        }
    }

/** Git for Windows' bash: a plain "bash" on Windows starts WSL, which usually has no distribution installed. */
val zkBash: String? = if (!System.getProperty("os.name").startsWith("Windows")) "bash" else
    listOfNotNull(System.getenv("ProgramFiles"), System.getenv("ProgramW6432"))
        .map { File(it, "Git/bin/bash.exe") }.firstOrNull { it.isFile }?.path

fun zkCommandSucceeds(vararg command: String): Boolean = runCatching {
    val process = ProcessBuilder(*command).directory(rootDir).redirectErrorStream(true).start()
    process.inputStream.readBytes()
    process.waitFor() == 0
}.getOrDefault(false)

val buildZkDesktop by tasks.registering(Exec::class) {
    workingDir(rootProject.projectDir)
    commandLine(zkBash ?: "bash", "native/build.sh", "host")
    environment("DIW_ZK_FEATURES", zkFeatures)
    inputs.property("zkFeatures", zkFeatures)
    inputs.files(rootProject.fileTree("native") { exclude("target/**", "dist/**") })
    outputs.dir(rootProject.layout.projectDirectory.dir("native/dist/resources"))
    onlyIf("the Rust toolchain is installed, or diw.zkNative=require") {
        when (zkNativeMode) {
            "require" -> true
            "skip" -> false
            else -> (zkBash != null && zkCommandSucceeds("cargo", "--version")).also {
                if (!it) logger.warn("ZK native library not built: bash or cargo not found (-Pdiw.zkNative=require fails instead)")
            }
        }
    }
}
val zkAssetResources by tasks.registering {
    val source = rootProject.file("native/assets.json")
    val destination = layout.buildDirectory.dir("generated/zkAssets")
    inputs.file(source)
    outputs.dir(destination)
    doLast {
        // Keep the pinned bytes identical on Windows checkouts with CRLF conversion.
        destination.get().file("zk/assets.json").asFile.apply {
            parentFile.mkdirs()
            writeText(source.readText().replace("\r\n", "\n"))
        }
    }
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
    jvm { compilerOptions { jvmTarget.set(JvmTarget.JVM_21) } }
    compilerOptions {
        optIn.add("kotlin.time.ExperimentalTime")
        optIn.add("kotlin.io.encoding.ExperimentalEncodingApi")
        freeCompilerArgs.add("-Xexpect-actual-classes")
    }
    sourceSets {
        val jvmCommonMain by creating { dependsOn(commonMain.get()) }
        androidMain.get().dependsOn(jvmCommonMain)
        jvmMain.get().dependsOn(jvmCommonMain)
        commonMain.get().resources.srcDir(zkAssetResources)
        jvmMain.get().resources.srcDir(buildZkDesktop.map { rootProject.file("native/dist/resources") })

        commonMain.dependencies {
            api(libs.multipaz)
            api(libs.multipaz.doctypes)
            api(libs.multipaz.longfellow)
            api(libs.coroutines.core)
            api(libs.serialization.json)
            api(libs.kotlinx.io)
            api(libs.ktor.client.core)
        }
        jvmCommonMain.dependencies {
            implementation(libs.bcprov)
            implementation(libs.bcpkix)
            implementation(libs.zxing.core)
        }
        androidMain.dependencies {
            api("${libs.jna.get()}@aar")
            implementation(libs.ktor.client.okhttp)
            implementation(libs.coroutines.android)
            implementation(libs.xerces.get().toString()) { exclude(group = "xml-apis") }
            implementation(files(androidDomExtras))
        }
        jvmMain.dependencies {
            api(libs.jna)
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
    // The Android library does not package commonMain resources, so the pinned asset list is added here as well.
    sourceSets.getByName("main").resources.srcDir(layout.buildDirectory.dir("generated/zkAssets"))
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

tasks.matching { it.name.startsWith("process") && it.name.endsWith("JavaRes") }.configureEach { dependsOn(zkAssetResources) }
