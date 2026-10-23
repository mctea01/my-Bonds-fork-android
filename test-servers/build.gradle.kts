plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
    application
}

kotlin {
    jvmToolchain(21)
    compilerOptions {
        optIn.add("kotlin.time.ExperimentalTime")
        optIn.add("kotlin.io.encoding.ExperimentalEncodingApi")
    }
}

dependencies {
    implementation(project(":core"))
    implementation(libs.ktor.server.core)
    implementation(libs.ktor.server.netty)
    implementation(libs.ktor.server.websockets)
    implementation(libs.ktor.client.java)
    implementation(libs.bcprov)
    implementation(libs.bcpkix)
    implementation("org.slf4j:slf4j-simple:2.0.17")
    testImplementation(kotlin("test"))
    testImplementation(libs.coroutines.test)
    testImplementation(libs.ktor.server.test.host)
    testImplementation(libs.ktor.client.mock)
    // Encrypts test PDFs with the standard security handler (RC4 and AES revisions).
    testImplementation("org.apache.pdfbox:pdfbox:3.0.8")
}

configurations.all {
    resolutionStrategy.eachDependency {
        if (requested.group == "org.bouncycastle") useVersion(libs.versions.bouncycastle.get())
    }
}

application {
    mainClass.set("diw.testservers.MainKt")
    applicationDefaultJvmArgs = listOf("-Dfile.encoding=UTF-8")
}

tasks.test {
    useJUnitPlatform()
    systemProperty("diw.bench", providers.gradleProperty("bench").getOrElse("false"))
    systemProperty("diw.bench.output", layout.buildDirectory.dir("reports/zk-bench").get().asFile.absolutePath)
    if (providers.gradleProperty("bench").getOrElse("false") == "true") {
        outputs.upToDateWhen { false }
        maxParallelForks = 1
    }
    jvmArgs("-Dfile.encoding=UTF-8", "-Xmx3g")
    // ZkNativeTest needs the library unless core's buildZkDesktop may leave it out (see core/build.gradle.kts).
    systemProperty("diw.zkNative", providers.gradleProperty("diw.zkNative")
        .orElse(providers.environmentVariable("DIW_ZK_NATIVE")).getOrElse("auto"))
    systemProperty("diw.zkFeatures", providers.gradleProperty("diw.zkFeatures")
        .orElse(providers.environmentVariable("DIW_ZK_FEATURES")).getOrElse(""))
    testLogging {
        events("passed", "failed", "skipped")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        showStandardStreams = true
    }
}
