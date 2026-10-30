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
    implementation(platform(libs.netty.bom))
    implementation(libs.ktor.server.websockets)
    implementation(libs.ktor.client.java)
    implementation(libs.bcprov)
    implementation(libs.bcpkix)
    implementation(libs.bcpg)
    implementation("org.slf4j:slf4j-simple:2.0.20")
    testImplementation(kotlin("test"))
    testImplementation(libs.coroutines.test)
    testImplementation(libs.ktor.server.test.host)
    testImplementation(libs.ktor.client.mock)
    // The Android engine: its WebSocket sessions refuse settings the Java engine accepts.
    testImplementation(libs.ktor.client.okhttp)
    // Encrypts test PDFs with the standard security handler (RC4 and AES revisions).
    testImplementation("org.apache.pdfbox:pdfbox:3.0.8")
}

configurations.all {
    resolutionStrategy.eachDependency {
        if (requested.group == "org.bouncycastle") useVersion(libs.versions.bouncycastle.get())
        // Keep every transitive Netty artifact on the patched version (SNI routing bypass, request smuggling).
        if (requested.group == "io.netty" && requested.name != "netty-bom") useVersion(libs.versions.netty.get())
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

// The signed zk template pack for a release (templates/ in the repository); the key comes from ZK_TEMPLATES_KEY.
tasks.register<JavaExec>("templatePack") {
    group = "distribution"
    description = "Builds build/zk-templates.jwt from templates/, signed with ZK_TEMPLATES_KEY"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("diw.testservers.tools.TemplatePackTool")
    args(rootProject.file("templates").absolutePath, layout.buildDirectory.file("zk-templates.jwt").get().asFile.absolutePath)
    jvmArgs("-Dfile.encoding=UTF-8")
}

// Checks a zkTLS page profile against the real site on this machine (templates/README.md): -Pprofile=<file>, and
// -Pshow to print the values read, -Psave=<file> to keep the response (it holds the query result), -Pfrom=<file> to
// check the rules against a kept response without contacting the site.
tasks.register<JavaExec>("checkProfile") {
    group = "verification"
    description = "Checks a zkTLS verification page profile against the real site"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("diw.testservers.tools.ProfileCheckTool")
    standardInput = System.`in`
    jvmArgs("-Dfile.encoding=UTF-8", "-Dstdout.encoding=UTF-8", "-Dstderr.encoding=UTF-8")
    val profile = providers.gradleProperty("profile")
    val show = providers.gradleProperty("show")
    val save = providers.gradleProperty("save")
    val from = providers.gradleProperty("from")
    argumentProviders.add(CommandLineArgumentProvider {
        listOfNotNull(profile.orNull?.let { rootProject.file(it).absolutePath }) +
            (if (show.isPresent) listOf("--show") else emptyList()) +
            (save.orNull?.let { listOf("--save", rootProject.file(it).absolutePath) } ?: emptyList()) +
            (from.orNull?.let { listOf("--from", rootProject.file(it).absolutePath) } ?: emptyList())
    })
}
