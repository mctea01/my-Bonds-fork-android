plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
    application
}

kotlin {
    jvmToolchain(21)
    compilerOptions {
        optIn.add("kotlin.time.ExperimentalTime")
    }
}

dependencies {
    implementation(project(":core"))
    implementation(libs.ktor.server.core)
    implementation(libs.ktor.server.netty)
    implementation(platform(libs.netty.bom))
    implementation(libs.ktor.client.java)
    implementation("org.slf4j:slf4j-simple:2.0.20")
    testImplementation(kotlin("test"))
    testImplementation(libs.coroutines.test)
    testImplementation(libs.ktor.server.test.host)
}

application {
    mainClass.set("diw.prover.MainKt")
    applicationName = "zk-prover-server"
    // A zkPDF proof holds about 2 GB of native memory; the JVM heap itself stays small.
    applicationDefaultJvmArgs = listOf("-Dfile.encoding=UTF-8", "-Xmx1g")
}

tasks.test {
    useJUnitPlatform()
    jvmArgs("-Dfile.encoding=UTF-8")
}
