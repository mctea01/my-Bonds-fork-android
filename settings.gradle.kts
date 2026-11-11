pluginManagement {
    repositories {
        google()
        maven { url = uri("https://maven-central.storage-download.googleapis.com/maven2/") }
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositories {
        google()
        maven { url = uri("https://maven-central.storage-download.googleapis.com/maven2/") }
        mavenCentral()
        // Tesseract4Android (machine readable zone OCR) is published only on JitPack; nothing else is taken from it.
        maven {
            url = uri("https://jitpack.io")
            content { includeGroup("cz.adaptech.tesseract4android") }
        }
    }
}
rootProject.name = "diw-wallet"
include(":core", ":test-servers", ":app", ":zk-prover-server")
project(":zk-prover-server").projectDir = file("tools/zk-prover-server")
