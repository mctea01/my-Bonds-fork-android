plugins {
    id("com.android.application") version "8.13.2" apply false
    id("com.android.library") version "8.13.2" apply false
    kotlin("multiplatform") version "2.4.21" apply false
    kotlin("jvm") version "2.4.21" apply false
    kotlin("plugin.compose") version "2.4.21" apply false
    kotlin("plugin.serialization") version "2.4.21" apply false
    id("org.jetbrains.compose") version "1.12.2" apply false
}

// Ktor 3.6 asks for OkHttp 5.5, whose AAR needs compileSdk 37 (beyond AGP 8.13). 5.4 has every OkHttp API the Ktor
// engine calls; lift this together with the AGP and compileSdk upgrade.
subprojects {
    configurations.all {
        resolutionStrategy.force(
            "com.squareup.okhttp3:okhttp:5.4.0",
            "com.squareup.okhttp3:okhttp-android:5.4.0",
            "com.squareup.okhttp3:okhttp-jvm:5.4.0",
        )
    }
}
