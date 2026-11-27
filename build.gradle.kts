plugins {
    id("com.android.application") version "9.5.3" apply false
    id("com.android.library") version "9.5.3" apply false
    id("com.android.dynamic-feature") version "9.5.3" apply false
    kotlin("multiplatform") version "2.4.21" apply false
    kotlin("jvm") version "2.4.21" apply false
    kotlin("plugin.compose") version "2.4.21" apply false
    kotlin("plugin.serialization") version "2.4.21" apply false
    id("org.jetbrains.compose") version "1.12.2" apply false
}

// Libraries bring in Guava (-android on Android, -jre on the desktop). Versions before the catalog's floor are raised
// to it with the same flavor, so a vulnerable Guava is not resolved transitively. Guava before 22 had no flavor
// (jimfs 1.1 in the Android lint tool asks for 18.0) and the floor only exists with one, so those get -jre; since
// 32.1 Gradle module metadata still picks the Android variant on Android. Ranges and other forms are left alone.
subprojects {
    val guavaFloor = rootProject.extensions.getByType<VersionCatalogsExtension>().named("libs").findVersion("guava").get().requiredVersion
    configurations.configureEach {
        resolutionStrategy.eachDependency {
            if (requested.group == "com.google.guava" && requested.name == "guava") {
                val version = requested.version.orEmpty()
                val number = version.substringBefore('-')
                if (Regex("""\d+(\.\d+)*""").matches(number)) {
                    fun parts(v: String) = v.split('.').map { it.toInt() }
                    val below = parts(number).zip(parts(guavaFloor)).firstOrNull { (a, b) -> a != b }?.let { (a, b) -> a < b }
                        ?: (parts(number).size < parts(guavaFloor).size)
                    if (below) {
                        useVersion("$guavaFloor-${version.substringAfter('-', "").ifEmpty { "jre" }}")
                        because("GHSA-xxph-c9ww-hj94 is fixed in Guava 33.7.2")
                    }
                }
            }
        }
    }
}
