// Barretenberg 5 for zkPassport proofs of circuits before 0.22.0 (native/zkpassport-bb5), as a Play on-demand module.
// It holds only the native library, built by :app's buildZkAndroid when DIW_ZK_FEATURES has bb5. Packages not from
// Google Play are made from the same bundle with every module included (docs/release.md), so all builds match.
plugins {
    id("com.android.dynamic-feature")
}

android {
    namespace = "diw.wallet.app.bb5"
    compileSdk = 36
    defaultConfig {
        minSdk = 29
    }
    sourceSets.getByName("main").jniLibs.srcDir(rootProject.file("native/dist/android-bb5"))
}

dependencies {
    implementation(project(":app"))
}

tasks.matching { it.name.startsWith("merge") && it.name.endsWith("JniLibFolders") }.configureEach {
    dependsOn(":app:buildZkAndroid")
}
