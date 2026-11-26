// The optional FaceNet-512 face embedding model for zkPassport FaceMatch (docs/design/zkpassport.md 5.6), as a Play
// on-demand module. It holds only the model file (tools/facematch-eval/README.md). Packages not from Google Play are
// made from the same bundle with every module included (docs/release.md), so all builds match.
plugins {
    id("com.android.dynamic-feature")
}

android {
    namespace = "diw.wallet.app.facenet"
    compileSdk = 36
    defaultConfig {
        minSdk = 29
    }
}

dependencies {
    implementation(project(":app"))
}
