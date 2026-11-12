# Release build (R8). Only what is loaded by name, through JNI or ServiceLoader is kept, and no wider than that:
# Google Play reports package-wide keep rules as insufficient DEX optimization.

# Bouncy Castle JCA providers register their algorithm classes by name and create them by reflection, so those
# classes keep their names and constructors; the rest of Bouncy Castle is shrunk and optimized like other code.
-keep class org.bouncycastle.jcajce.provider.** { <init>(...); }
-keep class org.bouncycastle.jce.provider.** { <init>(...); }
-keep class org.bouncycastle.pqc.jcajce.provider.** { <init>(...); }
# Multipaz reaches the ML-DSA and ML-KEM lightweight API by reflection (org.multipaz.crypto.BouncyCastlePqc).
-keep class org.bouncycastle.pqc.crypto.mldsa.** { *; }
-keep class org.bouncycastle.pqc.crypto.mlkem.** { *; }
-keep class org.bouncycastle.crypto.AsymmetricCipherKeyPair { *; }
-keep class org.bouncycastle.crypto.SecretWithEncapsulation { *; }
-keep class org.bouncycastle.crypto.KeyGenerationParameters { *; }
-keep class org.bouncycastle.crypto.params.AsymmetricKeyParameter { *; }
-dontwarn org.bouncycastle.**

# Xerces DOM for XML with non-ASCII names; the factory is created by reflection and loads its parts by name.
-keep class org.apache.xerces.** { *; }
-dontwarn org.apache.xerces.**
-keep class org.w3c.dom.events.** { *; }
-keep class org.w3c.dom.ranges.** { *; }
-keep class org.w3c.dom.traversal.** { *; }
-keep class org.w3c.dom.ElementTraversal { *; }
-dontwarn org.w3c.dom.**
-dontwarn javax.xml.**
-dontwarn org.apache.xml.resolver.**

# Multipaz is shrunk and optimized; its Longfellow natives are kept by the library's own rules. The credential
# database function is called by name (AndroidPlatform.credentialDatabase).
-keep class org.multipaz.digitalcredentials.DigitalCredentialsCredmanKt { public static *** calculateCredentialDatabase(...); }
-dontwarn org.multipaz.**

# Tesseract4Android: the native library reads and calls these classes through JNI by name (42 small classes).
-keep class com.googlecode.tesseract.android.** { *; }
-keep class com.googlecode.leptonica.android.** { *; }

# Wallet state stored as JSON (kotlinx.serialization keeps generated serializers through its own rules).
-keep class diw.wallet.core.oid4vci.IssuanceRecord { *; }
-keepclassmembers class diw.wallet.** {
    *** Companion;
    kotlinx.serialization.KSerializer serializer(...);
}

# JSON-LD (bbs-2023 and the RDFC cryptosuites): Titanium finds the Jakarta JSON provider through ServiceLoader or by
# its class name; its own HTTP document loader is never used (contexts load through LdContextLoader).
-keep class org.glassfish.json.JsonProviderImpl { <init>(); }
-dontwarn com.apicatalog.jsonld.http.**
-dontwarn jakarta.json.bind.**

# Ktor and coroutines are discovered through ServiceLoader.
-keep class io.ktor.client.engine.okhttp.OkHttpEngineContainer { *; }
-keep class kotlinx.coroutines.android.AndroidDispatcherFactory { *; }
-keep class kotlinx.coroutines.android.AndroidExceptionPreHandler { *; }
-dontwarn io.ktor.**
-dontwarn org.slf4j.**
-dontwarn java.lang.management.**
-dontwarn javax.naming.**

# Keep line numbers so crash reports from release builds stay readable.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# Interface strings read outside composition build their resource environment by reflection (AppStrings).
-keep class org.jetbrains.compose.resources.ResourceEnvironment { <init>(...); }
