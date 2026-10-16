# Release build (R8). Libraries below load classes by name, through JNI or ServiceLoader,
# so they are kept whole; the app and remaining libraries are shrunk and optimized.

# Bouncy Castle JCA provider: algorithm classes are looked up by name.
-keep class org.bouncycastle.** { *; }
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

# Multipaz: CBOR/COSE types, secure areas and Android Keystore glue.
-keep class org.multipaz.** { *; }
-dontwarn org.multipaz.**

# Wallet state stored as JSON (kotlinx.serialization keeps generated serializers through its own rules).
-keep class diw.wallet.core.oid4vci.IssuanceRecord { *; }
-keepclassmembers class diw.wallet.** {
    *** Companion;
    kotlinx.serialization.KSerializer serializer(...);
}

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
