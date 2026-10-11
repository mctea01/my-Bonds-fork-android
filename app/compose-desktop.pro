# Desktop release build (ProGuard, no obfuscation). Libraries below load classes by name,
# through JNI, JDBC or ServiceLoader, so they are kept whole.
-keep class org.bouncycastle.** { *; }
-keep class org.multipaz.** { *; }
-keep class org.sqlite.** { *; }
-keep class io.ktor.client.engine.java.** { *; }
-keep class kotlinx.coroutines.swing.** { *; }
-keep class org.slf4j.** { *; }
-keep class diw.wallet.core.oid4vci.IssuanceRecord { *; }
-keepclassmembers class diw.wallet.** {
    *** Companion;
    kotlinx.serialization.KSerializer serializer(...);
}
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod,SourceFile,LineNumberTable

-dontwarn org.bouncycastle.**
-dontwarn org.multipaz.**
-dontwarn io.ktor.**
-dontwarn kotlinx.**
-dontwarn org.slf4j.**
-dontwarn org.sqlite.**
-dontwarn okio.**
-dontwarn android.**
-dontwarn androidx.**
