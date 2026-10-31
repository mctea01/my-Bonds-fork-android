# UniFFI uses JNA to resolve exported symbols and structure field names.
-keep class diw.wallet.core.zk.native.bindings.** { *; }
-keep class diw.wallet.core.zk.native.ZkNative { *; }
-keep class com.sun.jna.** { *; }
-dontwarn java.awt.**
