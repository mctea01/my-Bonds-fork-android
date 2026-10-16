import java.io.File;
import java.lang.reflect.Method;

/** Runs the actual R8 APK classes and packaged x86_64 libraries on Android. */
public final class ZkAndroidSmoke {
    public static void main(String[] args) throws Exception {
        Class<?> loader = Class.forName("diw.wallet.core.zk.native.ZkNative");
        Method load = loader.getMethod("load", File.class);
        load.invoke(loader.getField("INSTANCE").get(null), new File(args[0]));
        Class<?> bindings = Class.forName("diw.wallet.core.zk.native.bindings.Diw_zkKt");
        if (!Boolean.TRUE.equals(bindings.getMethod("selfTest").invoke(null))) {
            throw new IllegalStateException("Native self-test failed");
        }
        System.out.println("native_info: " + bindings.getMethod("nativeInfo").invoke(null));
        System.out.println("self_test: true");
    }
}
