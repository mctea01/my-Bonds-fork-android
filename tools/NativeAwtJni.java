import java.io.IOException;
import java.lang.invoke.MethodType;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Stream;

/**
 * JNI metadata for the JDK's desktop libraries (tools/desktop-native.sh). AWT's native code (awt.dll, libawt_xawt.so,
 * fontmanager, jawt) calls back into Java through JNI: it builds every KeyEvent, MouseEvent and InputMethodEvent, reads
 * component fields and calls peer methods. GraalVM registers none of these itself, and the tracing agent only records
 * the calls a run happens to make, so a key press, an input method or the clipboard that the run never used fails in
 * the native executable. This tool registers, for JNI, every member of the desktop modules whose name and descriptor
 * both occur as strings in those libraries (JNI names and descriptors are C string literals there), and every class
 * whose internal name occurs there. Over-matching only adds a little to the image; a missing entry breaks input.
 *
 * Run with the GraalVM java that builds the image, so the classes are those of its own JDK:
 * java tools/NativeAwtJni.java OUTPUT.json LIBRARY...
 */
public class NativeAwtJni {
    /** Modules whose classes AWT's native code calls back into. */
    private static final List<String> MODULES = List.of("java.desktop", "java.datatransfer");

    /** Packages of those modules whose members are matched by name; other classes only when the libraries name them. */
    private static final List<String> PACKAGES = List.of("java.awt.", "sun.awt.", "sun.java2d.", "sun.font.", "sun.datatransfer.");

    /** Sorted reversed strings of the libraries: a value is a suffix of some string when its reverse is a prefix here. */
    private static String[] reversed;

    public static void main(String[] args) throws IOException {
        if (args.length < 2) {
            System.err.println("Usage: java NativeAwtJni.java OUTPUT.json LIBRARY...");
            System.exit(2);
        }
        TreeSet<String> strings = new TreeSet<>();
        for (int i = 1; i < args.length; i++) strings.addAll(cStrings(Files.readAllBytes(Path.of(args[i]))));
        reversed = strings.stream().map(s -> new StringBuilder(s).reverse().toString()).sorted().toArray(String[]::new);

        TreeSet<String> classNames = new TreeSet<>();
        FileSystem jrt = FileSystems.getFileSystem(URI.create("jrt:/"));
        for (String module : MODULES) {
            Path root = jrt.getPath("/modules", module);
            if (!Files.isDirectory(root)) continue;
            try (Stream<Path> files = Files.walk(root)) {
                files.map(p -> root.relativize(p).toString())
                    .filter(n -> n.endsWith(".class") && !n.endsWith("module-info.class"))
                    .forEach(n -> classNames.add(n.substring(0, n.length() - 6).replace('/', '.')));
            }
        }
        // Java2D's RenderBuffer (the Direct3D and OpenGL pipelines) writes through memory-segment VarHandles since
        // JDK 25; their implementation classes are looked up reflectively, so all of them are registered whole.
        TreeSet<String> whole = new TreeSet<>();
        Path invoke = jrt.getPath("/modules/java.base/java/lang/invoke");
        if (Files.isDirectory(invoke)) {
            try (Stream<Path> files = Files.list(invoke)) {
                files.map(p -> p.getFileName().toString())
                    .filter(n -> n.startsWith("VarHandleSegmentAs") && n.endsWith(".class"))
                    .forEach(n -> whole.add("java.lang.invoke." + n.substring(0, n.length() - 6)));
            }
        }
        classNames.addAll(whole);
        // Classes of other modules (java.lang.String, the exceptions AWT throws) only when the libraries name them.
        for (String s : strings) {
            if (s.indexOf('/') > 0 && s.matches("[a-z][a-z0-9_]*(/[A-Za-z0-9_$]+)+")) classNames.add(s.replace('/', '.'));
        }

        Map<String, Map<String, Object>> entries = new TreeMap<>();
        int members = 0;
        for (String name : classNames) {
            Class<?> c;
            try {
                c = Class.forName(name, false, ClassLoader.getPlatformClassLoader());
            } catch (Throwable e) {
                continue;
            }
            boolean all = whole.contains(name);
            boolean named = all || present(name.replace('.', '/'));
            boolean matched = named || PACKAGES.stream().anyMatch(name::startsWith);
            if (!matched) continue;
            TreeSet<String> fields = new TreeSet<>();
            List<List<String>> methods = new ArrayList<>();
            try {
                for (Field f : c.getDeclaredFields()) {
                    if (all || present(f.getName()) && present(f.getType().descriptorString())) fields.add(f.getName());
                }
                for (Method m : c.getDeclaredMethods()) {
                    if (m.isSynthetic() || m.isBridge() || Modifier.isNative(m.getModifiers())) continue;
                    String desc = MethodType.methodType(m.getReturnType(), m.getParameterTypes()).toMethodDescriptorString();
                    if (all || present(m.getName()) && present(desc)) methods.add(signature(m.getName(), m.getParameterTypes()));
                }
                if (named && !Modifier.isAbstract(c.getModifiers())) {
                    for (Constructor<?> k : c.getDeclaredConstructors()) {
                        String desc = MethodType.methodType(void.class, k.getParameterTypes()).toMethodDescriptorString();
                        if (all || present(desc)) methods.add(signature("<init>", k.getParameterTypes()));
                    }
                }
            } catch (Throwable e) {
                // A class whose members cannot be resolved on this platform is left out.
                continue;
            }
            if (!named && fields.isEmpty() && methods.isEmpty()) continue;
            Map<String, Object> entry = new TreeMap<>();
            entry.put("type", c.getName());
            entry.put("jniAccessible", true);
            if (!fields.isEmpty()) entry.put("fields", fields);
            if (!methods.isEmpty()) {
                methods.sort((a, b) -> String.join(",", a).compareTo(String.join(",", b)));
                entry.put("methods", methods);
            }
            entries.put(c.getName(), entry);
            members += fields.size() + methods.size();
        }
        Files.writeString(Path.of(args[0]), json(entries.values()), StandardCharsets.UTF_8);
        System.out.println("AWT JNI metadata: " + entries.size() + " classes, " + members + " members from " + (args.length - 1) + " libraries");
    }

    /** NUL-terminated runs of printable ASCII, as C string literals are stored. */
    private static List<String> cStrings(byte[] data) {
        List<String> out = new ArrayList<>();
        int start = -1;
        for (int i = 0; i < data.length; i++) {
            int b = data[i] & 0xff;
            if (b >= 0x20 && b < 0x7f) {
                if (start < 0) start = i;
            } else {
                if (b == 0 && start >= 0) out.add(new String(data, start, i - start, StandardCharsets.US_ASCII));
                start = -1;
            }
        }
        return out;
    }

    /** True when value ends some string of the libraries (linkers store a literal inside a longer one's tail). */
    private static boolean present(String value) {
        String r = new StringBuilder(value).reverse().toString();
        int i = Arrays.binarySearch(reversed, r);
        if (i >= 0) return true;
        i = -i - 1;
        return i < reversed.length && reversed[i].startsWith(r);
    }

    /** The name followed by the parameter types, as the metadata writes them. */
    private static List<String> signature(String name, Class<?>[] params) {
        List<String> s = new ArrayList<>();
        s.add(name);
        for (Class<?> p : params) s.add(p.getTypeName());
        return s;
    }

    private static String json(Iterable<Map<String, Object>> entries) {
        StringBuilder b = new StringBuilder("{\n  \"reflection\": [\n");
        boolean first = true;
        for (Map<String, Object> e : entries) {
            if (!first) b.append(",\n");
            first = false;
            b.append("    { \"type\": ").append(quote((String) e.get("type"))).append(", \"jniAccessible\": true");
            @SuppressWarnings("unchecked") TreeSet<String> fields = (TreeSet<String>) e.get("fields");
            if (fields != null) {
                b.append(",\n      \"fields\": [");
                boolean f1 = true;
                for (String f : fields) {
                    b.append(f1 ? " " : ", ").append("{ \"name\": ").append(quote(f)).append(" }");
                    f1 = false;
                }
                b.append(" ]");
            }
            @SuppressWarnings("unchecked") List<List<String>> methods = (List<List<String>>) e.get("methods");
            if (methods != null) {
                b.append(",\n      \"methods\": [");
                boolean m1 = true;
                for (List<String> m : methods) {
                    b.append(m1 ? "\n        " : ",\n        ").append("{ \"name\": ").append(quote(m.get(0))).append(", \"parameterTypes\": [");
                    for (int i = 1; i < m.size(); i++) b.append(i > 1 ? ", " : " ").append(quote(m.get(i)));
                    b.append(m.size() > 1 ? " ] }" : "] }");
                    m1 = false;
                }
                b.append("\n      ]");
            }
            b.append(" }");
        }
        return b.append("\n  ]\n}\n").toString();
    }

    private static String quote(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
}
