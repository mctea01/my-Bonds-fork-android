#!/usr/bin/env bash
# The desktop app as a GraalVM native executable (experimental; the JVM packages stay the release). Linux x86_64 and
# Windows x86_64; macOS on Apple silicon is attempted. Steps:
#   1. the uber jar without ProGuard (native-image keeps only what is reachable itself; ProGuard dropped sqlite-jdbc's
#      native-image feature), without Bouncy Castle's signature files and with the newest META-INF/versions/ entry
#      up to 25 moved to the root (native-image does not read them from the class path);
#   2. GraalVM's tracing agent records reflection, JNI, proxies and resources into one directory from the desktop tests
#      (AGENT_TESTS=0 skips them), the self-check (--self-check) and the app itself for AGENT_SECONDS (under Xvfb on
#      Linux); tools/native-metadata-filter.py then drops what only the tests use;
#   3. native-image with GraalVM 25. No heap limit is given: the executable may use up to 80 % of the machine's memory
#      (GraalVM's default MaximumHeapSizePercent), and the proving libraries run outside the heap anyway;
#   4. build/desktop-native/<os>/ holds the executable, the JDK libraries native-image puts beside it and the JAWT
#      library where Skiko looks for it (the app points java.home at the executable's folder);
#   5. the executable must pass its self-check and show its first screen (DIW_EXIT_AFTER_SECONDS).
# Needs GRAALVM_HOME (GraalVM 25), ANDROID_HOME and Python 3; on Linux xvfb-run, on Windows Visual Studio's C++ tools
# (found with vswhere when cl.exe is not on the PATH). NATIVE_IMAGE_XMX caps native-image's own memory (about 11 GB
# are needed). Usage: tools/desktop-native.sh
set -euo pipefail
cd "$(dirname "$0")/.."
: "${GRAALVM_HOME:?Set GRAALVM_HOME to GraalVM 25}"
case "$(uname -s)" in
    Linux) os=linux; exe=diw-desktop ;;
    MINGW* | MSYS* | CYGWIN*) os=windows; exe=diw-desktop.exe ;;
    Darwin) os=macos; exe=diw-desktop ;;
    *) echo "Unsupported host $(uname -s)" >&2; exit 1 ;;
esac
python=$(command -v python3 || command -v python)
graal=$GRAALVM_HOME
[ "$os" = windows ] && graal=$(cygpath -u "$GRAALVM_HOME")
java="$graal/bin/java"
out=build/desktop-native/$os
work=build/desktop-native/work-$os
meta=$work/meta
rm -rf "$out" "$work" && mkdir -p "$out" "$meta"
# Paths handed to Gradle and to Windows programs.
native_path() { if [ "$os" = windows ]; then cygpath -w "$PWD/$1"; else echo "$PWD/$1"; fi; }

# On Linux the window needs a display; elsewhere the runner's own desktop session is used.
with_display() { if [ "$os" = linux ]; then xvfb-run -a -s "-screen 0 1280x900x24" "$@"; else "$@"; fi; }

echo "== uber jar"
./gradlew --no-daemon -q :app:packageUberJarForCurrentOS
jar=$(ls -t app/build/compose/jars/*.jar 2>/dev/null | grep -v -- '-release\.jar$' | head -1 || true)
[ -n "$jar" ] || { echo "No uber jar" >&2; exit 1; }
"$python" -I - "$jar" "$work/app.jar" <<'PY'
import re, sys, zipfile
signature = re.compile(r"META-INF/[^/]+\.(SF|RSA|DSA|EC)$", re.I)
versioned = re.compile(r"META-INF/versions/(\d+)/(.+)$")
with zipfile.ZipFile(sys.argv[1]) as source, zipfile.ZipFile(sys.argv[2], "w", zipfile.ZIP_DEFLATED) as target:
    entries = [i for i in source.infolist() if not signature.match(i.filename)]
    # The newest version up to 25 of each versioned entry replaces the base one, as a Java 25 runtime would pick it.
    best = {}
    for info in entries:
        m = versioned.match(info.filename)
        if m and int(m[1]) <= 25 and not m[2].endswith("/") and m[2] != "module-info.class":
            if m[2] not in best or int(m[1]) > best[m[2]][0]:
                best[m[2]] = (int(m[1]), info)
    # Read before writing: writestr() moves a ZipInfo's offset to the target file.
    promoted = {name: (info.date_time, source.read(info)) for name, (_, info) in best.items()}
    for info in entries:
        if info.filename not in promoted:
            target.writestr(info, source.read(info))
    for name, (date_time, data) in promoted.items():
        target.writestr(zipfile.ZipInfo(name, date_time), data, zipfile.ZIP_DEFLATED)
    print(f"app.jar: {len(promoted)} versioned entries flattened")
PY

echo "== tracing agent"
if [ "${AGENT_TESTS:-1}" = 1 ]; then
    # A test that fails only under the agent's slowdown still leaves what it reached; the build goes on.
    ./gradlew --no-daemon -q :app:desktopTest "-Pdiw.nativeAgent=$(native_path "$meta")" \
        || echo "::warning::desktop tests failed under the tracing agent; their metadata is kept"
    "$python" -I tools/native-metadata-filter.py "$meta"
fi
agent=(-agentlib:native-image-agent=config-merge-dir="$meta" --add-modules=java.smartcardio
    --add-opens=java.smartcardio/sun.security.smartcardio=ALL-UNNAMED -Dfile.encoding=UTF-8 -jar "$work/app.jar")
with_display "$java" "${agent[@]}" --self-check "$work/self-check-jvm.txt" || { cat "$work/self-check-jvm.txt" || true; exit 1; }
# The app closes itself after AGENT_SECONDS through a normal exit, so the agent writes what it saw.
DIW_WALLET_HOME="$work/home" DIW_EXIT_AFTER_SECONDS="${AGENT_SECONDS:-60}" with_display "$java" "${agent[@]}"

echo "== native-image"
args=(-cp "$work/app.jar" "-H:ConfigurationFileDirectories=$meta" --no-fallback -march=compatibility
    -H:+UnlockExperimentalVMOptions -H:+ReportExceptionStackTraces --enable-url-protocols=http,https
    -Dfile.encoding=UTF-8 --add-modules=java.smartcardio
    # Every resource but classes: images, fonts and strings of screens the agent never opened are still there.
    "-H:IncludeResources=.*" "-H:ExcludeResources=.*\\.class\$"
    -o "$out/diw-desktop")
[ -n "${NATIVE_IMAGE_XMX:-}" ] && args+=("-J-Xmx$NATIVE_IMAGE_XMX")
# A window application on Windows, without a console beside it.
[ "$os" = windows ] && args+=(-H:NativeLinkerOption=/SUBSYSTEM:WINDOWS -H:NativeLinkerOption=/ENTRY:mainCRTStartup)
args+=(diw.wallet.app.desktop.MainKt)
if [ "$os" = windows ]; then
    # native-image needs the MSVC environment; a small batch file sets it up and runs native-image in it.
    wrapper=$work/native-image.cmd
    {
        echo "@echo off"
        if ! command -v cl.exe > /dev/null 2>&1; then
            vs=$("/c/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe" -latest -products '*' \
                -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | tr -d '\r')
            [ -n "$vs" ] || { echo "Visual Studio C++ tools not found" >&2; exit 1; }
            echo "call \"$vs\\VC\\Auxiliary\\Build\\vcvars64.bat\" > nul || exit /b 1"
        fi
        printf '"%s"' "$(cygpath -w "$graal/bin/native-image.cmd")"
        for a in "${args[@]}"; do printf ' "%s"' "$a"; done
        printf '\r\n'
    } > "$wrapper"
    cmd //c "$(cygpath -w "$wrapper")"
else
    "$graal/bin/native-image" "${args[@]}"
fi

# Skiko loads JAWT from java.home: lib/ on Linux and macOS, bin/ on Windows (and the executable's own folder, where
# Windows looks for a DLL's dependencies first).
case $os in
    linux) mkdir -p "$out/lib" && cp "$graal/lib/libjawt.so" "$out/lib/" ;;
    macos) mkdir -p "$out/lib" && cp "$graal/lib/libjawt.dylib" "$out/lib/" ;;
    windows) mkdir -p "$out/bin" && cp "$graal/bin/jawt.dll" "$out/bin/" && cp "$graal/bin/jawt.dll" "$out/" ;;
esac

echo "== native executable"
code=0
with_display "$out/$exe" --self-check "$work/self-check-native.txt" || code=$?
cat "$work/self-check-native.txt" || true
[ "$code" = 0 ] || { echo "The native self-check failed (exit $code)" >&2; exit 1; }
code=0
DIW_WALLET_HOME="$work/smoke" DIW_EXIT_AFTER_SECONDS="${SMOKE_SECONDS:-20}" with_display "$out/$exe" || code=$?
[ "$code" = 0 ] || { echo "The native executable did not show its first screen (exit $code)" >&2; exit 1; }
cp "$work/self-check-native.txt" "$out/self-check.txt"
ls -l "$out"
echo "Built $out/$exe"
