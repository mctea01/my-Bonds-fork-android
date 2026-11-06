#!/usr/bin/env bash
# Experimental: the desktop app as a GraalVM native executable (Linux x86_64). The JVM build (packageDeb and friends)
# stays the supported one. Steps:
#   1. the release uber jar, without Bouncy Castle's signature files and marked Multi-Release (sqlite-jdbc's
#      native-image feature lives under META-INF/versions/9);
#   2. the tracing agent records reflection, JNI and resources while the app runs under Xvfb (AGENT_SECONDS, or
#      AGENT_INTERACTIVE=1 to use the app on the current display and close it yourself; every screen used then is
#      covered, screens never opened are not);
#   3. native-image with GraalVM 25 (about 11 GB of memory and 5 minutes on 4 cores);
#   4. build/desktop-native/ with the executable, the AWT libraries, lib/libjawt.so (Skiko looks for it under
#      java.home) and a launcher that sets java.home.
# Needs GRAALVM_HOME (GraalVM 25), ANDROID_HOME, xvfb-run and zip. Usage: tools/desktop-native.sh
set -euo pipefail
cd "$(dirname "$0")/.."
: "${GRAALVM_HOME:?Set GRAALVM_HOME to GraalVM 25}"
out=build/desktop-native
work=$out/work
rm -rf "$out" && mkdir -p "$work"

./gradlew -q :app:packageReleaseUberJarForCurrentOS
jar=$(ls -t app/build/compose/jars/*-release.jar 2>/dev/null | head -1 || true)
[ -n "$jar" ] || jar=$(ls -t app/build/compose/jars/*.jar | head -1)
cp "$jar" "$work/app.jar"
zip -q -d "$work/app.jar" 'META-INF/*.SF' 'META-INF/*.RSA' 'META-INF/*.DSA' 'META-INF/*.EC' || true
(cd "$work" && mkdir -p mf && cd mf && unzip -q ../app.jar META-INF/MANIFEST.MF \
    && { grep -q '^Multi-Release' META-INF/MANIFEST.MF || { sed -i '/^\s*$/d' META-INF/MANIFEST.MF; printf 'Multi-Release: true\r\n\r\n' >> META-INF/MANIFEST.MF; }; } \
    && zip -q ../app.jar META-INF/MANIFEST.MF)

agent=(-agentlib:native-image-agent=config-output-dir="$work/meta" --add-modules=java.smartcardio -Dfile.encoding=UTF-8 -jar "$work/app.jar")
if [ "${AGENT_INTERACTIVE:-0}" = 1 ]; then
    "$GRAALVM_HOME/bin/java" "${agent[@]}"
else
    # The app keeps running until closed; the agent writes its files when the process ends.
    HOME="$work/home" xvfb-run -a -s "-screen 0 1280x900x24" timeout "${AGENT_SECONDS:-90}" "$GRAALVM_HOME/bin/java" "${agent[@]}" || true
fi

"$GRAALVM_HOME/bin/native-image" -cp "$work/app.jar" -H:ConfigurationFileDirectories="$work/meta" \
    --no-fallback -march=compatibility -Dfile.encoding=UTF-8 -H:+ReportExceptionStackTraces \
    --enable-url-protocols=http,https -J-Xmx11g -o "$out/diw-desktop" diw.wallet.app.desktop.MainKt

mkdir -p "$out/lib"
cp "$GRAALVM_HOME/lib/libjawt.so" "$out/lib/"
cat > "$out/diw-desktop.sh" <<'EOF'
#!/bin/sh
# Skiko loads libjawt.so from java.home/lib; a native executable has no java.home of its own.
dir=$(cd "$(dirname "$0")" && pwd)
exec "$dir/diw-desktop" -Djava.home="$dir" -Dfile.encoding=UTF-8 "$@"
EOF
chmod +x "$out/diw-desktop.sh"
rm -rf "$work"
echo "Built $out/diw-desktop.sh"
