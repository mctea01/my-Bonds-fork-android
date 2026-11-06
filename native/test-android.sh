#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${ANDROID_HOME:?Set ANDROID_HOME}"
apk=${1:-app/build/outputs/apk/release/app-release.apk}
[[ "$(adb shell getprop ro.product.cpu.abi | tr -d '\r')" == x86_64 ]] || {
    echo "An x86_64 Android emulator is required" >&2; exit 1;
}
work=native/target/android-smoke
mkdir -p "$work/classes" "$work/dex" "$work/lib"
javac --release 8 -d "$work/classes" test-servers/src/test/kotlin/diw/testservers/zk/android/ZkAndroidSmoke.java
"$ANDROID_HOME/build-tools/36.0.0/d8" --min-api 29 --output "$work/dex" "$work/classes/ZkAndroidSmoke.class"
python3 - "$apk" "$work/lib" <<'PY'
import pathlib, sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as apk:
    for name in ('libdiw_zk.so', 'libjnidispatch.so'):
        pathlib.Path(sys.argv[2], name).write_bytes(apk.read('lib/x86_64/' + name))
PY
adb install -r "$apk"
remote=/data/local/tmp/diw-zk-smoke
adb shell mkdir -p "$remote"
adb push "$apk" "$remote/app.apk"
adb push "$work/dex/classes.dex" "$remote/classes.dex"
adb push "$work/lib/." "$remote/"
adb shell "CLASSPATH=$remote/classes.dex:$remote/app.apk app_process -Djava.library.path=$remote -Djna.boot.library.path=$remote -Djna.library.path=$remote /system/bin ZkAndroidSmoke $remote"
