#!/usr/bin/env bash
# Run the same synthetic acceptance test inside an x86_64 Android emulator.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${ANDROID_HOME:?Set ANDROID_HOME}"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/28.2.13676358"
export ANDROID_NDK="$ANDROID_NDK_HOME"
[[ "$(adb shell getprop ro.product.cpu.abi | tr -d '\r')" == x86_64 ]] || {
    echo 'An x86_64 Android emulator is required' >&2; exit 1;
}
mkdir -p openac-age/build
binary=$(python3 -I - <<'PY'
import json
import os
from pathlib import Path
import subprocess

# cargo-ndk 4.1.2 consumes Cargo's artifact messages. Obtain its NDK
# configuration, then capture Cargo's original JSON stream on the host.
environment = os.environ.copy()
environment.update(json.loads(subprocess.check_output([
    'cargo', 'ndk-env', '-t', 'x86_64', '--platform', '29', '--json'
])))
# ndk-env excludes the pinned linker's private routing variables.
environment['_CARGO_NDK_LINK_CLANG'] = environment['CLANG_PATH']
environment['_CARGO_NDK_LINK_TARGET'] = '--target=x86_64-linux-android29'
messages = Path('openac-age/build/android-tests.json')
with messages.open('w') as output:
    subprocess.run(['cargo', 'test', '--target', 'x86_64-linux-android',
        '--release', '--locked', '-p', 'openac-age', '--test', 'openac_age',
        '--no-run', '--message-format=json'], env=environment, stdout=output, check=True)
artifacts = []
for line in messages.read_text().splitlines():
    value = json.loads(line)
    if (value.get('reason') == 'compiler-artifact'
            and value['target']['name'] == 'openac_age'
            and 'test' in value['target']['kind'] and value.get('executable')):
        artifacts.append(value['executable'])
if len(artifacts) != 1:
    raise SystemExit('Expected exactly one Android integration-test executable')
print(artifacts[0])
PY
)
python3 -I openac-age/install_assets.py openac-age/build/assets/circom
# A fixed directory contains only synthetic test data and public circuit assets.
remote=/data/local/tmp/diw-openac-age
adb shell mkdir -p "$remote"
trap 'adb shell rm -rf /data/local/tmp/diw-openac-age >/dev/null' EXIT
adb push "$binary" "$remote/openac-age-tests"
adb push openac-age/build/assets/circom "$remote/"
adb shell chmod 700 "$remote/openac-age-tests"
adb shell "TMPDIR=$remote OPENAC_TEST_ASSETS=$remote/circom $remote/openac-age-tests synthetic_prepare_show_reblind_and_independent_policy --ignored --nocapture"
