#!/usr/bin/env bash
# Packages for installs outside Google Play, made from the same bundle (.aab) Play gets, so every package has the same
# code, version and signature (docs/release.md):
#   <prefix>.apk                 one APK with every module and both ABIs, on-demand modules included (features/)
#   <prefix>-arm64-v8a.apk and <prefix>-x86_64.apk   the same for one ABI, smaller
#   <prefix>.apks                the split set as Play would deliver it, for split installers (bundletool install-apks,
#                                SAI); its on-demand modules are separate splits, installed only when chosen
# Usage: tools/bundle-apks.sh release|debug <bundle.aab> <output prefix> [--universal-only]
# Signing follows app/build.gradle.kts: release uses DIW_KEYSTORE_FILE (DIW_KEYSTORE_PASSWORD, DIW_KEY_ALIAS,
# DIW_KEY_PASSWORD) when set; otherwise, and for debug, DIW_DEBUG_KEYSTORE_FILE or ~/.android/debug.keystore.
set -euo pipefail

BUNDLETOOL_VERSION=1.18.3
BUNDLETOOL_SHA256=a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29

kind=${1:?release or debug}
aab=${2:?bundle}
prefix=${3:?output prefix}
only=${4:-}
[[ "$kind" == release || "$kind" == debug ]] || { echo "The first argument is release or debug" >&2; exit 1; }
[[ -f "$aab" ]] || { echo "No bundle at $aab" >&2; exit 1; }

jar=${BUNDLETOOL_JAR:-"${RUNNER_TEMP:-${TMPDIR:-/tmp}}/bundletool-all-$BUNDLETOOL_VERSION.jar"}
if [[ ! -f "$jar" ]]; then
    curl -sSLf -o "$jar.part" "https://github.com/google/bundletool/releases/download/$BUNDLETOOL_VERSION/bundletool-all-$BUNDLETOOL_VERSION.jar"
    mv "$jar.part" "$jar"
fi
if command -v sha256sum > /dev/null; then digest=$(sha256sum "$jar"); else digest=$(shasum -a 256 "$jar"); fi
[[ "${digest%% *}" == "$BUNDLETOOL_SHA256" ]] || { echo "bundletool does not match its pinned SHA-256" >&2; rm -f "$jar"; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# bundletool reads passwords from files (pass: would put them on the command line).
secret() { umask 077; printf '%s' "$2" > "$work/$1"; printf 'file:%s' "$work/$1"; }

if [[ "$kind" == release && -n "${DIW_KEYSTORE_FILE:-}" ]]; then
    signing=(--ks="$DIW_KEYSTORE_FILE" --ks-pass="$(secret store "${DIW_KEYSTORE_PASSWORD:?}")" --ks-key-alias="${DIW_KEY_ALIAS:?}"
        --key-pass="$(secret key "${DIW_KEY_PASSWORD:-$DIW_KEYSTORE_PASSWORD}")")
else
    store=${DIW_DEBUG_KEYSTORE_FILE:-"$HOME/.android/debug.keystore"}
    [[ -f "$store" ]] || { echo "No signing key: set DIW_KEYSTORE_FILE or DIW_DEBUG_KEYSTORE_FILE, or build once with Gradle" >&2; exit 1; }
    password=${DIW_DEBUG_KEYSTORE_PASSWORD:-android}
    alias=${DIW_DEBUG_KEY_ALIAS:-}
    if [[ -z "$alias" ]]; then
        # The same choice as Gradle: the only key, else androiddebugkey.
        aliases=$(keytool -list -keystore "$store" -storepass "$password" 2>/dev/null | grep -i 'PrivateKeyEntry' | cut -d, -f1)
        if [[ $(printf '%s\n' "$aliases" | grep -c .) -eq 1 ]]; then alias=$aliases; else alias=androiddebugkey; fi
    fi
    signing=(--ks="$store" --ks-pass="$(secret store "$password")" --ks-key-alias="$alias" --key-pass="$(secret key "$password")")
fi

bundletool() { java -jar "$jar" "$@"; }

bundletool build-apks --bundle="$aab" --output="$work/universal.apks" --mode=universal --modules=_ALL_ "${signing[@]}"
unzip -p "$work/universal.apks" universal.apk > "$prefix.apk"
if [[ "$only" == --universal-only ]]; then ls -l "$prefix.apk"; exit 0; fi

for abi in arm64-v8a x86_64; do
    printf '{"supportedAbis":["%s"],"supportedLocales":["en"],"screenDensity":440,"sdkVersion":34}\n' "$abi" > "$work/$abi.json"
    # System mode fuses the base and every listed module for one device into a single standalone APK.
    bundletool build-apks --bundle="$aab" --output="$work/$abi.apks" --mode=system --modules=_ALL_ \
        --device-spec="$work/$abi.json" "${signing[@]}"
    unzip -p "$work/$abi.apks" system/system.apk > "$prefix-$abi.apk"
done

bundletool build-apks --bundle="$aab" --output="$prefix.apks" "${signing[@]}"
ls -l "$prefix.apk" "$prefix"-*.apk "$prefix.apks"
