#!/usr/bin/env bash
# Builds the Android e2e fixtures without Gradle, from the SDK build tools:
#   out/e2e.dex   E2EClient, run with app_process (spawned with -p)
#   out/e2e.apk   the same code as an app (traced with --package)
# Needs ANDROID_HOME (or ANDROID_SDK_ROOT), a JDK, a build-tools and a platform.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}"
bt="$(ls -d "$sdk"/build-tools/* | sort -V | tail -1)"
jar="$(ls -d "$sdk"/platforms/android-* | sort -V | tail -1)/android.jar"
out="$here/out"
rm -rf "$out"; mkdir -p "$out/classes"

javac -source 11 -target 11 -nowarn -cp "$jar" -d "$out/classes" \
	$(find "$here/src" -name '*.java') 2>&1 | grep -v 'bootstrap classpath' || true
"$bt/d8" --min-api 29 --lib "$jar" --output "$out" $(find "$out/classes" -name '*.class')
cp "$out/classes.dex" "$out/e2e.dex"

"$bt/aapt2" link -I "$jar" --manifest "$here/AndroidManifest.xml" -o "$out/unsigned.apk"
(cd "$out" && zip -q unsigned.apk classes.dex)
"$bt/zipalign" -f 4 "$out/unsigned.apk" "$out/aligned.apk"
keytool -genkeypair -keystore "$out/debug.jks" -storepass android -keypass android \
	-alias e2e -keyalg RSA -keysize 2048 -validity 365 -dname CN=ePtracerE2E >/dev/null 2>&1
"$bt/apksigner" sign --ks "$out/debug.jks" --ks-pass pass:android --out "$out/e2e.apk" "$out/aligned.apk"
echo "[+] $out/e2e.dex $out/e2e.apk"
