#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

sdk_dir=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}
if [[ -z "$sdk_dir" && -f local.properties ]]; then
    sdk_dir=$(sed -n 's/^sdk.dir=//p' local.properties | head -n 1)
fi
android_jar="$sdk_dir/platforms/android-31/android.jar"
app_classes=app/build/intermediates/javac/debug/classes
resources=app/build/intermediates/compile_and_runtime_not_namespaced_r_class_jar/debug/R.jar
if [[ ! -f "$android_jar" || ! -f "$resources" || ! -f "$app_classes/net/typeblog/socks/util/Utility.class" ]]; then
    echo 'Set ANDROID_HOME and run ./gradlew :app:assembleDebug before these tests.' >&2
    exit 1
fi

test_classes=$(mktemp -d)
trap 'rm -rf "$test_classes"' EXIT
classpath="$test_classes:$app_classes:$resources:$android_jar"
javac -cp "$classpath" -d "$test_classes" \
    app/src/main/java/net/typeblog/socks/util/SocksDnsRelay.java \
    app/src/main/java/net/typeblog/socks/util/Utility.java \
    app/src/test/java/net/typeblog/socks/util/SocksDnsRelayTest.java \
    app/src/test/java/net/typeblog/socks/util/PortTest.java
java -cp "$classpath" net.typeblog.socks.util.SocksDnsRelayTest
java -cp "$classpath" net.typeblog.socks.util.PortTest
