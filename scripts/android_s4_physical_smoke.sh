#!/usr/bin/env bash
# Manual physical-device test runner for S.4.2.
# Intentionally NEVER installs/uninstalls the app under test, clears app data,
# replaces a production APK, or deletes the user's real Keystore alias.
set -euo pipefail

if [[ $# -ne 1 || -z "${1:-}" ]]; then
  printf 'Usage: ANDROID_SERIAL=<serial> %s <device-serial>\n' "$0" >&2
  printf 'Find the serial with: adb devices -l\n' >&2
  exit 2
fi

device="$1"
if [[ ! "$device" =~ ^[a-zA-Z0-9._:-]+$ ]]; then
  echo 'Invalid device serial' >&2
  exit 2
fi
command -v adb >/dev/null || { echo 'adb is required' >&2; exit 2; }

ADB=(adb -s "$device")
if [[ "$("${ADB[@]}" get-state 2>/dev/null)" != "device" ]]; then
  echo 'Device is disconnected or USB debugging is unauthorized' >&2
  exit 2
fi

pkg="com.ghostdeveloper.spdecode"
if ! "${ADB[@]}" shell pm path "$pkg" | grep -q '^package:'; then
  echo 'Install a DEBUG build of SP-DECODE first. Production builds are intentionally untouched.' >&2
  exit 3
fi
if ! "${ADB[@]}" shell run-as "$pkg" pwd >/dev/null 2>&1; then
  echo 'Installed SP-DECODE is not debuggable. Refusing to replace or uninstall it.' >&2
  exit 3
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_apk="$repo_root/android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"
if [[ ! -s "$test_apk" ]]; then
  echo 'Missing test APK. Build locally with: cd android && gradle :app:assembleAndroidTest' >&2
  exit 3
fi

echo 'S.4.2: installing ONLY the instrumentation test package.'
"${ADB[@]}" install -r "$test_apk" >/dev/null

test_class="$pkg.DevicePrivateCredentialLifecycleInstrumentedTest"
instrumentation="$pkg.test/androidx.test.runner.AndroidJUnitRunner"
printf 'Device: %s\n' "$device"
printf 'API: %s\n' "$("${ADB[@]}" shell getprop ro.build.version.sdk | tr -d '\r')"
printf 'Test: %s\n' "$test_class"
echo 'The test uses isolated debug-only aliases and cleans them up.'

log="$(mktemp)"
trap 'rm -f "$log"' EXIT
if ! "${ADB[@]}" shell am instrument -w -r \
  -e class "$test_class" "$instrumentation" >"$log" 2>&1; then
  echo 'Instrumentation invocation failed.' >&2
  cat "$log" >&2
  exit 1
fi
cat "$log"
if ! grep -Eq 'OK \([0-9]+ tests?\)' "$log" ||
   ! grep -q 'INSTRUMENTATION_CODE: -1' "$log" ||
   grep -Eq 'FAILURES!!!|INSTRUMENTATION_FAILED|INSTRUMENTATION_CODE: 0' "$log"; then
  echo 'S.4.2 physical smoke: FAIL or inconclusive' >&2
  exit 1
fi
echo 'S.4.2 isolated physical-device instrumentation: PASS'
echo 'UI/manual lock-screen checks must be recorded separately.'
