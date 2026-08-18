#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
installer="${repository_root}/Scripts/install-local-runtime.sh"

help_output=$("$installer" --help)
printf '%s\n' "$help_output" | grep -F -- '--source-preview --identity-hash SHA1' >/dev/null

assert_fails_with() {
  expected="$1"
  shift
  set +e
  output=$("$installer" "$@" 2>&1)
  result=$?
  set -e
  [ "$result" -eq 1 ]
  printf '%s\n' "$output" | grep -F -- "$expected" >/dev/null
}

assert_fails_with \
  '--source-preview requires a 40-character --identity-hash' \
  --source-preview
assert_fails_with \
  '--source-preview and --allow-provisioning-updates are mutually exclusive' \
  --source-preview --identity-hash 0000000000000000000000000000000000000000 \
  --allow-provisioning-updates
assert_fails_with \
  '--identity-hash requires --source-preview' \
  --team-id ABCDEFGHIJ --identity-hash 0000000000000000000000000000000000000000
assert_fails_with \
  '--team-id is not accepted with --source-preview' \
  --source-preview --identity-hash 0000000000000000000000000000000000000000 \
  --team-id ABCDEFGHIJ

printf '%s\n' 'Source Preview installer argument contract passed.'
