#! /bin/bash
# check_on_test_code_in_prod GOLANG_SOURCE_ROOT_PATH
# Checks there functions matching `TestOnly` are not called in poduction code.

pushd "$1" &> /dev/null || exit 1
CANDIDATES=(
  `find -type f ! -name '*test.go' -print0 | xargs --null grep --files-with-matches TestOnly | sort`
)

for ff in "${CANDIDATES[@]}"; do
  #echo "Checking '$ff' ..."
  [[ "$ff" = ./volume_store/cloud_integration/* ]] && continue
  [[ "$ff" = ./workflow/backup_restore_canary/canary_integration/* ]] && continue
  [[ "$ff" = ./encryption/fuzz_correctness/* ]] && continue
  gawk '
    /^func.*TestOnly/ { line_ok = 1; }
    /^\/\/.*TestOnly/ { line_ok = 1; }
    /\/\/ lint:OK/    { line_ok = 1; }
    /TestOnly/ {
      if (line_ok == 0) {
        print("Bad line " NR ": " $0);
        exit 1;
      }
      line_ok = 0;
    }
  ' "$ff" && continue
  echo "[ERROR] Found TestOnly call in '$ff'"
  exit 1
done
echo "LINTER OK"

