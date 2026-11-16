#!/usr/bin/env bash
# The local gate (run it in the pinned toolchain: tools/container.sh tools/gate.sh [JOB...]).
# Jobs, in order: format, build, asan, fuzz. Exit status 1 when any job fails; a summary of every job is printed at
# the end.
#   FUZZ_SECONDS      seconds of fuzzing per target (default 60)
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
JOBS=("$@")
[[ ${#JOBS[@]} -gt 0 ]] || JOBS=(format build asan fuzz)
FUZZ_SECONDS=${FUZZ_SECONDS:-60}

# No clang-format style is adopted; tracked text files outside the data and vectors must be free of tabs, trailing
# blanks and CRs, and every file ends in a newline.
format() {
  local f rc=0
  mapfile -t files < <(git ls-files -- . ':!fuzz/corpus' ':!tests/data' ':!tests/vectors')
  if grep -n -I -E $'\t| +$|\r' -- "${files[@]}"; then rc=1; fi
  mapfile -t files < <(git ls-files -- . ':!fuzz/corpus')
  for f in "${files[@]}"; do
    if [[ -s $f && $(tail -c1 "$f" | od -An -c | tr -d ' ') != '\n' ]]; then echo "$f: no final newline"; rc=1; fi
  done
  return $rc
}
# GCC 15, strict warnings as errors, the GoogleTest suites.
build() {
  CXX=g++ cmake -S . -B build/gcc -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo >/dev/null \
    && cmake --build build/gcc \
    && ctest --test-dir build/gcc --output-on-failure
}
# clang 21 with AddressSanitizer (leak checking on) and UndefinedBehaviorSanitizer.
asan() {
  local san="-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer"
  CXX=clang++ cmake -S . -B build/asan -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="$san" \
      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" >/dev/null \
    && cmake --build build/asan \
    && ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1 ctest --test-dir build/asan --output-on-failure
}
# libFuzzer (with ASan and UBSan) on the URL/link checks and the lookalike engine.
fuzz() {
  CXX=clang++ cmake -S . -B build/fuzz -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DMAILLOOKALIKE_FUZZ=ON >/dev/null \
    && cmake --build build/fuzz || return 1
  local t rc=0
  for t in url_links lookalike_host; do
    mkdir -p "build/fuzz-corpus/$t" build/fuzz-findings
    "build/fuzz/fuzz_$t" -max_total_time="$FUZZ_SECONDS" -rss_limit_mb=2048 -timeout=30 -max_len=4096 \
      -print_final_stats=1 -artifact_prefix="build/fuzz-findings/$t-" "build/fuzz-corpus/$t" "fuzz/corpus/$t" || rc=1
  done
  return $rc
}

declare -A RESULT
fail=0
for j in "${JOBS[@]}"; do
  echo "=== $j"
  start=$SECONDS
  if "$j"; then RESULT[$j]="PASS $((SECONDS - start))s"; else RESULT[$j]="FAIL $((SECONDS - start))s"; fail=1; fi
done
echo "=== summary"
for j in "${JOBS[@]}"; do echo "$j: ${RESULT[$j]}"; done
exit $fail
