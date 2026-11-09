#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

OUT=/mayhem
B="$SRC/mayhem/_build"
H="$SRC/mayhem/harnesses"
TESTS="task_unittest algo_unittest http_unittest redis_unittest mysql_unittest facilities_unittest graph_unittest memory_unittest upstream_unittest dns_unittest resource_unittest uriparser_unittest"
TARGETS="fuzz_http_request fuzz_http_response fuzz_redis_request fuzz_redis_response fuzz_dns_response fuzz_mysql_response fuzz_kafka_response fuzz_uri fuzz_json"

# The compilers reach CMake through the exported CC/CXX, not -DCMAKE_C_COMPILER: the first configure
# caches whatever clang resolved to (the ccache masquerade in the image build), and passing the
# bare name on a later run would make CMake discard the cache.
# workflow's CMake installs its headers by copy into INC_DIR and its archives into LIB_DIR; both
# default into the source tree, so point them at the build dir. -DCMAKE_BUILD_TYPE=None keeps the
# project's RelWithDebInfo default (which appends a plain -g, i.e. DWARF 5) out of the flags.
configure() { # <dir> <flags>
	cmake -S "$SRC" -B "$1" -G "Unix Makefiles" \
		-DCMAKE_BUILD_TYPE=None \
		-DCMAKE_C_FLAGS="$2" -DCMAKE_CXX_FLAGS="$2" \
		-DINC_DIR="$1/include" -DLIB_DIR="$1/lib" \
		-DKAFKA=y
}

# 1) The test suite, with the project's normal flags (own build dir, no sanitizers).
configure "$B/test" "-O2 $COVERAGE_FLAGS"
cmake --build "$B/test" -j"$MAYHEM_JOBS" --target workflow-static
for t in $TESTS; do
	$CXX -std=c++17 -O2 -fno-exceptions -Wno-deprecated-declarations $COVERAGE_FLAGS \
		-I"$B/test/include" "$SRC/test/$t.cc" "$B/test/lib/libworkflow.a" \
		-lgtest -lgtest_main -lssl -lcrypto -lpthread -lrt -o "$B/test/$t"
done

# 2) The library with sanitizers and DWARF 3. DEBUG_FLAGS goes after SANITIZER_FLAGS so its
#    -gdwarf-3 wins over the -g the base carries in SANITIZER_FLAGS.
# UBSan's `null`, `object-size`, `alignment`, `pointer-overflow` and `nonnull-attribute` checks are relaxed, and only
# those: the project's list_entry() macro (src/kernel/list.h) takes &((type *)0)->member as an
# offsetof, which null and object-size flag ("member access within null pointer") on every list
# walk of every input; the wire parsers read integers through misaligned casts and add 0 to NULL
# pointers or pass them with a zero length to memcpy, all benign on the supported targets. ASan still reports real null dereferences (SEGV)
# and out-of-bounds accesses; the rest of UBSan stays on and halting.
FLAGS="-O1 $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -fno-sanitize=null,object-size,alignment,pointer-overflow,nonnull-attribute"
configure "$B/fuzz" "$FLAGS"
cmake --build "$B/fuzz" -j"$MAYHEM_JOBS" --target workflow-static wfkafka-static

# 3) One fuzzer plus one -standalone reproducer per harness.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"
$CXX -std=c++11 $FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/lsan_off.o"
LIBS="$B/fuzz/lib/libwfkafka.a $B/fuzz/lib/libworkflow.a -lssl -lcrypto -lz -llz4 -lzstd -lsnappy -lpthread -lrt"
for t in $TARGETS; do
	$CXX -std=c++11 -fno-exceptions $FLAGS -I"$B/fuzz/include" -I"$H" -c "$H/$t.cc" -o "$B/$t.o"
	$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/$t.o" "$B/lsan_off.o" $LIBS -o "$OUT/$t"
	$CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$B/$t.o" "$B/standalone_main.o" "$B/lsan_off.o" $LIBS -o "$OUT/$t-standalone"
done
