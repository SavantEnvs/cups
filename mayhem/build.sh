#!/usr/bin/env bash
#
# cups/mayhem/build.sh — build OpenPrinting/cups's OSS-Fuzz harnesses as sanitized libFuzzer
# targets (+ standalone reproducers), AND cups' own unit-test programs (from the same sanitized
# objects) for mayhem/test.sh.
#
# This is the FULL CUPS printing system (distinct from the libcups library repo). The fuzzed
# surface is attacker-controlled bytes into CUPS' C parsers:
#   fuzz_ipp               — IPP message wire format via ippReadIO() (cups/ipp.c).
#   fuzz_ipp_gen           — IPP wire format via ippReadIO() into request+response objects.
#   fuzz_raster            — CUPS raster page headers via cupsRasterReadHeader2() (cups/raster.c).
#   fuzz_cups              — PostScript page-setup interpreter _cupsRasterExecPS() (raster-interpret.c).
#   fuzz_ppd_gen_1         — PPD file parser ppdOpenFile() + ppdMarkDefaults/ppdConflicts (cups/ppd*.c).
#   fuzz_ppd_gen_conflicts — PPD parser + cupsParseOptions/cupsGetConflicts/cupsResolveConflicts.
#   fuzz_ppd_gen_cache     — PPD parser + _ppdCacheCreateWithPPD/_ppdCacheWriteFile cache round-trip.
#   fuzz_array             — cups_array_t API (cups/array.c) driven through a FuzzedDataProvider.
#   fuzz_http_core         — HTTP URI/field/base64/addr helpers (cups/http*.c) on a segmented input.
#
# Harnesses come from OpenPrinting/fuzzing (the upstream OSS-Fuzz fuzzer repo); they are vendored
# into mayhem/harnesses/ so the build is self-contained (no network clone at image-build time).
#
# Build contract comes from the org base ENV (CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/SRC/
# STANDALONE_FUZZ_MAIN/OUT). We build the cups libraries THEMSELVES with $SANITIZER_FLAGS so the
# parsed code (not just the harness) is instrumented. The harnesses AND cups' unit-test programs
# (test.sh's oracle) are compiled from committed (git HEAD) sources, against one HEAD copy of the cups
# headers, with the library's own make flags (steps 2-5); the library (step 1) is the only part built
# from the patched working tree, and both sets link it. A patch therefore cannot steer the compile of
# the fuzz targets without the unit-test programs' (link- and run-time probes are outside this).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS: explicit DWARF-3 so Mayhem's triage can read symbols (clang-19 defaults to DWARF-5).
# Placed after $SANITIZER_FLAGS in every compile so it is never shadowed.
: "${DEBUG_FLAGS:=-gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${OUT:=/mayhem}"
: "${SRC:=/mayhem}"

# ── Benign-UB relaxation (build.sh only) ───────────────────────────────────────────────────────
# CUPS' IPP/PPD/raster/string parsers deliberately use idioms that trip UBSan on essentially every
# input, drowning out any real bug (same set the sibling libcups repo relaxes):
#   * ipp.c / raster.c: request_id = (buffer[0] << 24) | ...  -> shift / signed-integer-overflow
#   * string.c:         casts an arbitrary input buffer for the string interning pool -> alignment
#   * array.c:          calls a typed comparator through a generic fn pointer          -> function
# Upstream OSS-Fuzz builds CUPS with sanitizers: address, memory (UBSan is NOT in the halting set).
# We keep ASan + the meaningful UBSan checks (null deref, bounds, etc.) HALTING and disable only this
# set of well-known benign checks so the harness reaches real parser code instead of crashing at byte 0.
UBSAN_RELAX="function,alignment,shift,signed-integer-overflow,unsigned-integer-overflow,implicit-integer-sign-change,enum,nonnull-attribute,returns-nonnull-attribute"
case "$SANITIZER_FLAGS" in
  *undefined*) SANITIZER_FLAGS="$SANITIZER_FLAGS -fno-sanitize=$UBSAN_RELAX" ;;
esac

# -fsanitize=fuzzer-no-link lets the instrumented library collect coverage feedback for libFuzzer.
case "$SANITIZER_FLAGS" in
  *fuzzer-no-link*) : ;;
  *) SANITIZER_FLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link" ;;
esac

# CUPS' fuzz harnesses include private headers and use deprecated APIs; mirror the upstream
# OSS-Fuzz build's defines and relax the warnings-as-errors the modern toolchain would raise.
EXTRA_CFLAGS="-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fPIE \
-Wno-error=deprecated-declarations -Wno-error=implicit-function-declaration -Wno-error=int-conversion"

export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE STANDALONE_FUZZ_MAIN MAYHEM_JOBS OUT SRC

cd "$SRC"
git config --global --add safe.directory "$SRC" 2>/dev/null || true
git rev-parse -q --verify HEAD >/dev/null \
  || { echo "ERROR: $SRC is not a git checkout (build.sh stages the unit-test inputs from HEAD)" >&2; exit 1; }

# ── 0) Refuse edits to the two make fragments rlenv's patch policy does not see as build files ─────
# rlenv rejects patches to build files by NAME (Makefile, configure, *.m4, ...). CUPS keeps its compiler
# and linker flags in Makedefs.in (configure turns it into Makedefs) and cups/Makefile includes
# cups/Dependencies; neither name is on that list. An edit to either can drop $SANITIZER_FLAGS from the
# library objects (every PoV then stops crashing with the program unchanged) or inject make rules, so a
# change to them is a build change, not a source patch, and fails the build here.
for f in Makedefs.in cups/Dependencies; do
  git diff --quiet HEAD -- "$f" \
    || { echo "ERROR: $f differs from the committed tree; it is a build-system file, not source (edit source files only)" >&2; exit 1; }
done

# LeakSanitizer off-switch (SPEC §6.2 item 15): linked into every fuzz target, standalone reproducer
# and unit-test program. Built first because step 1's LDFLAGS carries it into the unit-test links.
LSAN_OFF_O="$SRC/mayhem/lsan_off.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$LSAN_OFF_O"

# The cups unit-test programs test.sh runs (built in step 4).
UNIT_TESTS="testarray testfile testform testi18n testipp testjson testjwt testoptions testppd testpwg testraster"

# ── 1) Build the CUPS libraries (static, sanitized) ────────────────────────────────────────────
export CFLAGS="${CFLAGS:-} $SANITIZER_FLAGS $DEBUG_FLAGS $EXTRA_CFLAGS"
export CXXFLAGS="${CXXFLAGS:-} $SANITIZER_FLAGS $DEBUG_FLAGS $EXTRA_CFLAGS"
# lsan_off.o rides in LDFLAGS (make's ALL_LDFLAGS) so the unit-test links in step 4 carry the hook too.
export LDFLAGS="${LDFLAGS:-} $SANITIZER_FLAGS -fPIE $LSAN_OFF_O"

./configure --enable-static --disable-shared --with-tls=openssl
# Build ONLY the cups/ library subdir (libcups.a + libcupsimage.a — everything the harnesses link
# against). A full top-level `make` also compiles build-time codegen helpers in ppdc/ (genstrings,
# ppdc, …) with our halting sanitizers; those crash on benign UBSan findings (e.g. a NULL passed to
# a __nonnull memcpy in ppdc-array.cxx) and abort the whole build before any library is produced.
make -C cups libs -j"$MAYHEM_JOBS"

LIBCUPS="$SRC/cups/libcups.a"
LIBCUPSIMAGE="$SRC/cups/libcupsimage.a"
[ -f "$LIBCUPS" ]      || { echo "ERROR: $LIBCUPS not built" >&2; exit 1; }
[ -f "$LIBCUPSIMAGE" ] || { echo "ERROR: $LIBCUPSIMAGE not built" >&2; exit 1; }

# ── 2) ONE compile view for the harnesses AND the unit-test programs ──────────────────────────────
# test.sh's programs are the oracle for the graded fuzz targets, so the translation units of both sets
# are compiled by the same command line (tu_cmd below) and see the same headers; nothing a source patch
# can change differs between them (QA #1460 A class; the cups follow-up to #1120):
#   a) FLAGS: exactly the flags make uses for every cups/*.c object (the .c.o rule
#      `$(CC) $(ARCHFLAGS) $(OPTIM) $(ALL_CFLAGS)`, run from cups/), read from the configured Makedefs by
#      make itself; only -I paths and two warning switches are added. The predefined-macro sets are
#      asserted identical to make's below (hand-written flags once left out -Os, _FORTIFY_SOURCE,
#      _GNU_SOURCE, ..., so `#if !defined(__OPTIMIZE__)` in a header could steer the harness only).
#   b) HEADERS + SOURCES: the 9 harnesses, fuzz_helpers.cpp AND the 11 unit-test programs all compile
#      against ONE copy of the cups headers, the committed tree's (git HEAD), staged into mayhem-head/
#      and searched before make's `-I..`. The unit-test sources are compiled from that same HEAD copy, so
#      their own-directory "..." includes land in it too. A header a patch edits therefore changes only
#      the library objects (step 1), which both sets link: it cannot tell a harness TU from a unit-test TU
#      (a __FILE__/__BASE_FILE__ test, an include-guard probe, or a macro that renames a declaration so
#      that one side reaches the real function and the other a stub). Asserted in step 5: every repo
#      file either set reads is a HEAD-staged copy (or the configure-generated config.h, or the harness'
#      own vendored files), and each cups header is read from that one copy by both sets.
#   The cups library (step 1) is the only code compiled from the patched working tree and its headers.
HDIR="$SRC/mayhem/harnesses"
HEAD_DIR="$SRC/mayhem-head"
rm -rf "$HEAD_DIR"; mkdir -p "$HEAD_DIR/obj" "$HEAD_DIR/deps"
{ git ls-tree -z --name-only HEAD cups/ | grep -z -E '\.h$'
  for t in $UNIT_TESTS; do printf 'cups/%s.c\0' "$t"; done
} | xargs -0 git archive --format=tar HEAD -- | tar -C "$HEAD_DIR" -xf -
# The staged copy must be byte-identical to the HEAD blobs.
( cd "$HEAD_DIR" && find cups -type f | LC_ALL=C sort ) > "$HEAD_DIR/files.lst"
want="$(xargs git ls-tree HEAD -- < "$HEAD_DIR/files.lst" | awk -F'\t' '{ split($1, a, " "); print a[3], $2 }' | LC_ALL=C sort)"
# (absolute paths: git resolves relative --stdin-paths against the top of the work tree, not the cwd)
got="$(paste -d' ' <(sed "s|^|$HEAD_DIR/|" "$HEAD_DIR/files.lst" | git hash-object --no-filters --stdin-paths) "$HEAD_DIR/files.lst" | LC_ALL=C sort)"
[ -n "$want" ] && [ "$want" = "$got" ] && [ -s "$HEAD_DIR/cups/cups-private.h" ] && [ -s "$HEAD_DIR/cups/testppd.c" ] \
  || { echo "ERROR: could not stage the committed cups headers and unit-test sources from HEAD" >&2; exit 1; }
echo "staged from git HEAD into mayhem-head/: $(wc -l < "$HEAD_DIR/files.lst") files (cups/*.h + unit-test sources), blob-verified"
# `-I$HEAD_DIR/cups` serves the harnesses' <ppd-private.h> spellings, `-I$HEAD_DIR` serves <cups/ipp.h>; both come
# before make's `-I..` (the repo root, from cups/), which still supplies the configure-generated config.h
# (configure and config.h.in are build files to rlenv).
HINC="-I$HEAD_DIR/cups -I$HEAD_DIR"
TU_WFLAGS="-Wno-deprecated-declarations -Wno-unused-result"

mk_eval() { make -s --no-print-directory -C "$SRC/cups" --eval="mayhem-eval: ; $1" mayhem-eval; }
TU_CFLAGS="$(mk_eval '@echo $(ARCHFLAGS) $(OPTIM) $(ALL_CFLAGS)')"
TU_CXXFLAGS="$(mk_eval '@echo $(ARCHFLAGS) $(OPTIM) $(ALL_CXXFLAGS)')"
for w in $SANITIZER_FLAGS $DEBUG_FLAGS; do   # every TU must keep every sanitizer/debug flag
  case " $TU_CFLAGS " in *" $w "*) : ;; *) echo "ERROR: make's cups/*.c flags lack '$w': $TU_CFLAGS" >&2; exit 1 ;; esac
done
echo "harness + unit-test TU flags (from make): $TU_CFLAGS"

# tu_cmd <c|c++> — THE compile command of every harness and unit-test TU (run from cups/, like make).
tu_cmd() { if [ "$1" = c ]; then echo "$CC $HINC $TU_CFLAGS $TU_WFLAGS"; else echo "$CXX $HINC $TU_CXXFLAGS $TU_WFLAGS"; fi; }
# cc_tu <harness|unit> <c|c++> <source> <object>; -MD records every file the compile read (step 5).
cc_tu() { ( cd "$SRC/cups" && $(tu_cmd "$2") -MD -MF "$HEAD_DIR/deps/$1-$(basename "$4" .o).d" -c "$3" -o "$4" ); }

# Assert: the predefined-macro set of tu_cmd == that of make's own cups/*.c (and .cxx) compile line.
for lang in c c++; do
  if [ "$lang" = c ]; then theirs='$(CC) $(ARCHFLAGS) $(OPTIM) $(ALL_CFLAGS)'; else theirs='$(CXX) $(ARCHFLAGS) $(OPTIM) $(ALL_CXXFLAGS)'; fi
  m1="$(cd "$SRC/cups" && $(tu_cmd "$lang") -dM -E -x "$lang" /dev/null | LC_ALL=C sort -u)"
  m2="$(mk_eval "$theirs -dM -E -x $lang /dev/null" | LC_ALL=C sort -u)"
  [ -n "$m1" ] && [ "$m1" = "$m2" ] || {
    echo "ERROR: harness/unit-test ($lang) predefined macros differ from make's cups/*.c compile:" >&2
    diff <(printf '%s\n' "$m2") <(printf '%s\n' "$m1") >&2 || true; exit 1; }
done
echo "harness + unit-test TU predefined macros == make's cups/*.c macros (C and C++): OK"

# ── 3) Build each OSS-Fuzz harness: libFuzzer (-> $OUT/<name>) + standalone reproducer ──────────
# Link libs mirror OpenPrinting/fuzzing's fuzzer/Makefile.
AVAHI_LIBS="$(pkg-config --libs avahi-client 2>/dev/null || echo '-lavahi-client -lavahi-common')"
DBUS_LIBS="$(pkg-config --libs dbus-1 2>/dev/null || echo '-ldbus-1')"
LINK_LIBS="-L$SRC/cups -lcups -lcupsimage -lz -lpthread $AVAHI_LIBS $DBUS_LIBS -lssl -lcrypto -lcrypt -lsystemd -lm"

# fuzz_helpers.cpp provides the FuzzedDataProvider glue that fuzz_array links against.
cc_tu harness c++ "$HDIR/fuzz_helpers.cpp" "$SRC/mayhem/fuzz_helpers.o"

# Standalone driver object (no libFuzzer runtime; reads one input file at a time; includes no cups header).
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$SRC/mayhem/standalone_main.o"

HARNESSES="fuzz_ipp fuzz_ipp_gen fuzz_raster fuzz_cups fuzz_ppd_gen_1 fuzz_ppd_gen_conflicts fuzz_ppd_gen_cache fuzz_array fuzz_http_core"
for harness in $HARNESSES; do
  cc_tu harness c "$HDIR/$harness.c" "$SRC/mayhem/$harness.o"

  # libFuzzer target -> $OUT/<name>  (link with CXX: fuzz_helpers.o is C++)
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$SRC/mayhem/$harness.o" "$SRC/mayhem/fuzz_helpers.o" \
       "$LSAN_OFF_O" $LINK_LIBS -o "$OUT/$harness"

  # standalone reproducer (no libFuzzer runtime) -> $OUT/<name>-standalone
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$SRC/mayhem/$harness.o" "$SRC/mayhem/fuzz_helpers.o" "$SRC/mayhem/standalone_main.o" \
       "$LSAN_OFF_O" $LINK_LIBS -o "$OUT/$harness-standalone"

  echo "built $harness (+ standalone)"
done

# ── 4) Build cups' OWN unit tests the same way, linked against the SAME sanitized libraries ────────
# test.sh is the functional oracle for PATCH grading, so the programs it runs must contain exactly the
# library code the graded fuzz targets contain, compiled the same way. Each program is compiled from its
# HEAD source in mayhem-head/cups/ by tu_cmd (step 2) and linked by make's own unit-test link line
# (`$(LD_CC) $(ARCHFLAGS) $(ALL_LDFLAGS) -o $@ <program>.o $(LINKCUPSSTATIC)`) against step 1's libcups.a,
# with step 1's LDFLAGS ($SANITIZER_FLAGS, lsan_off.o). A patch that disables code only in a sanitizer-
# or fuzzing-mode build (#if __has_feature(address_sanitizer), #ifdef FUZZING_BUILD_MODE_...) therefore
# changes the unit tests exactly as it changes the fuzz targets (QA #1460 section A; reference pattern
# fast_rsync #1122). Nothing is copied from the working tree, so files a patch creates or deletes
# cannot break this step (QA #1120 follow-up: a patch is applied without --index).
#
# Failure policy: a unit-test program that fails to compile or link is NOT fatal (a source patch may
# legitimately break one); it is simply absent from mayhem-tests/bin and test.sh reports it as FAIL.
#
# The programs' INPUT files are staged from the committed tree (git HEAD), never from the working tree:
# several of them (locale/*.po for testppd, cups/utf8demo.txt for testi18n, the cups/*.[ch] word lists
# testarray loads from its cwd) sit outside rlenv's scrubbed paths, so a patch could otherwise edit what
# the oracle reads (QA #1460 pforth class). The patch is applied to the working tree only, so HEAD is
# the pristine commit.
if [ "${SKIP_TESTS:-0}" != "1" ]; then
  TESTRUN="$SRC/mayhem-tests"
  rm -rf "$TESTRUN"
  mkdir -p "$TESTRUN/bin"
  UT_LD="$(mk_eval '@echo $(LD_CC) $(ARCHFLAGS) $(ALL_LDFLAGS)')"
  UT_LIBS="$(mk_eval '@echo $(LINKCUPSSTATIC)')"
  echo "unit-test link line (from make): $UT_LD -o <program> <program>.o $UT_LIBS"
  for t in $UNIT_TESTS; do
    if cc_tu unit c "$HEAD_DIR/cups/$t.c" "$HEAD_DIR/obj/$t.o" \
       && ( cd "$SRC/cups" && $UT_LD -o "$TESTRUN/bin/$t" "$HEAD_DIR/obj/$t.o" $UT_LIBS ); then
      echo "built unit test $t"
    else
      rm -f "$TESTRUN/bin/$t"
      echo "WARNING: unit test $t failed to build (test.sh will report it as FAIL)" >&2
    fi
  done
  # Pristine inputs: the fixtures and data files the programs open, plus every committed cups/*.c|*.h
  # (testarray's "Load unique words" reads all *.c/*.h files in its working directory).
  {
    printf '%s\0' cups/test.ppd cups/test2.ppd cups/testfile.txt cups/testipp.test cups/utf8demo.txt \
                  locale/cups_fr.po locale/cups_zh_TW.po
    git ls-tree -z --name-only HEAD cups/ | grep -z -E '\.[ch]$'
  } | xargs -0 git archive --format=tar HEAD -- | tar -C "$TESTRUN" -xif -
  [ -s "$TESTRUN/cups/test.ppd" ] && [ -s "$TESTRUN/locale/cups_fr.po" ] \
    || { echo "ERROR: could not stage the unit-test inputs from HEAD" >&2; exit 1; }
fi

# ── 5) Assert the header view the harnesses and the unit tests compiled against ─────────────────
# From the -MD records of the real compiles: every file under $SRC that a harness or unit-test TU read
# must be a HEAD-staged copy in mayhem-head/cups/, the configure-generated config.h, or (harness TUs
# only) the harness' own vendored files in mayhem/harnesses/; files outside $SRC belong to the system
# and toolchain. A working-tree cups header reached by either set fails the build, and so does a header
# name read from two different copies. (The two sets include different subsets of the cups headers;
# what must match is the copy each header comes from, and both sets read the same one, from HEAD.)
SRC_R="$(realpath "$SRC")"; HEAD_R="$(realpath "$HEAD_DIR")/cups/"; HDIR_R="$(realpath "$HDIR")/"
hv_files() {   # hv_files <dep-file>... -> the resolved paths those compiles read, one per line
  sed -s -e 's/\\$//' -e '1s/^[^:]*://' "$@" | tr -s ' \t' '\n\n' | sed '/^$/d' \
    | ( cd "$SRC/cups" && xargs -r realpath -m -- ) | LC_ALL=C sort -u
}
hv_bad() {     # hv_bad <allowed-extra-prefix|''> < paths -> the repo paths outside the allowed copies
  awk -v s="$SRC_R/" -v h="$HEAD_R" -v c="$SRC_R/config.h" -v x="$1" \
    'index($0, s) == 1 && !(index($0, h) == 1 && index(substr($0, length(h) + 1), "/") == 0) \
       && $0 != c && !(x != "" && index($0, x) == 1)'
}
H_FILES="$(hv_files "$HEAD_DIR"/deps/harness-*.d)"
U_FILES=""
if compgen -G "$HEAD_DIR/deps/unit-*.d" >/dev/null; then U_FILES="$(hv_files "$HEAD_DIR"/deps/unit-*.d)"; fi
bad="$( { printf '%s\n' "$H_FILES" | hv_bad "$HDIR_R"; printf '%s\n' "$U_FILES" | hv_bad ''; } | LC_ALL=C sort -u)"
dup="$(printf '%s\n' "$H_FILES" "$U_FILES" | awk -v s="$SRC_R/" 'index($0, s) == 1 && /\.h$/' | LC_ALL=C sort -u \
         | awk -F/ '{ print $NF }' | LC_ALL=C sort | uniq -d)"
if [ -n "$bad" ] || [ -n "$dup" ]; then
  echo "ERROR: a harness or unit-test compile read repo files outside the HEAD-staged header copy:" >&2
  printf '  %s\n' $bad >&2; [ -z "$dup" ] || printf '  header read from two copies: %s\n' $dup >&2
  exit 1
fi
h_hdr="$(printf '%s\n' "$H_FILES" | awk -v h="$HEAD_R" 'index($0, h) == 1 && /\.h$/')"
u_hdr="$(printf '%s\n' "$U_FILES" | awk -v h="$HEAD_R" 'index($0, h) == 1 && /\.h$/')"
echo "header view: harness TUs read $(printf '%s' "$h_hdr" | grep -c .) cups headers, unit-test TUs $(printf '%s' "$u_hdr" | grep -c .)," \
     "$(comm -12 <(printf '%s\n' "$h_hdr") <(printf '%s\n' "$u_hdr") | grep -c .) shared; all from the HEAD copy in mayhem-head/cups: OK"

echo "build.sh complete:"
for h in $HARNESSES; do ls -la "$OUT/$h" 2>&1 || true; done
