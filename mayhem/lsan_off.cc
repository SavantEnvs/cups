// Build-time LeakSanitizer off-switch (fleet convention, SPEC §6.2 item 15).
//
// -fsanitize=address always bundles LeakSanitizer; leaks are not the defect class this target is
// fuzzed for. LSan consults this hook at exit, so leak detection is skipped while ASan's memory-error
// checks and UBSan stay fully active. build.sh compiles it with $SANITIZER_FLAGS and links it into
// every fuzz target, every -standalone reproducer and every unit-test program test.sh runs.
extern "C" int __lsan_is_turned_off() { return 1; }
