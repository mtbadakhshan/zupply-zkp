# Add Google Benchmark
set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "Disable GTest tests in Benchmark" FORCE)
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "Disable testing of the Benchmark" FORCE)
add_subdirectory(benchmark)

add_subdirectory(libsnark)
target_compile_options(gmock PRIVATE -Wno-deprecated-copy)


OPTION(IS_LIBIOP_PARENT OFF)
add_subdirectory(libiop)
