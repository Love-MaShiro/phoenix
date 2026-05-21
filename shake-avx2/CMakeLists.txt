cmake_minimum_required(VERSION 3.16)

project(shake_avx2_stub C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(PARAMS "phoenix-shake-256s" CACHE STRING "Parameter set under params/")
set(THASH "simple" CACHE STRING "THASH backend variant: simple or robust")
set(SPX_AVX2_FLAGS "-mavx2" CACHE STRING "Extra compiler flags required for the AVX2 Keccak x4 backend")
set_property(CACHE THASH PROPERTY STRINGS simple robust)

if(NOT PARAMS MATCHES "^phoenix-shake-")
    message(FATAL_ERROR "shake-avx2 only supports SHAKE parameter sets, got: ${PARAMS}")
endif()

if(NOT THASH STREQUAL "simple" AND NOT THASH STREQUAL "robust")
    message(FATAL_ERROR "THASH must be simple or robust, got: ${THASH}")
endif()

set(SPX_COMMON_SOURCES
    address.c
    counter.c
    fips202.c
    fips202x4.c
    hash_shake.c
    hash_shake256x4.c
    keccak4x/KeccakP-1600-times4-SIMD256.c
    merkle.c
    octopus.c
    randombytes.c
    sign.c
    tfors.c
    utils.c
    utilsx1.c
    utilsx4.c
    wots.c
    wotsx1.c
    thash_shake_${THASH}.c
    thash_shake_${THASH}x4.c
)

set(SPX_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/test
)

add_library(spx_shake_ref STATIC ${SPX_COMMON_SOURCES})
target_include_directories(spx_shake_ref PUBLIC ${SPX_INCLUDE_DIRS})
target_compile_definitions(spx_shake_ref PUBLIC PARAMS=${PARAMS} PARAMNAME="${PARAMS}" THASH_VARIANT_${THASH} ALLOW_DEEP_TREES)
separate_arguments(SPX_AVX2_FLAGS_LIST NATIVE_COMMAND "${SPX_AVX2_FLAGS}")
target_compile_options(spx_shake_ref PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wmissing-prototypes ${SPX_AVX2_FLAGS_LIST})

set(SPX_TESTS tfors spx octopus gwots hashx4 utilsx4 thashx4)

foreach(test_name IN LISTS SPX_TESTS)
    add_executable(test_${test_name} test/${test_name}.c test/cycles.c)
    target_link_libraries(test_${test_name} PRIVATE spx_shake_ref)
    target_include_directories(test_${test_name} PRIVATE ${SPX_INCLUDE_DIRS})
    target_compile_options(test_${test_name} PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wmissing-prototypes ${SPX_AVX2_FLAGS_LIST})
endforeach()

foreach(bench_name IN ITEMS benchmark x4_benchmark tfors_benchmark gwots_benchmark)
    add_executable(${bench_name} test/${bench_name}.c test/cycles.c)
    target_link_libraries(${bench_name} PRIVATE spx_shake_ref)
    target_include_directories(${bench_name} PRIVATE ${SPX_INCLUDE_DIRS})
    target_compile_options(${bench_name} PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wmissing-prototypes ${SPX_AVX2_FLAGS_LIST})
endforeach()

find_package(OpenSSL QUIET)
if(OpenSSL_FOUND)
    add_executable(PQCgenKAT_sign
        PQCgenKAT_sign.c
        address.c
        counter.c
        fips202.c
        fips202x4.c
        hash_shake.c
        hash_shake256x4.c
        keccak4x/KeccakP-1600-times4-SIMD256.c
        merkle.c
        octopus.c
        rng.c
        sign.c
        tfors.c
        utils.c
        utilsx1.c
        utilsx4.c
        wots.c
        wotsx1.c
        thash_shake_${THASH}.c
        thash_shake_${THASH}x4.c
    )
    target_include_directories(PQCgenKAT_sign PRIVATE ${SPX_INCLUDE_DIRS})
    target_compile_definitions(PQCgenKAT_sign PRIVATE PARAMS=${PARAMS} PARAMNAME="${PARAMS}" THASH_VARIANT_${THASH} ALLOW_DEEP_TREES)
    target_compile_options(PQCgenKAT_sign PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wmissing-prototypes ${SPX_AVX2_FLAGS_LIST})
    target_link_libraries(PQCgenKAT_sign PRIVATE OpenSSL::Crypto)

    add_executable(test_x4_consistency
        test/test_x4_consistency.c
        address.c
        counter.c
        fips202.c
        fips202x4.c
        hash_shake.c
        hash_shake256x4.c
        keccak4x/KeccakP-1600-times4-SIMD256.c
        merkle.c
        octopus.c
        rng.c
        sign.c
        tfors.c
        utils.c
        utilsx1.c
        utilsx4.c
        wots.c
        wotsx1.c
        thash_shake_${THASH}.c
        thash_shake_${THASH}x4.c
    )
    target_include_directories(test_x4_consistency PRIVATE ${SPX_INCLUDE_DIRS})
    target_compile_definitions(test_x4_consistency PRIVATE PARAMS=${PARAMS} PARAMNAME="${PARAMS}" THASH_VARIANT_${THASH} ALLOW_DEEP_TREES)
    target_compile_options(test_x4_consistency PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wmissing-prototypes ${SPX_AVX2_FLAGS_LIST})
    target_link_libraries(test_x4_consistency PRIVATE OpenSSL::Crypto)
else()
    message(STATUS "OpenSSL not found: skipping PQCgenKAT_sign target")
endif()
