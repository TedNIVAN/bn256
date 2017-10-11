cmake_minimum_required(VERSION 3.8)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_COMPILER gcc)
set(CMAKE_VERBOSE_MAKEFILE on)
set(CMAKE_ASM_COMPILER gcc)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
enable_language(ASM)

project(bn256)
FUNCTION(PREPEND var prefix)
    SET(listVar "")
    FOREACH (f ${ARGN})
        LIST(APPEND listVar "${prefix}/${f}")
    ENDFOREACH (f)
    SET(${var} "${listVar}" PARENT_SCOPE)
ENDFUNCTION(PREPEND)

set(CMAKE_C_STANDARD 99)
include_directories(dclxvi)
set(DCLXVI_SOURCES linefunction.c optate.c fpe.c fp2e.c fp6e.c fp12e.c curvepoint_fp.c twistpoint_fp2.c final_expo.c scalar.c
        parameters.c mul.c mydouble.c fp2e_add2.s fp2e_sub2.s fp2e_double2.s fp2e_triple2.s fp2e_neg2.s fp2e_mul.s
        fp2e_mul_fpe.s fp2e_short_coeffred.s fp2e_add.s fp2e_sub.s fp2e_parallel_coeffmul.s fp2e_mulxi.s fp2e_double.s
        fp2e_triple.s fp2e_neg.s fp2e_conjugate.s fpe_mul.s fp2e_square.s consts.s)
PREPEND(DCLXVI_SOURCES dclxvi/ ${DCLXVI_SOURCES})
add_library(bn256 SHARED ${DCLXVI_SOURCES})

add_executable(test_bn256 bn256.c bn256_ibe.c bn256_bls.c crypto_salsa.c test_bn256.c bn256.h bn256_ibe.h bn256_bls.h crypto.h)