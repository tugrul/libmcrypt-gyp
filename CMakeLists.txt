# CMake build for libmcrypt-gyp: the same static library that libmcrypt.gyp
# builds, for projects that do not use node-gyp.
#
# Use it from another project with add_subdirectory() or FetchContent and link
# the libmcrypt::libmcrypt target:
#
#     add_subdirectory(third_party/libmcrypt)
#     target_link_libraries(app PRIVATE libmcrypt::libmcrypt)
#
# There are no install rules on purpose. The mcrypt.h in this tree is not
# API-compatible with upstream libmcrypt 2.5.8 (the directory arguments are
# gone), so it must not land where a system libmcrypt is expected.

cmake_minimum_required(VERSION 3.14...3.31)

project(libmcrypt VERSION 2.5.8 LANGUAGES C)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(LIBMCRYPT_IS_TOP_LEVEL ON)
else()
    set(LIBMCRYPT_IS_TOP_LEVEL OFF)
endif()

option(LIBMCRYPT_BUILD_TESTS
    "Build the libmcrypt self-test program and register it with CTest"
    ${LIBMCRYPT_IS_TOP_LEVEL})

include(CheckIncludeFile)
include(CheckSymbolExists)
include(CheckTypeSize)

# ---------------------------------------------------------------------------
# Sources. Keep this list in step with 'sources' in libmcrypt.gyp.
# ---------------------------------------------------------------------------
set(LIBMCRYPT_SOURCES
    modules/algorithms/3-way.c
    modules/algorithms/arcfour.c
    modules/algorithms/blowfish.c
    modules/algorithms/blowfish-compat.c
    modules/algorithms/cast-128.c
    modules/algorithms/cast-256.c
    modules/algorithms/des.c
    modules/algorithms/enigma.c
    modules/algorithms/gost.c
    modules/algorithms/loki97.c
    modules/algorithms/panama.c
    modules/algorithms/rc2.c
    modules/algorithms/rijndael-128.c
    modules/algorithms/rijndael-192.c
    modules/algorithms/rijndael-256.c
    modules/algorithms/safer64.c
    modules/algorithms/safer128.c
    modules/algorithms/saferplus.c
    modules/algorithms/serpent.c
    modules/algorithms/tripledes.c
    modules/algorithms/twofish.c
    modules/algorithms/wake.c
    modules/algorithms/xtea.c
    modules/modes/cbc.c
    modules/modes/cfb.c
    modules/modes/ctr.c
    modules/modes/ecb.c
    modules/modes/ncfb.c
    modules/modes/nofb.c
    modules/modes/ofb.c
    modules/modes/stream.c
    lib/bzero.c
    lib/mcrypt.c
    lib/mcrypt_extra.c
    lib/mcrypt_modules.c
    lib/mcrypt_symb.c
    lib/xmemory.c
)

# Always static: the library is meant to be linked into the consumer, and a
# shared "libmcrypt" would be mistaken for the upstream one.
add_library(libmcrypt STATIC ${LIBMCRYPT_SOURCES})
add_library(libmcrypt::libmcrypt ALIAS libmcrypt)

set_target_properties(libmcrypt PROPERTIES
    OUTPUT_NAME mcrypt
    # The sources are pre-C99 style C (K&R declarations) and stop compiling
    # as C23, the default of GCC 15 and later. gnu99, not c99: strdup() and
    # mlock() need the extensions.
    C_STANDARD 99
    C_EXTENSIONS ON
)

# Position-independent by default so the library can go into a shared object
# or a plugin. Set CMAKE_POSITION_INDEPENDENT_CODE yourself to override.
if(NOT DEFINED CMAKE_POSITION_INDEPENDENT_CODE)
    set_target_properties(libmcrypt PROPERTIES POSITION_INDEPENDENT_CODE ON)
endif()

target_include_directories(libmcrypt
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/lib
)

# ---------------------------------------------------------------------------
# Configuration. libmcrypt.gyp hard-codes these per operating system; here
# they are detected, as upstream's configure script did.
# ---------------------------------------------------------------------------
target_compile_definitions(libmcrypt PRIVATE
    STDC_HEADERS
    VERSION="${PROJECT_VERSION}"
    # Without this, libdefs.h marks every function __declspec(dllexport) on
    # Windows and the consumer's executable ends up exporting them all.
    LIBMCRYPT_STATIC
    # C89 functions. libdefs.h refuses to compile without one of
    # memmove/bcopy, and Bzero() prefers memset over bzero.
    HAVE_MEMMOVE
    HAVE_MEMSET
)

check_include_file(sys/types.h LIBMCRYPT_HAVE_SYS_TYPES_H)
check_include_file(strings.h   LIBMCRYPT_HAVE_STRINGS_H)
check_include_file(unistd.h    LIBMCRYPT_HAVE_UNISTD_H)
check_include_file(byteswap.h  LIBMCRYPT_HAVE_BYTESWAP_H)
check_include_file(sys/mman.h  LIBMCRYPT_HAVE_SYS_MMAN_H)

foreach(header SYS_TYPES_H STRINGS_H UNISTD_H BYTESWAP_H)
    if(LIBMCRYPT_HAVE_${header})
        target_compile_definitions(libmcrypt PRIVATE HAVE_${header})
    endif()
endforeach()

# Key material is mlock()ed where the platform has it.
if(LIBMCRYPT_HAVE_SYS_MMAN_H)
    check_symbol_exists(mlock "sys/mman.h" LIBMCRYPT_HAVE_MLOCK)
    if(LIBMCRYPT_HAVE_MLOCK)
        target_compile_definitions(libmcrypt PRIVATE HAVE_SYS_MMAN_H HAVE_MLOCK)
    endif()
endif()

# libdefs.h picks its 32, 16 and 8 bit types from these.
check_type_size("unsigned char"      LIBMCRYPT_SIZEOF_UNSIGNED_CHAR)
check_type_size("unsigned short int" LIBMCRYPT_SIZEOF_UNSIGNED_SHORT_INT)
check_type_size("unsigned int"       LIBMCRYPT_SIZEOF_UNSIGNED_INT)
check_type_size("unsigned long int"  LIBMCRYPT_SIZEOF_UNSIGNED_LONG_INT)

foreach(type UNSIGNED_CHAR UNSIGNED_SHORT_INT UNSIGNED_INT UNSIGNED_LONG_INT)
    if(NOT LIBMCRYPT_SIZEOF_${type})
        message(FATAL_ERROR "libmcrypt: could not determine sizeof(${type})")
    endif()
    target_compile_definitions(libmcrypt PRIVATE
        SIZEOF_${type}=${LIBMCRYPT_SIZEOF_${type}})
endforeach()

# Byte order. libdefs.h also derives this from the compiler's __BYTE_ORDER__;
# defining it here covers compilers that do not provide that macro.
if(DEFINED CMAKE_C_BYTE_ORDER)
    if(CMAKE_C_BYTE_ORDER STREQUAL "BIG_ENDIAN")
        set(LIBMCRYPT_BIG_ENDIAN ON)
    endif()
else()
    include(TestBigEndian)
    test_big_endian(LIBMCRYPT_BIG_ENDIAN)
endif()
if(LIBMCRYPT_BIG_ENDIAN)
    target_compile_definitions(libmcrypt PRIVATE WORDS_BIGENDIAN)
endif()

# The upstream sources are noisy under -Wall. As a subproject, do not let the
# parent's warning flags (or -Werror) decide whether this library builds.
if(NOT LIBMCRYPT_IS_TOP_LEVEL)
    if(MSVC)
        target_compile_options(libmcrypt PRIVATE /w)
    else()
        target_compile_options(libmcrypt PRIVATE -w)
    endif()
endif()

# ---------------------------------------------------------------------------
# Self-test: on by default only when this is the top-level project.
# ---------------------------------------------------------------------------
if(LIBMCRYPT_BUILD_TESTS)
    enable_testing()
    add_executable(libmcrypt_selftest test/selftest.c)
    target_link_libraries(libmcrypt_selftest PRIVATE libmcrypt::libmcrypt)
    add_test(NAME libmcrypt_selftest COMMAND libmcrypt_selftest)
endif()
