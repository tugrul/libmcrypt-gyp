# libmcrypt-gyp

[![CI](https://github.com/tugrul/libmcrypt-gyp/actions/workflows/ci.yml/badge.svg)](https://github.com/tugrul/libmcrypt-gyp/actions/workflows/ci.yml)

libmcrypt 2.5.8 as one static library that builds with
[node-gyp](https://github.com/nodejs/node-gyp) or CMake. There is no autotools
step and nothing is loaded at run time: every algorithm and mode is compiled in.

It exists so that [node-mcrypt](https://github.com/tugrul/node-mcrypt) does not
need a system libmcrypt package, which Windows does not have. Any C or C++
project can use it the same way.

libmcrypt gives one interface to 19 block and stream ciphers in 8 modes of
operation. Each of them produces the same output here as in upstream 2.5.8.

> **Before you pick it for something new:** upstream's last release is 2.5.8,
> from February 2007. The library has no authenticated encryption, and its list
> includes ciphers that are long obsolete, such as DES and RC4. Use it where
> existing data or existing software needs mcrypt.

- [Using it from a Node addon](#using-it-from-a-node-addon)
- [Using it from a CMake project](#using-it-from-a-cmake-project)
- [A first program](#a-first-program)
- [Algorithms](#algorithms) and [modes](#modes)
- [How the API behaves](#how-the-api-behaves)
- [Function reference](#function-reference)
- [The same ciphers in OpenSSL](#the-same-ciphers-in-openssl)
- [Differences from upstream libmcrypt](#differences-from-upstream-libmcrypt)
- [Known problems](#known-problems)
- [Building and testing this repository](#building-and-testing-this-repository)
- [Platform notes](#platform-notes)
- [Repository layout](#repository-layout)
- [Adding an algorithm or a mode](#adding-an-algorithm-or-a-mode)

## Using it from a Node addon

Put the repository below your addon, for example as a submodule:

```sh
git submodule add https://github.com/tugrul/libmcrypt-gyp.git lib/libmcrypt
```

and depend on its target in `binding.gyp`:

```python
{
    'targets': [{
        'target_name': 'addon',
        'sources': ['src/addon.cc'],
        'dependencies': ['lib/libmcrypt/libmcrypt.gyp:libmcrypt'],
        'include_dirs': ['lib/libmcrypt/include/']
    }]
}
```

Then `#include <mcrypt.h>`.

The copy has to sit in or below the directory of your `binding.gyp`. With a
`.gyp` file in a parent directory, gyp's make generator writes the library on
top of itself and the build fails.

`libmcrypt.gyp` has settings for Linux, macOS, FreeBSD and Windows. On another
operating system the build stops in `lib/libdefs.h` with `Cannot find a 32 bit
integer in your system`; use the CMake build there.

## Using it from a CMake project

With a copy in your tree:

```cmake
add_subdirectory(third_party/libmcrypt)
target_link_libraries(app PRIVATE libmcrypt::libmcrypt)
```

or fetched at configure time:

```cmake
include(FetchContent)
FetchContent_Declare(libmcrypt
    GIT_REPOSITORY https://github.com/tugrul/libmcrypt-gyp.git
    GIT_TAG        <commit>)  # there are no release tags: pin a commit
FetchContent_MakeAvailable(libmcrypt)
target_link_libraries(app PRIVATE libmcrypt::libmcrypt)
```

Then `#include <mcrypt.h>`.

| | |
| --- | --- |
| CMake version | 3.14 or newer |
| Library type | Always static, built as position-independent code so it can go into a shared library or a plugin. Set `CMAKE_POSITION_INDEPENDENT_CODE` yourself to change that. |
| Install rules | None, on purpose. The `mcrypt.h` here is not compatible with upstream's, so it must not land where a system libmcrypt is expected. |
| `LIBMCRYPT_BUILD_TESTS` | Builds the self-test and registers it with CTest. `ON` when this is the top-level project, `OFF` when it is pulled into another one. |
| `LIBMCRYPT_C_STANDARD` | The C standard the library is compiled as: `99` (the default), `11`, `17` or `23`, always with the GNU extensions. `23` needs CMake 3.21. |
| Warnings | When pulled into another project the library is compiled with its warnings off, so your `-Werror` does not decide whether it builds. |

## A first program

```c
#include <stdio.h>
#include <mcrypt.h>

int main(void)
{
    /* AES-128 in CBC mode, first block of NIST SP 800-38A, F.2.1 */
    unsigned char key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                              0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    unsigned char iv[16]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    unsigned char buf[16] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                              0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
    int i, rc;

    MCRYPT td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, MCRYPT_CBC);
    if (td == MCRYPT_FAILED) {
        fputs("unknown algorithm or mode, or the two do not go together\n", stderr);
        return 1;
    }

    rc = mcrypt_generic_init(td, key, sizeof key, iv);
    if (rc < 0) {
        fprintf(stderr, "mcrypt_generic_init: %s", mcrypt_strerror(rc));
        mcrypt_module_close(td);
        return 1;
    }

    mcrypt_generic(td, buf, sizeof buf);            /* encrypts buf in place */
    for (i = 0; i < 16; i++)
        printf("%02x", buf[i]);
    printf("\n");                                   /* 7649abac8119b246cee98e9b12e9197d */

    mcrypt_generic_deinit(td);                      /* drop the key and the chaining state */
    mcrypt_generic_init(td, key, sizeof key, iv);   /* same handle, fresh state */
    mdecrypt_generic(td, buf, sizeof buf);          /* decrypts buf in place */
    for (i = 0; i < 16; i++)
        printf("%02x", buf[i]);
    printf("\n");                                   /* 6bc1bee22e409f96e93d7e117393172a */

    mcrypt_generic_end(td);                         /* deinit and close in one call */
    return 0;
}
```

The header declares algorithm and mode names as `char *`, not `const char *`.
That is fine in C. A C++ compiler warns when a string literal is passed, so
cast it: `const_cast<char *>("cbc")`.

## Algorithms

`mcrypt_module_open()` takes the name in the first column. `_` is accepted in
place of `-` (`rijndael_128`). There are no other aliases: `aes` is not a name.

| Name | Cipher | Block (bytes) | Key (bytes) | Notes |
| --- | --- | --- | --- | --- |
| `rijndael-128` | Rijndael, 128-bit block | 16 | 16, 24, 32 | This is AES-128, AES-192 and AES-256. |
| `rijndael-192` | Rijndael, 192-bit block | 24 | 16, 24, 32 | Not AES. |
| `rijndael-256` | Rijndael, 256-bit block | 32 | 16, 24, 32 | Not AES, whatever the key size. |
| `twofish` | Twofish | 16 | 16, 24, 32 | |
| `serpent` | Serpent | 16 | 16, 24, 32 | |
| `cast-256` | CAST-256 | 16 | 16, 24, 32 | |
| `loki97` | LOKI97 | 16 | 16, 24, 32 | |
| `saferplus` | SAFER+ | 16 | 16, 24, 32 | |
| `blowfish` | Blowfish | 8 | 1 to 56 | |
| `blowfish-compat` | Blowfish with byte-swapped words | 8 | 1 to 56 | Every 32-bit word of input and output is byte-swapped compared with `blowfish`. Kept for data written by old libmcrypt versions. |
| `tripledes` | Triple DES, three keys (EDE) | 8 | 24 | |
| `des` | DES | 8 | 8 | |
| `cast-128` | CAST-128 (CAST5) | 8 | 16 | |
| `gost` | GOST 28147-89 | 8 | 32 | With the S-boxes printed in *Applied Cryptography*, according to upstream's manual. |
| `rc2` | RC2 | 8 | 1 to 128 | The effective key length is fixed at 1024 bits. |
| `xtea` | XTEA | 8 | 16 | |
| `arcfour` | RC4 | stream | 1 to 256 | |
| `wake` | WAKE | stream | 32 | |
| `enigma` | The one-rotor machine of Unix `crypt(1)` | stream | 1 to 13 | See [Known problems](#known-problems). |

Block algorithms work with every mode except `stream`. Stream algorithms work
with `stream` only. That makes 115 valid pairs.

Four more ciphers are compiled but cannot be opened, as in upstream's default
build: 3-way, Panama, SAFER-SK64 and SAFER-SK128. The header still defines
`MCRYPT_3WAY`, `MCRYPT_SAFER_SK64` and `MCRYPT_SAFER_SK128`; opening them
fails. [Adding an algorithm or a mode](#adding-an-algorithm-or-a-mode) says how
to switch them on.

## Modes

| Name | Mode | IV | Data length per call |
| --- | --- | --- | --- |
| `cbc` | Cipher block chaining | one block | whole blocks |
| `ecb` | Electronic codebook | none | whole blocks |
| `cfb` | Cipher feedback, 8 bits at a time | one block | any |
| `ncfb` | Cipher feedback, a whole block at a time | one block | any |
| `ofb` | Output feedback, 8 bits at a time | one block | any |
| `nofb` | Output feedback, a whole block at a time | one block | any |
| `ctr` | Counter | one block, the first counter value | any |
| `stream` | For the stream algorithms | none | any |

What most other libraries call CFB and OFB are `ncfb` and `nofb` here. `cfb`
is CFB-8, and `ofb` is an 8-bit OFB that has no counterpart in OpenSSL.

The header has macros for some names only (`MCRYPT_CBC`, `MCRYPT_ECB`,
`MCRYPT_CFB`, `MCRYPT_OFB`, `MCRYPT_nOFB`, `MCRYPT_STREAM`). For `ctr`, `ncfb`
and `blowfish-compat` pass the string.

## How the API behaves

### The life of a handle

1. `mcrypt_module_open(algorithm, mode)` returns a handle, or `MCRYPT_FAILED`
   when a name is unknown or a block algorithm is paired with `stream` (or a
   stream algorithm with any other mode).
2. `mcrypt_generic_init(td, key, key_length, iv)` sets the key and the IV. It
   returns 0, or a negative error code.
3. `mcrypt_generic(td, data, length)` encrypts and `mdecrypt_generic(td, data,
   length)` decrypts, both in place. They return 0 on success. Each call
   continues where the previous one stopped, so a long message can be
   processed in pieces.
4. `mcrypt_generic_deinit(td)` drops the key. The handle can then be
   initialised again or closed with `mcrypt_module_close(td)`.
   `mcrypt_generic_end(td)` does both.

### Keys

- The key bytes are used as given. There is no password hashing or key
  derivation.
- A key of length 0, or longer than `mcrypt_enc_get_key_size(td)`, is refused
  with error -3.
- **A key shorter than the next supported size is padded with zero bytes, and
  no error is reported.** A 20-byte key for `rijndael-128` is used as a 24-byte
  key ending in four zero bytes. Check the length yourself if you want such
  keys refused. `mcrypt_enc_get_supported_key_sizes()` gives the sizes; an
  empty list means every length up to the longest is used as it is.

### IVs

- `mcrypt_enc_get_iv_size(td)` gives the size: the block size for block
  algorithms, 0 for the three stream algorithms. `ecb` ignores the IV;
  `mcrypt_enc_mode_has_iv(td)` returns 0 for it.
- Passing `NULL` means an IV of all zero bytes.
- The library does not generate IVs and does not store them with the
  ciphertext. Both are up to you.

### Data length and padding

- **`cbc` and `ecb` process whole blocks only.** Bytes after the last whole
  block are left as they are, unencrypted, and the call still returns 0. A
  length of 1 or more bytes but less than one block returns -1. Nothing is
  padded for you: add and remove padding (PKCS#7, for example) yourself.
- The other modes take any length, and the output has the length of the input.
- Splitting the data across calls gives the same result as one call, at block
  boundaries for `cbc` and `ecb` and anywhere for the other modes.

### Memory

| Returned by | Free with |
| --- | --- |
| `mcrypt_list_algorithms()`, `mcrypt_list_modes()` | `mcrypt_free_p(list, count)` |
| `mcrypt_enc_get_algorithms_name()`, `mcrypt_enc_get_modes_name()`, `mcrypt_enc_get_supported_key_sizes()`, `mcrypt_module_get_algo_supported_key_sizes()` | `mcrypt_free(pointer)` |

### Errors

`mcrypt_strerror(code)` returns the text for a code and `mcrypt_perror(code)`
prints it to `stderr`. The text ends in a newline. For a code that is not in
the table `mcrypt_strerror()` returns `NULL`. The header does not name the
codes.

| Code | Text |
| --- | --- |
| -1 | Unknown error. |
| -2 | Algorithm incompatible with this mode. |
| -3 | Key length is not legal. |
| -4 | Memory allocation failed. |
| -5 | Unknown mode. |
| -6 | Unknown algorithm. |

The query functions that take a name (`mcrypt_module_...`) return -1 for a name
they do not know.

### Threads

A handle holds all the state of one encryption. Use each handle from one thread
at a time; separate handles can be used from separate threads. No cipher and no
mode writes to data that handles share: the lookup tables are constants.

## Function reference

`td` is a handle from `mcrypt_module_open()`.

| Function | What it does |
| --- | --- |
| `MCRYPT mcrypt_module_open(char *algorithm, char *mode)` | Creates a handle. `MCRYPT_FAILED` on error. |
| `int mcrypt_module_close(MCRYPT td)` | Frees a handle. |
| `int mcrypt_generic_init(MCRYPT td, void *key, int lenofkey, void *IV)` | Sets key and IV. 0 or a negative error code. |
| `int mcrypt_generic(MCRYPT td, void *plaintext, int len)` | Encrypts in place. |
| `int mdecrypt_generic(MCRYPT td, void *ciphertext, int len)` | Decrypts in place. |
| `int mcrypt_generic_deinit(MCRYPT td)` | Drops the key; the handle stays usable for another init. |
| `int mcrypt_generic_end(MCRYPT td)` | `mcrypt_generic_deinit()` and `mcrypt_module_close()` together. |
| `int mcrypt_enc_get_key_size(MCRYPT td)` | Longest key in bytes. |
| `int *mcrypt_enc_get_supported_key_sizes(MCRYPT td, int *len)` | List of key sizes; `NULL` and `*len == 0` when any length up to the longest is used as it is. |
| `int mcrypt_enc_get_block_size(MCRYPT td)` | Block size in bytes; 1 for stream algorithms. |
| `int mcrypt_enc_get_iv_size(MCRYPT td)` | IV size in bytes. |
| `int mcrypt_enc_mode_has_iv(MCRYPT td)` | 1 if the mode uses an IV. |
| `int mcrypt_enc_is_block_algorithm(MCRYPT td)` | 1 for a block algorithm, 0 for a stream algorithm. |
| `int mcrypt_enc_is_block_mode(MCRYPT td)` | 1 if the mode needs whole blocks (`cbc`, `ecb`). |
| `int mcrypt_enc_is_block_algorithm_mode(MCRYPT td)` | 1 if the mode is for block algorithms (all but `stream`). |
| `char *mcrypt_enc_get_algorithms_name(MCRYPT td)` | Display name such as `Rijndael-128`. Free it. |
| `char *mcrypt_enc_get_modes_name(MCRYPT td)` | Display name such as `CBC`. Free it. |
| `int mcrypt_enc_self_test(MCRYPT td)` | Runs the algorithm's known-answer test. 0 when it passes. |
| `int mcrypt_enc_get_state(MCRYPT td, void *st, int *size)` | Copies out the mode's chaining state. `*size` is the room in `st` on entry and the bytes written on return. Not for `ecb` and `stream`. |
| `int mcrypt_enc_set_state(MCRYPT td, void *st, int size)` | Puts a saved state back. |
| `char **mcrypt_list_algorithms(int *size)` | Names of all algorithms. |
| `char **mcrypt_list_modes(int *size)` | Names of all modes. |
| `void mcrypt_free_p(char **p, int size)` | Frees such a list. |
| `void mcrypt_free(void *ptr)` | Frees anything else the library returned. |
| `int mcrypt_module_self_test(char *algorithm)` | Known-answer test by name. 0 when it passes. |
| `int mcrypt_module_is_block_algorithm(char *algorithm)` | As the `mcrypt_enc_` function, by name. |
| `int mcrypt_module_is_block_algorithm_mode(char *mode)` | As the `mcrypt_enc_` function, by name. |
| `int mcrypt_module_is_block_mode(char *mode)` | As the `mcrypt_enc_` function, by name. |
| `int mcrypt_module_get_algo_key_size(char *algorithm)` | Longest key in bytes. |
| `int mcrypt_module_get_algo_block_size(char *algorithm)` | Block size in bytes. |
| `int *mcrypt_module_get_algo_supported_key_sizes(char *algorithm, int *len)` | As the `mcrypt_enc_` function, by name. |
| `int mcrypt_module_algorithm_version(char *algorithm)` | A date such as `20010801`. |
| `int mcrypt_module_mode_version(char *mode)` | A date such as `20010801`. |
| `const char *mcrypt_check_version(const char *req)` | The version string `2.5.8` if the library is at least `req` (or `req` is `NULL`), otherwise `NULL`. |
| `const char *mcrypt_strerror(int err)` | Text for an error code, ending in a newline; `NULL` for an unknown code. |
| `void mcrypt_perror(int err)` | Prints that text to `stderr`. |

## The same ciphers in OpenSSL

Useful when data has to move between this library and something else. Each
row was checked against OpenSSL 3.0.13 with random keys, IVs and data.

| Here | OpenSSL |
| --- | --- |
| `rijndael-128` with a 16, 24 or 32-byte key | `aes-128-*`, `aes-192-*`, `aes-256-*` |
| `des` | `des-*` |
| `tripledes` | `des-ede3-*` |
| `blowfish`, keys of 4 to 56 bytes | `bf-*` with the key length set |
| `cast-128` with a 16-byte key | `cast5-*` |
| `rc2` | `rc2-*` with the effective key bits set to 1024 |
| `arcfour` | `rc4` with the key length set |

| Mode here | OpenSSL suffix |
| --- | --- |
| `ecb` | `-ecb` |
| `cbc` | `-cbc` |
| `cfb` | `-cfb8` |
| `ncfb` | `-cfb` |
| `nofb` | `-ofb` |
| `ctr` | `-ctr` |
| `ofb` | none |

So `rijndael-128` with a 32-byte key in `cbc` is `aes-256-cbc`. Remember the
padding: OpenSSL pads with PKCS#7 by default and this library does not pad.

`blowfish-compat`, `rijndael-192` and `rijndael-256` have no OpenSSL
counterpart, and OpenSSL does not ship the remaining ciphers.

## Differences from upstream libmcrypt

Ciphertext, metadata, list order and error codes are the same as in 2.5.8,
with the one exception described under *The `ncfb` fix* below. That was checked
by linking one test program against this tree and against the unmodified 2.5.8
sources: 43,648 fixed cases and 345,000 random ones across all 115 algorithm
and mode pairs.

`test/vectors-2.5.8.txt` keeps that comparison in the repository: it holds
1,088 answers given by the unmodified upstream sources, and the tests compare
the library with it on every platform in CI.

What differs is the build and the part of the API that dealt with loadable
modules.

**Build.** autotools, libltdl and the generated symbol table are gone.
`libmcrypt.gyp` and `CMakeLists.txt` list the sources.

**API.** Every argument that named a module directory is gone:

| Function | Upstream | Here |
| --- | --- | --- |
| `mcrypt_module_open` | `(algorithm, a_directory, mode, m_directory)` | `(algorithm, mode)` |
| `mcrypt_list_algorithms` | `(libdir, &size)` | `(&size)` |
| `mcrypt_list_modes` | `(libdir, &size)` | `(&size)` |
| `mcrypt_module_self_test` | `(algorithm, a_directory)` | `(algorithm)` |
| `mcrypt_module_is_block_algorithm` | `(algorithm, a_directory)` | `(algorithm)` |
| `mcrypt_module_is_block_algorithm_mode` | `(mode, m_directory)` | `(mode)` |
| `mcrypt_module_is_block_mode` | `(mode, m_directory)` | `(mode)` |
| `mcrypt_module_get_algo_key_size` | `(algorithm, a_directory)` | `(algorithm)` |
| `mcrypt_module_get_algo_block_size` | `(algorithm, a_directory)` | `(algorithm)` |
| `mcrypt_module_get_algo_supported_key_sizes` | `(algorithm, a_directory, &len)` | `(algorithm, &len)` |
| `mcrypt_module_algorithm_version` | `(algorithm, a_directory)` | `(algorithm)` |
| `mcrypt_module_mode_version` | `(mode, a_directory)` | `(mode)` |

`mcrypt_module_support_dynamic()` and `mcrypt_mutex_register()` are removed.
The other 24 functions keep their upstream signatures. Code written for
upstream needs the directory arguments deleted and calls to the two removed
functions dropped.

The header still reports version `2.5.8` and `MCRYPT_API_VERSION 20021217`, so
neither can tell this library from upstream.

**Fixes for newer compilers and other CPUs.** Upstream has undefined behaviour
that older compilers happened to handle as intended. Fixed here, without
changing any output that was right before:

- Rotate counts of 32 and more, which made CAST-256 wrong when built with
  clang 22.
- A signed overflow in Enigma's key generator, which changed its output on
  32-bit PowerPC with clang 22.
- The byte order is taken from the compiler, so big-endian builds work without
  a configure step.
- Seven left shifts that overflowed a signed type, in DES, Triple DES, GOST
  and LOKI97. Two of them overflowed only where `long` is 32 bits wide: on
  32-bit systems and on Windows.
- Old-style function declarations without parameter types in `des.c` and
  `tripledes.c`. C23, the default of GCC 15, rejects the calls made through
  them. The sources are now valid from C99 to C23. The build files still pin
  the dialect to gnu99, so that every compiler builds the same language.

**Constant lookup tables.** Upstream fills the tables of Rijndael, GOST and
LOKI97 at the first key setup, in arrays that all threads share and without a
lock. Two threads that set their first key at the same moment race on them,
and GOST marks its tables as ready before it has filled them, so the second
thread can encrypt with tables that are still half empty. Here the tables are
constants with the values that code produced.

**The `ncfb` fix.** In upstream, `ncfb` goes wrong when a message is handed
over in several calls and one of them, other than the last, is not a whole
number of blocks. The calls that follow then produce wrong output, and some of
those bytes are the plaintext XORed with earlier ciphertext, so they are not
protected by the key at all. Decryption in such pieces is wrong too. Here
`ncfb` gives the same result however the data is split. This is the only place
where output differs from upstream, and it differs only where upstream's was
wrong: one call per message, and several calls that are all whole blocks
except the last, give the same bytes and the same saved state as before.
Data that upstream encrypted through the faulty path cannot be decrypted by
repeating the same calls here.

**Module registry.** Upstream gave every module function a name-mangled global
symbol (`rijndael_128_LTX__mcrypt_set_key`) and generated a table of them.
Here each module keeps its functions `static` and exports one descriptor; see
[Adding an algorithm or a mode](#adding-an-algorithm-or-a-mode).

## Known problems

Both come from upstream 2.5.8 and behave the same way there.

- **Enigma and `char`.** `enigma` reads the key through plain `char`. A key
  byte of `0x80` or more gives different output where `char` is unsigned (Linux
  on ARM, PowerPC and s390x) than where it is signed (x86). No other cipher
  depends on this.
- **Saved state in the middle of a block.** In `ncfb` and `ctr`, a state taken
  with `mcrypt_enc_get_state()` after a number of bytes that is not a multiple
  of the block size does not continue correctly once it is put back with
  `mcrypt_enc_set_state()`: the saved state does not include the current
  keystream block. Save the state at a block boundary. `cbc`, `cfb`, `ofb` and
  `nofb` are not affected.

`KNOWN-BUGS` is upstream's own list, kept as it was. Its one entry is about
CAST-256 and RC6 on 64-bit Alpha machines; RC6 is not part of this library.

## Building and testing this repository

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

`ctest --test-dir` needs CMake 3.20; with an older one, run `ctest` inside
`build`.

CTest runs two programs.

**`test/selftest.c`** checks what the library has to get right by itself:

1. every algorithm's built-in known-answer test,
2. AES-128 known answers from NIST SP 800-38A in all seven block modes,
3. an encrypt and decrypt round trip through every algorithm and mode pair,
4. for every pair, that a message handed over in several calls gives the same
   result as in one call.

It ends with a line like
`libmcrypt 2.5.8: 19 algorithms, 8 modes, 115 algorithm/mode pairs, 0 failures`.

**`test/vectors.c`** compares the library with upstream. It asks the library a
fixed list of questions and looks each answer up in `test/vectors-2.5.8.txt`,
which is the output of the same program linked with the unmodified 2.5.8
sources:

- the version, the two lists and their order, and what the library reports
  about every algorithm, mode and pair,
- which names open, the error texts, and the key lengths that are refused,
- for every pair, the ciphertext and the saved mode state for each key size,
  for keys that get padded, without an IV and with an IV of all one bits,
- for every pair, a digest of 200 more encryptions with pseudo-random key, IV
  and data lengths.

It ends with a line like
`libmcrypt 2.5.8 vectors: 1088 answers compared with upstream, 0 different, 0 other failures`.
A difference is printed with upstream's answer next to the library's. The
comment at the top of `test/vectors.c` describes the file format and how the
file is made.

Both programs exit non-zero if anything failed.

To test the gyp build the way node-mcrypt uses it, build the small addon in
`test/addon`. It runs the self-test when it is loaded and has a `vectors()`
function for the comparison:

```sh
mkdir -p test/addon/lib/libmcrypt
cp -r include lib modules libmcrypt.gyp test/addon/lib/libmcrypt/
npx node-gyp rebuild --directory test/addon
node -e "const t = require('./test/addon/build/Release/selftest.node'); process.exit(t.failures || t.vectors('test/vectors-2.5.8.txt') ? 1 : 0)"
```

### Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request:

| Job | What it covers |
| --- | --- |
| CMake | Linux x86-64 with gcc and with clang, Linux arm64, macOS arm64, macOS x86-64, Windows x64 with MSVC |
| node-gyp | Linux, macOS and Windows with the current Node.js LTS |
| Fedora latest | The newest released gcc and clang, each with the sources built as gnu99 and as C23 |
| Emulated | s390x (big-endian), ppc64le, 32-bit ARM and 32-bit x86, under QEMU |
| Sanitizers | AddressSanitizer and UndefinedBehaviorSanitizer on 64-bit x86, UndefinedBehaviorSanitizer on 32-bit x86, with no check left out |
| Function pointer types | Clang's function sanitizer: every call into a module goes through a pointer of the function's own type |

## Platform notes

- **Byte order** is detected at compile time. s390x is the big-endian target
  in CI.
- **Windows.** In the gyp build the public functions are marked
  `__declspec(dllexport)`, so a Node addon that links the library exports
  them. The CMake build defines `LIBMCRYPT_STATIC`, which turns that off.
- **FreeBSD** has settings in `libmcrypt.gyp` but no CI job.
- **`mlock()`.** Key material is locked in memory where the platform has
  `mlock()`: Linux, macOS and FreeBSD in the gyp build, and wherever CMake
  finds it.
- **`config.h`** in the repository root is left from upstream's `configure`.
  Nothing includes it. The gyp file and `CMakeLists.txt` are the configuration.

## Repository layout

| Path | Contents |
| --- | --- |
| `include/mcrypt.h` | The public header. It includes `include/mutils/mcrypt.h`, which has the declarations. |
| `lib/` | The front end: opening handles, key and IV handling, name lookup, memory. |
| `lib/mcrypt_registry.h` | The module interface: the two descriptor types and the declaration of every descriptor. |
| `lib/mcrypt_registry.c` | The list of algorithms and modes that can be opened. |
| `modules/algorithms/` | One source file per cipher. |
| `modules/modes/` | One source file per mode. |
| `libmcrypt.gyp` | The node-gyp build. |
| `CMakeLists.txt` | The CMake build. |
| `test/selftest.c` | The self-test. |
| `test/vectors.c`, `test/vectors-2.5.8.txt` | The comparison with upstream 2.5.8 and upstream's answers. |
| `test/addon/` | A Node addon that CI uses to test the gyp build. |
| `AUTHORS`, `THANKS`, `KNOWN-BUGS`, `COPYING.LIB` | From upstream, unchanged. |

## Adding an algorithm or a mode

Every algorithm and every mode is one source file. It keeps its functions
`static` and ends with one descriptor, a constant structure of function
pointers:

```c
const mcrypt_algo_module mcrypt_algo_rijndael_128 = {
	.name = "rijndael-128",
	.set_key = _mcrypt_set_key,
	.encrypt = _mcrypt_encrypt,
	.decrypt = _mcrypt_decrypt,
	.get_size = _mcrypt_get_size,
	.get_block_size = _mcrypt_get_block_size,
	.is_block_algo = _is_block_algorithm,
	.get_key_size = _mcrypt_get_key_size,
	.get_supported_key_sizes = _mcrypt_get_supported_key_sizes,
	.get_name = _mcrypt_get_algorithms_name,
	.self_test = _mcrypt_self_test,
	.get_version = _mcrypt_algorithm_version
};
```

The pointer types in `lib/mcrypt_registry.h` are the real types of the
functions, so a function with the wrong signature does not compile. A stream
algorithm fills `stream_set_key`, `stream_encrypt` and `stream_decrypt` in
place of the three block fields. A mode defines a `mcrypt_mode_module`.

To add a module:

1. Write `modules/algorithms/<name>.c` or `modules/modes/<name>.c` with its
   descriptor. An existing module of the same kind is the template.
2. Declare the descriptor at the end of `lib/mcrypt_registry.h`.
3. Add its address to `mcrypt_algo_modules[]` or `mcrypt_mode_modules[]` in
   `lib/mcrypt_registry.c`. `mcrypt_list_algorithms()` and
   `mcrypt_list_modes()` return names in the order of these lists.
4. Add the source file to `sources` in `libmcrypt.gyp` and to
   `LIBMCRYPT_SOURCES` in `CMakeLists.txt`.
5. Run the tests. The self-test picks the new module up from the lists. The
   comparison with upstream reports it as a difference, because upstream's
   file has no answers for it.

3-way, Panama, SAFER-SK64 and SAFER-SK128 are already at step 2: their
descriptors (`mcrypt_algo_threeway`, `mcrypt_algo_panama`,
`mcrypt_algo_safer_sk64`, `mcrypt_algo_safer_sk128`) exist and step 3 is all
that is missing. With the four added the self-test passes on x86-64 Linux; no
other platform has been tried, and CI does not cover them.

