# Changes from upstream libmcrypt 2.5.8

This is the file-by-file record of how this repository differs from the
libmcrypt 2.5.8 release. The [README](../README.md#differences-from-upstream-libmcrypt)
has the short version for people who use the library; this document is for
people who maintain it or need to know exactly what was touched.

## Base

| | |
| --- | --- |
| Upstream release | `libmcrypt-2.5.8.tar.gz`, 1,335,178 bytes, February 2007 |
| SHA-256 | `e4eb6c074bbab168ac47b947c195ff8cef9d51a211cdd18ca9c9ef34d27a373e` |
| Imported in | `3f11e24` (2015-08-15) |

2.5.8 is the last upstream release, so there is nothing newer to merge.

Of the 89 files tracked here, 33 are byte-identical to the tarball, 41 are
modified and 15 are new. 76 of the tarball's 150 files are not here.

## What the library computes

Ciphertext, decryption, saved state, names, sizes, version numbers, list order
and error codes are the same as in 2.5.8, with one exception: `ncfb` when a
message is passed in several calls and a call ends inside a block. Upstream is
wrong there and this library is not; see the README.

Two comparisons with the unmodified upstream sources stand behind that:

- `test/vectors.c` with `test/vectors-2.5.8.txt`, in the repository and run by
  CI on every platform: 1,088 answers, none different.
- A larger one made outside the repository on x86-64 Linux: 43,648 fixed cases
  and 345,000 random ones over all 115 algorithm and mode pairs. 4,536 of the
  fixed cases differ and all of them are `ncfb`: 2,264 where the message is
  split inside a block, and 2,272 where encryption continues from a state that
  was saved inside a block. Everything else is identical, and so are the four
  ciphers that are compiled but cannot be opened.

## Removed

| Removed | Why |
| --- | --- |
| `configure`, `configure.in`, every `Makefile.am` and `Makefile.in`, `aclocal.m4`, `acinclude.m4`, `libtool`, `ltmain.sh`, `config.guess`, `config.sub`, `install-sh`, `depcomp`, `missing`, `mkinstalldirs`, `buildconf`, `config.h.in`, `autom4te.cache/`, and the generated `Makefile`, `config.log`, `config.status`, `stamp-h1` and `autoscan.log` that were left in the tarball | The autotools build. `libmcrypt.gyp` and `CMakeLists.txt` replace it. |
| `libltdl/` | Modules are no longer loaded at run time. |
| `lib/win32_comp.c`, `lib/win32_comp.h` | `dlopen` shims for Windows. The one macro still needed, `WIN32DLL_DEFINE`, is in `lib/libdefs.h`. |
| `lib/mcrypt_threads.c` | It only held `mcrypt_mutex_register()`, a libltdl hook. |
| `lib/libmcrypt.sym`, `lib/libmcrypt.m4`, `lib/libmcrypt-config.in`, `include/mutils/mcrypt.h.in`, `libmcrypt.spec`, `libmcrypt.spec.in` | Export list, packaging and install helpers of the shared library. |
| `src/` (`aes_test.c`, `cipher_test.c`) | Upstream's test programs, written for the four-argument API. `test/` replaces them. |
| `doc/`, `README`, `NEWS`, `ChangeLog`, `TODO`, `INSTALL` | Documentation of the upstream build and API. `README.md` replaces it. |

## Added

| File | Purpose |
| --- | --- |
| `libmcrypt.gyp` | The node-gyp build: one static library, with the defines that `configure` used to detect listed per operating system. |
| `CMakeLists.txt` | The CMake build: one static library, `libmcrypt::libmcrypt`, and the two tests. It detects the platform instead of listing it. |
| `lib/mcrypt_registry.h` | The module interface: the descriptor types `mcrypt_algo_module` and `mcrypt_mode_module`, and the declaration of every descriptor. |
| `lib/mcrypt_registry.c` | The two lists of descriptors that can be opened. |
| `modules/algorithms/rijndael-tables.h`, `modules/algorithms/loki97-tables.h` | Lookup tables as constants. Upstream computes them at the first key setup. |
| `test/selftest.c` | Known answers, round trips and split calls for every pair. |
| `test/vectors.c`, `test/vectors-2.5.8.txt` | The comparison with upstream and upstream's answers. |
| `test/addon/` | A Node addon that CI builds to test the gyp build. |
| `.github/workflows/ci.yml` | CI. |
| `README.md`, `docs/CHANGES-FROM-UPSTREAM.md`, `.gitignore` | |

## Public header (`include/mutils/mcrypt.h`)

Every argument that named a module directory is gone:

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
Of upstream's 38 public functions, 36 remain.

Algorithm and mode names are declared `const char *`, and the key, the IV and
the state given to `mcrypt_enc_set_state()` are `const void *`. Upstream's
header says `char *` and `void *`, while upstream's definitions take pointers
to `const`; the header was never checked against them, because the library
does not include it. That is still so, and a change to either side has to be
made to the other by hand.

`include/mcrypt.h` is unchanged.

## Front end (`lib/`)

| File | Change |
| --- | --- |
| `mcrypt_modules.c` | Rewritten, 1,021 lines down to 576. Upstream finds every module function by building a string such as `rijndael_128_LTX__mcrypt_encrypt` and searching a table of names. Here `mcrypt_module_open()` finds the descriptor of the algorithm and of the mode once, and every later call goes through it. Names compare with `_` and `-` as the same character, as upstream does. A `NULL` name gives `MCRYPT_FAILED`. |
| `mcrypt_extra.c` | 439 lines down to 206. `mcrypt_list_algorithms()` and `mcrypt_list_modes()` copy the names out of the descriptor lists; the directory scanning is gone. `mcrypt_algorithm_module_ok()` and `mcrypt_mode_module_ok()` are lookups in the lists. |
| `mcrypt_internal.h` | `CRYPT_STREAM` holds a pointer to the algorithm's descriptor and one to the mode's, in place of two libltdl handles and five cached function pointers. The internal prototypes carry `WIN32DLL_DEFINE`. |
| `mcrypt_modules.h` | `rotl32()` and `rotr32()` reduce the count modulo 32. Includes `mcrypt_registry.h`. |
| `libdefs.h` | The libltdl stubs and the `<dirent.h>`, `<endian.h>` and `<machine/endian.h>` includes are gone. Defines `WIN32DLL_DEFINE`, empty when `LIBMCRYPT_STATIC` is set. Defines `WORDS_BIGENDIAN` from the compiler's byte order. |
| `mcrypt.c` | `mcrypt_generic()` and `mdecrypt_generic()` return the result directly instead of through a local, and a dead `#if 0` block is gone. Key and IV handling is untouched. |
| `bzero.c`, `bzero.h`, `xmemory.c`, `xmemory.h` | Unchanged. |

A static build of upstream's sources defines 450 external symbols. This
library defines 86: the 36 public functions, 19 functions and lists that the
library's own files share, and one descriptor for each of the 31 modules.

## Modules (`modules/`)

### Every algorithm and every mode

- The `#define _mcrypt_encrypt rijndael_128_LTX__mcrypt_encrypt` lines, which
  gave each function a global name of its own, are gone. The functions are
  `static`.
- The functions take the parameter types of the interface (`void *`,
  `const void *`) and assign them to locals of the types upstream had in the
  parameter list. Empty parameter lists are `(void)`.
- Each file ends with its descriptor, a constant struct that points to the
  functions: `mcrypt_algo_rijndael_128`, `mcrypt_mode_cbc`, and so on. It is
  the file's only external symbol.
- A mode receives the algorithm's descriptor where upstream passed two
  untyped function pointers.
- The empty `main()` that upstream compiled into Windows DLL modules is gone.
- The self-tests cast the arguments of `strcmp()` to `const char *`.

### Further changes

None of these changes what a cipher or a mode computes, except the `ncfb` row.

| File | Change |
| --- | --- |
| `3-way.c` | `gamma()` is `threeway_gamma()`, so it does not share a name with the C library's function. The seven helpers are `static`. |
| `arcfour.c`, `wake.c` | The IV variables exist only under `#ifdef USE_IV`, which is where they are used. |
| `blowfish-compat.c` | The five initial tables (`ks0` to `ks3`, `pi`) are `static const` at file scope. Upstream copies them onto the stack at every key setup. |
| `cast-128.c` | `ROL()` reduces the count modulo 32. `z[]` and `t[]` are zero-initialised in the key schedule. |
| `cast-256.c` | The S-box table is `static const`. |
| `des.c`, `tripledes.c` | The helpers have prototypes; upstream declares them without parameter types. Two left shifts are done on unsigned values. The nine tables are `const`. `tripledes.c` passes `key->iperm` where it passed `&key->iperm`, and a `printf` inside `#ifdef DEBUG` is corrected. |
| `enigma.c` | The key generator multiplies and adds as unsigned and converts back, where upstream overflows a signed integer. `shuffle()` is `static`. |
| `gost.c` | The four 256-entry tables are constants; the function that built them from the eight S-boxes is gone, and the S-boxes are kept as a comment. One left shift is done on an unsigned value. |
| `loki97.c`, `loki97-tables.h` | The three tables are constants in the new header; the functions that built them are gone. `f_fun()` is `static`. Two left shifts are done on unsigned values. |
| `panama.c`, `panama.h` | Loop counters are unsigned. A loop variable used only in big-endian builds is declared there. The zero block that stands in for a missing input is `const`. Eleven stale declarations are gone from the header. |
| `rijndael-128.c`, `rijndael-192.c`, `rijndael-256.c`, `rijndael-tables.h` | The seven tables are constants in the new header, shared by the three files; the function that built them is gone. |
| `safer64.c`, `safer128.c`, `safer.h` | The exponent and logarithm tables are constants in `safer.h`; the function that built them is gone. A loop counter in the key setup is signed. |
| `saferplus.c` | The two tables are `static const`, the two round functions `static`. |
| `twofish.c` | The eight tables are `static const`, the six helpers `static`. `t0` and `t1` are zero-initialised in `_mcrypt_encrypt`. |
| `loki97.c`, `xtea.c`, `modes/ctr.c`, `modes/ncfb.c`, `modes/nofb.c` | Unused locals removed. |
| `modes/cbc.c` | A loop counter is unsigned. |
| `modes/ncfb.c` | Nine lines corrected, so that a message gives the same result however it is split across calls. This is the one change to output. |

The module headers are unchanged, except `safer.h` and `panama.h` above. The
eight headers in `modules/modes/` are not included by anything, here or in
upstream.

## Algorithms and modes

`lib/mcrypt_registry.c` lists them in upstream's order, which is the order
`mcrypt_list_algorithms()` and `mcrypt_list_modes()` return:

- **Modes (8):** cbc, cfb, ctr, ecb, ncfb, nofb, ofb, stream
- **Algorithms (19):** cast-128, gost, rijndael-128, twofish, arcfour,
  cast-256, loki97, rijndael-192, saferplus, wake, blowfish-compat, des,
  rijndael-256, serpent, xtea, blowfish, enigma, rc2, tripledes

That is the set of upstream's default static build.

Four more sources are compiled and have descriptors, but are not in the list,
so they cannot be opened: `3-way.c` (threeway), `panama.c`, `safer64.c`
(safer-sk64) and `safer128.c` (safer-sk128). Upstream's default build leaves
out threeway and the two SAFER-SK ciphers as well, because `configure` looks
for source files named after the module (`threeway.c`, `safer-sk64.c`,
`safer-sk128.c`) and those do not exist. Panama is not in upstream's default
list. The header still defines `MCRYPT_3WAY`, `MCRYPT_SAFER_SK64` and
`MCRYPT_SAFER_SK128`.

## Build configuration

`libmcrypt.gyp` defines `STDC_HEADERS` and `VERSION="2.5.8"` everywhere, asks
GCC and clang for gnu99, and defines per operating system:

| Define | linux | mac | freebsd | win |
| --- | --- | --- | --- | --- |
| `HAVE_BYTESWAP_H` | yes | | | |
| `HAVE_MLOCK`, `HAVE_SYS_MMAN_H` | yes | yes | yes | |
| `HAVE_STRINGS_H`, `HAVE_UNISTD_H` | yes | yes | yes | |
| `HAVE_BZERO`, `HAVE_MEMMOVE`, `HAVE_MEMSET`, `HAVE_SYS_TYPES_H` | yes | yes | yes | yes |
| `WIN32` | | | | yes |
| `SIZEOF_UNSIGNED_CHAR=1`, `SIZEOF_UNSIGNED_SHORT_INT=2`, `SIZEOF_UNSIGNED_INT=4`, `SIZEOF_UNSIGNED_LONG_INT=8` | yes | yes | yes | yes |

- `word32` is `unsigned int` on every platform. `SIZEOF_UNSIGNED_LONG_INT=8`
  is given everywhere, also on Windows and on 32-bit targets where it is not
  true; its only effect is that `libdefs.h` passes over `unsigned long` and
  picks `unsigned int`.
- Linux swaps bytes with `<byteswap.h>`. The other platforms use the rotate
  macros in `lib/mcrypt_modules.h`.
- An operating system other than these four gets no size defines and stops in
  `libdefs.h` with `Cannot find a 32 bit integer in your system`.

`CMakeLists.txt` finds the headers, `mlock()` and the type sizes by itself,
defines `LIBMCRYPT_STATIC`, and compiles as gnu99 unless
`LIBMCRYPT_C_STANDARD` says otherwise.

`HAVE_CONFIG_H` is never defined, so `config.h` in the repository root is not
included by anything. It differs from the copy in the tarball and is kept only
because it was part of the import.

## Faults of upstream 2.5.8 that are fixed here

| Fault | Effect | Fixed in |
| --- | --- | --- |
| `ncfb` mixes up its buffers when a call ends inside a block and more data follows. | Wrong output for the following calls; part of it is the plaintext XORed with earlier ciphertext. | `bc9a063` |
| Rijndael, GOST, LOKI97 and SAFER-SK fill their lookup tables at the first key setup, in shared arrays and without a lock. GOST marks its tables as ready before it fills them. | Two threads that set their first key at the same moment race; one can encrypt with tables that are half empty. | *Make the lookup tables of Rijndael, GOST, LOKI97 and SAFER-SK constants* |
| `rotl32()`, `rotr32()` and CAST-128's `ROL()` shift by the raw count, and CAST-256 passes counts of 32 and more. | CAST-256 fails its known-answer test when built with clang 22 at `-O1` or higher. | `a0e34d2` |
| Enigma's key generator overflows a signed 32-bit integer. | Different ciphertext when built with clang 22 for 32-bit PowerPC. | `a591408` |
| Seven left shifts overflow a signed type, in DES, Triple DES, GOST and LOKI97. Two of them only where `long` is 32 bits wide. | None seen with any compiler tested; reported by the undefined-behaviour sanitizer. | *Remove the undefined behaviour the sanitizer reported and make the sources valid C23* |
| `des.c` and `tripledes.c` declare their helpers without parameter types. | They do not compile as C23, the default of GCC 15. | the same commit |
| The header declares names, key and IV as pointers to non-`const`. | C++ callers have to cast string literals. | *Declare names, keys and IVs as const, and keep module helpers out of the symbol table* |
| Six ciphers export helpers and tables under names such as `mu`, `rho`, `shuffle` and `qp`. | A program that defines the same name does not link, or shares the symbol. | the same commit |
| WAKE's self-test frees a buffer twice on the path it takes when the test fails. | The program aborts where the function should return -1. It does not happen while the test passes. | `a9e1d0d` |

## Faults that earlier commits of this repository had

All are fixed. They matter to anyone who used a build from that time.

| Fault | From | Fixed in |
| --- | --- | --- |
| The Blowfish key schedule read the key as plain `char`. Where `char` is signed, which includes x86 and x86-64, a key with a byte of `0x80` or more gave different ciphertext from upstream. | `93ab68f` | `2e04c3a` for blowfish, `84ed22f` for blowfish-compat |
| `mcrypt_enc_self_test()` and `mcrypt_module_self_test()` returned -1 for 16 of the 19 algorithms where `char` is signed, and WAKE's aborted (the last row of the table above). The ciphers themselves were correct. | `93ab68f` | `a9e1d0d` |
| Names with `_` for `-`, such as `rijndael_128`, did not open. | `9c16e8c` | `e221595` |
| `mcrypt_module_open()` crashed on a `NULL` name. | `9c16e8c` | `f0e1eea` |
| `WORDS_BIGENDIAN` was never defined, so twelve ciphers gave wrong results on big-endian machines: blowfish, blowfish-compat, cast-256, des, gost, loki97, rc2, serpent, tripledes, twofish, wake, xtea. | `f8e3750` | `75563c0` |

The Blowfish fault reached node-mcrypt releases:

| libmcrypt-gyp commits | blowfish | blowfish-compat | node-mcrypt versions |
| --- | --- | --- | --- |
| `93ab68f` to `d65bca3` | affected | affected | 0.1.1 to 0.1.11 |
| `2e04c3a` | correct | affected | 0.1.12 to 0.1.15 |
| `84ed22f` | correct | correct | 0.1.16, 0.1.17 |

Keys of ASCII text were not affected.

## Left as upstream has it

- **Enigma and `char`.** Enigma reads the key through plain `char`, so a key
  byte of `0x80` or more gives different output where `char` is unsigned.
- **Saved state inside a block.** In `ncfb` and `ctr`, a state saved after a
  number of bytes that is not a multiple of the block size does not continue
  correctly when it is put back.
- **Enigma's `shuffle()`** keeps a `static` variable. The function is never
  called: the flag that selects it is fixed at 0. It is the only writable
  static data left in the library, and an optimising compiler removes it.
- **`KNOWN-BUGS`, `AUTHORS`, `THANKS`, `COPYING.LIB`** are unchanged.

## History

| Date | Commit | Author | What |
| --- | --- | --- | --- |
| 2015-08-15 | `3f11e24` | Tuğrul Topuz | Import of the 2.5.8 sources, with a generated `config.h` and `mcrypt_symb.c` |
| 2015-08-15 | `f8e3750` | Tuğrul Topuz | `libmcrypt.gyp` |
| 2015-08-17 | `93ab68f` | Tuğrul Topuz | Compiler-warning clean-up across all modules |
| 2015-08-17 | `7c51698` | Tuğrul Topuz | Visual C++ support: `WIN32DLL_DEFINE` on internal prototypes, Windows defines |
| 2015-08-19 | `e425100` | Tuğrul Topuz | Run-time module loading removed; API reduced; libltdl and the Windows shims deleted |
| 2015-08-20 | `a791ce0` | Tuğrul Topuz | `mcrypt_module_open` fixes |
| 2015-09-17 | `37ee9e4` | Dylan Wood | `config.h`: `sizeof(unsigned long)` set to 8 (#1) |
| 2015-11-09 | `9c16e8c`, `258ba1a`, `5e7f173` | Tuğrul Topuz | The table of symbol names replaced by a table of typed function pointers |
| 2015-11-15 | `59cb541`, `d65bca3` | Tuğrul Topuz | Unused defines removed; per-OS defines moved into the gyp file |
| 2016-07-25 | `42348e2` | Danila Balagansky | FreeBSD defines (#3) |
| 2016-11-30 | `2e04c3a` | wangshijun | Blowfish key read as `unsigned char` again (#4) |
| 2019-03-23 | `84ed22f` | jowanw | The same for blowfish-compat; its tables moved to file scope (#5) |
| 2026-11-25 | `a9e1d0d` | Tuğrul Topuz | Self-tests pass again where `char` is signed; WAKE self-test double free |
| 2026-11-25 | `f0e1eea`, `e221595` | Tuğrul Topuz | `NULL` names; `_` for `-` in names |
| 2026-11-25 | `0f13329` | Tuğrul Topuz | blowfish-compat tables `static const` |
| 2026-11-25 | `79f9be8` | Tuğrul Topuz | gyp: compile as gnu99 |
| 2026-11-25 | `75563c0` | Tuğrul Topuz | `WORDS_BIGENDIAN` from the compiler's byte order |
| 2026-11-25 | `a0e34d2`, `a591408` | Tuğrul Topuz | Rotates defined for any count; Enigma's key generator unsigned |
| 2026-11-25 | `f7b0de7` | Tuğrul Topuz | `CMakeLists.txt` and `test/selftest.c` |
| 2026-11-25 | `d813d92`, `1f80413` | Tuğrul Topuz | GitHub Actions CI and `test/addon` |
| 2026-11-26 | `4ea7971`, `c4920ed` | Tuğrul Topuz | Per-module descriptors in place of the generated symbol table; CI job for function pointer types |
| 2026-11-26 | `08c14fc` | Tuğrul Topuz | `README.md` |
| 2026-11-26 | `bc9a063` | Tuğrul Topuz | The `ncfb` fix |
| 2026-11-26 | `0fead5b` | Tuğrul Topuz | `test/vectors.c` and `test/vectors-2.5.8.txt` |
| 2026-11-26 | *Make the lookup tables of Rijndael, GOST, LOKI97 and SAFER-SK constants* | Tuğrul Topuz | Constant lookup tables |
| 2026-11-26 | *Remove the undefined behaviour the sanitizer reported and make the sources valid C23* | Tuğrul Topuz | Seven shifts, prototypes in `des.c` and `tripledes.c`, `LIBMCRYPT_C_STANDARD`, 32-bit sanitizer job |
| 2026-11-26 | *Declare names, keys and IVs as const, and keep module helpers out of the symbol table* | Tuğrul Topuz | `const` in the header; 28 helpers and tables `static` |
| 2026-11-26 | *Add the record of changes from upstream* | Tuğrul Topuz | This document |

The last four rows name commits by their title: find them with
`git log --grep`.

## Licence

Unchanged from upstream. `COPYING.LIB` is the GNU Lesser General Public
License 2.1, and the source headers refer to the GNU Library General Public
License, version 2 or later. Section 2(b) of `COPYING.LIB` asks that modified
files carry a notice that they were changed and when; the tables above list
every modified file, and `git log` has the dates.
