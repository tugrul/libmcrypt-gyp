/*
 * Known answers of upstream libmcrypt 2.5.8.
 *
 * This program asks the library it is linked with a fixed list of questions
 * and writes one line per answer:
 *
 *     vectors generate         print the lines
 *     vectors check FILE       compare them with FILE; exit 1 on a difference
 *
 * test/vectors-2.5.8.txt is what "generate" prints when it is linked with
 * the unmodified upstream sources. "check" against that file therefore fails
 * as soon as this library answers anything differently from upstream.
 *
 * What is asked:
 *
 *     library, algorithms, modes   version and the two lists, in order
 *     algorithm, mode              what the library says about each by name
 *     pair                         every algorithm with every mode: whether
 *                                  they open together, and the sizes and
 *                                  names an open handle reports
 *     open                         names that are not in the lists
 *     error                        the text for each error code
 *     init                         key lengths that must be refused
 *     kat                          key, IV, plaintext, ciphertext and the
 *                                  saved mode state: for every key size, for
 *                                  keys that get padded, without an IV and
 *                                  with an IV of all one bits
 *     bulk                         a digest of 200 more encryptions with
 *                                  pseudo-random key, IV and data lengths
 *
 * Keys, IVs and data come from a generator seeded with the names of the
 * algorithm and the mode, so the lines do not depend on the order in which
 * they are produced. Every "kat" and "bulk" ciphertext is also decrypted
 * again and has to give the plaintext back.
 *
 * Each message is encrypted in one call. What upstream does when a message
 * is split across calls is not recorded here, because for ncfb it is wrong;
 * test/selftest.c checks that splitting changes nothing.
 *
 * Enigma keys use bytes below 0x80 only. Enigma reads its key through plain
 * char, so other bytes give different output where char is unsigned, and
 * this file has to hold on every platform.
 *
 * To make the file again, build this program with VECTORS_UPSTREAM_API
 * defined, link it with an unmodified libmcrypt 2.5.8 and run "generate".
 *
 * With LIBMCRYPT_VECTORS_NO_MAIN defined only libmcrypt_vectors_check() is
 * compiled (test/addon/addon.c).
 */
#ifdef _MSC_VER
# define _CRT_SECURE_NO_WARNINGS	/* for fopen() and vsprintf() */
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mcrypt.h>

#ifdef VECTORS_UPSTREAM_API	/* upstream's functions take module directories */
# define OPEN(a, m)		mcrypt_module_open((char *) (a), NULL, (char *) (m), NULL)
# define LIST_ALGORITHMS(n)	mcrypt_list_algorithms(NULL, n)
# define LIST_MODES(n)		mcrypt_list_modes(NULL, n)
# define A_IS_BLOCK(a)		mcrypt_module_is_block_algorithm((char *) (a), NULL)
# define A_BLOCK_SIZE(a)	mcrypt_module_get_algo_block_size((char *) (a), NULL)
# define A_KEY_SIZE(a)		mcrypt_module_get_algo_key_size((char *) (a), NULL)
# define A_KEY_SIZES(a, n)	mcrypt_module_get_algo_supported_key_sizes((char *) (a), NULL, n)
# define A_VERSION(a)		mcrypt_module_algorithm_version((char *) (a), NULL)
# define M_IS_BLOCK(m)		mcrypt_module_is_block_mode((char *) (m), NULL)
# define M_FOR_BLOCK(m)		mcrypt_module_is_block_algorithm_mode((char *) (m), NULL)
# define M_VERSION(m)		mcrypt_module_mode_version((char *) (m), NULL)
#else
# define OPEN(a, m)		mcrypt_module_open((char *) (a), (char *) (m))
# define LIST_ALGORITHMS(n)	mcrypt_list_algorithms(n)
# define LIST_MODES(n)		mcrypt_list_modes(n)
# define A_IS_BLOCK(a)		mcrypt_module_is_block_algorithm((char *) (a))
# define A_BLOCK_SIZE(a)	mcrypt_module_get_algo_block_size((char *) (a))
# define A_KEY_SIZE(a)		mcrypt_module_get_algo_key_size((char *) (a))
# define A_KEY_SIZES(a, n)	mcrypt_module_get_algo_supported_key_sizes((char *) (a), n)
# define A_VERSION(a)		mcrypt_module_algorithm_version((char *) (a))
# define M_IS_BLOCK(m)		mcrypt_module_is_block_mode((char *) (m))
# define M_FOR_BLOCK(m)		mcrypt_module_is_block_algorithm_mode((char *) (m))
# define M_VERSION(m)		mcrypt_module_mode_version((char *) (m))
#endif

#define MAX_DATA 256		/* longest message, and room for the longest key */
#define BULK_CASES 200
#define MAX_REPORTED 20

typedef unsigned long long u64;	/* at least 64 bits everywhere */

/* ------------------------------------------------------------------------
 * Where the lines go: to stdout, or against the file.
 *
 * Every line is a question followed by the answer. The question is the
 * first few words: for "kat" everything up to the plaintext, for "pair",
 * "open", "init" and "bulk" the two names, for the rest one name or none.
 * Checking looks the question up in the file, so a line that is missing or
 * extra on one side is reported as such and does not shift the others.
 * ---------------------------------------------------------------------- */

static int checking;
static char *wanted_text;	/* the file */
static char **wanted;		/* its lines, sorted by question */
static char *wanted_seen;
static size_t wanted_count;
static long lines, differences, failures;
static char line[8192];
static size_t line_len;

static void line_add(const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsprintf(line + line_len, fmt, ap);
	va_end(ap);
	if (n > 0)
		line_len += (size_t) n;
}

static void line_add_hex(const char *name, const unsigned char *p, int n)
{
	static const char digits[] = "0123456789abcdef";
	int i;

	line_add(" %s=", name);
	if (p == NULL || n == 0) {
		line[line_len++] = '-';
	} else {
		for (i = 0; i < n; i++) {
			line[line_len++] = digits[p[i] >> 4];
			line[line_len++] = digits[p[i] & 15];
		}
	}
	line[line_len] = '\0';
}

/* How many characters of a line are the question. */
static size_t question_length(const char *text)
{
	static const struct {
		const char *kind;
		int words;
	} kinds[] = {
		{ "kat", 6 }, { "pair", 3 }, { "open", 3 }, { "init", 3 }, { "bulk", 3 },
		{ "algorithm", 2 }, { "mode", 2 }, { "error", 2 }
	};
	size_t kind_len = strcspn(text, " "), i, n = 0;
	int words = 1;

	for (i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
		if (strlen(kinds[i].kind) == kind_len && memcmp(text, kinds[i].kind, kind_len) == 0)
			words = kinds[i].words;
	}
	while (text[n] != '\0') {
		if (text[n] == ' ' && --words == 0)
			break;
		n++;
	}
	return n;
}

static int compare_questions(const void *a, const void *b)
{
	const char *x = *(char *const *) a, *y = *(char *const *) b;
	size_t nx = question_length(x), ny = question_length(y);
	int c = memcmp(x, y, nx < ny ? nx : ny);

	return c != 0 ? c : nx < ny ? -1 : nx > ny;
}

static void free_wanted(void)
{
	free(wanted_text);
	free(wanted);
	free(wanted_seen);
	wanted_text = wanted_seen = NULL;
	wanted = NULL;
	wanted_count = 0;
}

/* Reads the file and sorts its lines. Comments and empty lines are dropped. */
static int load_wanted(const char *path)
{
	FILE *f = fopen(path, "rb");
	char *p, *end;
	long size;
	size_t n = 0;

	if (f == NULL)
		return 0;
	if (fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0
	    || (wanted_text = malloc((size_t) size + 1)) == NULL) {
		fclose(f);
		return 0;
	}
	size = (long) fread(wanted_text, 1, (size_t) size, f);
	fclose(f);
	wanted_text[size] = '\0';

	for (p = wanted_text; *p != '\0'; p++)
		n += *p == '\n';
	wanted = malloc((n + 1) * sizeof(*wanted));
	wanted_seen = calloc(n + 1, 1);
	if (wanted == NULL || wanted_seen == NULL) {
		free_wanted();
		return 0;
	}

	wanted_count = 0;
	for (p = wanted_text; *p != '\0'; p = end) {
		end = p + strcspn(p, "\r\n");
		while (*end == '\r' || *end == '\n')
			*end++ = '\0';
		if (*p != '\0' && *p != '#')
			wanted[wanted_count++] = p;
	}
	qsort(wanted, wanted_count, sizeof(*wanted), compare_questions);
	return 1;
}

static void line_end(void)
{
	char *key = line, **found;

	lines++;
	if (!checking) {
		puts(line);
	} else if ((found = bsearch(&key, wanted, wanted_count, sizeof(*wanted),
				    compare_questions)) == NULL) {
		if (differences++ < MAX_REPORTED)
			printf("DIFFERENT  not in upstream's file: %.90s\n", line);
	} else {
		wanted_seen[found - wanted] = 1;
		if (strcmp(*found, line) != 0 && differences++ < MAX_REPORTED) {
			size_t at = 0;

			while ((*found)[at] != '\0' && (*found)[at] == line[at])
				at++;
			printf("DIFFERENT  %.*s\n", (int) question_length(line) > 90 ? 90
			       : (int) question_length(line), line);
			printf("    upstream: %s%.70s\n", at > 20 ? "..." : "",
			       *found + (at > 20 ? at - 20 : 0));
			printf("    here:     %s%.70s\n", at > 20 ? "..." : "",
			       line + (at > 20 ? at - 20 : 0));
		}
	}
	line_len = 0;
	line[0] = '\0';
}

/* Something is wrong that the file cannot show, such as a failed round trip. */
static void failure(const char *what, const char *algorithm, const char *mode)
{
	if (failures++ < MAX_REPORTED)
		printf("FAILED     %s: %s/%s\n", what, algorithm, mode);
}

/* ------------------------------------------------------------------------
 * Pseudo-random bytes that are the same on every platform.
 * ---------------------------------------------------------------------- */

static u64 fnv(u64 h, const void *data, size_t n)
{
	const unsigned char *p = data;

	while (n-- > 0) {
		h ^= *p++;
		h *= 0x100000001b3ULL;
		h &= 0xffffffffffffffffULL;
	}
	return h;
}

static u64 rng_state;

static void rng_seed(const char *a, const char *b, const char *c)
{
	u64 h = 0xcbf29ce484222325ULL;

	h = fnv(h, a, strlen(a) + 1);
	h = fnv(h, b, strlen(b) + 1);
	h = fnv(h, c, strlen(c) + 1);
	rng_state = h | 1;
}

static u64 rng_next(void)		/* xorshift64* */
{
	rng_state ^= rng_state >> 12;
	rng_state ^= rng_state << 25;
	rng_state &= 0xffffffffffffffffULL;
	rng_state ^= rng_state >> 27;
	return (rng_state * 0x2545f4914f6cdd1dULL) & 0xffffffffffffffffULL;
}

static int rng_range(int low, int high)	/* low..high */
{
	return low + (int) (rng_next() % (u64) (high - low + 1));
}

static void rng_bytes(unsigned char *p, int n)
{
	while (n-- > 0)
		*p++ = (unsigned char) (rng_next() >> 56);
}

static void make_key(const char *algorithm, unsigned char *key, int n)
{
	int i;

	rng_bytes(key, n);
	if (strcmp(algorithm, "enigma") == 0) {	/* see the top of this file */
		for (i = 0; i < n; i++)
			key[i] &= 0x7f;
	}
}

/* ------------------------------------------------------------------------
 * What the library says about names.
 * ---------------------------------------------------------------------- */

static void line_add_key_sizes(int *sizes, int count)
{
	int i;

	line_add(" keysizes=");
	if (sizes == NULL || count == 0)
		line_add("any");
	for (i = 0; sizes != NULL && i < count; i++)
		line_add("%s%d", i ? "," : "", sizes[i]);
}

static void describe_lists(char **algorithms, int n_algorithms, char **modes, int n_modes)
{
	int i, count, *sizes;

	line_add("library %s", mcrypt_check_version(NULL));
	line_end();

	line_add("algorithms");
	for (i = 0; i < n_algorithms; i++)
		line_add(" %s", algorithms[i]);
	line_end();

	line_add("modes");
	for (i = 0; i < n_modes; i++)
		line_add(" %s", modes[i]);
	line_end();

	for (i = 0; i < n_algorithms; i++) {
		count = 0;
		sizes = A_KEY_SIZES(algorithms[i], &count);
		line_add("algorithm %s block=%d blocksize=%d keysize=%d", algorithms[i],
			 A_IS_BLOCK(algorithms[i]), A_BLOCK_SIZE(algorithms[i]),
			 A_KEY_SIZE(algorithms[i]));
		line_add_key_sizes(sizes, count);
		line_add(" version=%d", A_VERSION(algorithms[i]));
		line_end();
		mcrypt_free(sizes);
	}

	for (i = 0; i < n_modes; i++) {
		line_add("mode %s block_mode=%d for_block_algorithms=%d version=%d", modes[i],
			 M_IS_BLOCK(modes[i]), M_FOR_BLOCK(modes[i]), M_VERSION(modes[i]));
		line_end();
	}
}

static void describe_pair(const char *algorithm, const char *mode)
{
	MCRYPT td = OPEN(algorithm, mode);
	char *algorithm_name, *mode_name;
	int count = 0, *sizes;

	line_add("pair %s %s", algorithm, mode);
	if (td == MCRYPT_FAILED) {
		line_add(" none");
		line_end();
		return;
	}

	algorithm_name = mcrypt_enc_get_algorithms_name(td);
	mode_name = mcrypt_enc_get_modes_name(td);
	sizes = mcrypt_enc_get_supported_key_sizes(td, &count);

	line_add(" names=%s,%s blocksize=%d keysize=%d ivsize=%d has_iv=%d", algorithm_name,
		 mode_name, mcrypt_enc_get_block_size(td), mcrypt_enc_get_key_size(td),
		 mcrypt_enc_get_iv_size(td), mcrypt_enc_mode_has_iv(td));
	line_add(" block_algorithm=%d block_mode=%d for_block_algorithms=%d",
		 mcrypt_enc_is_block_algorithm(td), mcrypt_enc_is_block_mode(td),
		 mcrypt_enc_is_block_algorithm_mode(td));
	line_add_key_sizes(sizes, count);
	line_end();

	mcrypt_free(sizes);
	mcrypt_free(algorithm_name);
	mcrypt_free(mode_name);
	mcrypt_module_close(td);
}

static const char *shown(const char *name)
{
	return name == NULL ? "(null)" : name[0] == '\0' ? "(empty)" : name;
}

static void describe_open(const char *algorithm, const char *mode)
{
	MCRYPT td = OPEN(algorithm, mode);

	line_add("open %s %s %s", shown(algorithm), shown(mode),
		 td == MCRYPT_FAILED ? "fails" : "opens");
	line_end();
	if (td != MCRYPT_FAILED)
		mcrypt_module_close(td);
}

static void describe_errors(void)
{
	int code;

	for (code = -8; code <= 1; code++) {
		const char *text = mcrypt_strerror(code);

		line_add("error %d ", code);
		if (text == NULL)
			line_add("(none)");
		for (; text != NULL && *text != '\0'; text++) {
			if (*text == '\n')	/* the texts end in a newline */
				line_add("\\n");
			else
				line_add("%c", *text);
		}
		line_end();
	}
}

/* ------------------------------------------------------------------------
 * Encryption.
 * ---------------------------------------------------------------------- */

/* Key lengths worth a line: every size the algorithm lists, the longest key,
 * and lengths the library pads with zero bytes up to the next size. */
static int key_lengths(MCRYPT td, int *out)
{
	int count = 0, n = 0, i, max = mcrypt_enc_get_key_size(td);
	int *sizes = mcrypt_enc_get_supported_key_sizes(td, &count);

	if (sizes == NULL || count == 0) {	/* any length up to max */
		out[n++] = 1;
		if (max > 5)
			out[n++] = 5;
		if (max / 2 > 5)
			out[n++] = max / 2;
		out[n++] = max;
	} else {
		for (i = 0; i < count; i++)
			out[n++] = sizes[i];
		if (sizes[0] > 3)
			out[n++] = sizes[0] - 3;	/* padded to the first size */
		if (count > 1 && sizes[1] - sizes[0] > 4)
			out[n++] = sizes[0] + 4;	/* padded to the second size */
	}
	mcrypt_free(sizes);
	return n;
}

/* One encryption. Fills ct and state; returns 0, or the code of what failed. */
static int encrypt_once(const char *algorithm, const char *mode, MCRYPT td, unsigned char *key,
			int key_len, unsigned char *iv, const unsigned char *pt,
			unsigned char *ct, int len, unsigned char *state, int *state_len)
{
	unsigned char back[MAX_DATA];
	int rc;

	rc = mcrypt_generic_init(td, key, key_len, iv);
	if (rc < 0)
		return rc;
	memcpy(ct, pt, (size_t) len);
	rc = mcrypt_generic(td, ct, len);
	if (rc != 0) {
		mcrypt_generic_deinit(td);
		return rc;
	}
	*state_len = MAX_DATA;
	if (mcrypt_enc_get_state(td, state, state_len) != 0)
		*state_len = 0;
	mcrypt_generic_deinit(td);

	memcpy(back, ct, (size_t) len);
	if (mcrypt_generic_init(td, key, key_len, iv) < 0
	    || mdecrypt_generic(td, back, len) != 0
	    || memcmp(back, pt, (size_t) len) != 0)
		failure("decryption does not give the plaintext back", algorithm, mode);
	mcrypt_generic_deinit(td);
	return 0;
}

enum { NO_IV, RANDOM_IV, ALL_ONES_IV };

static void known_answer(const char *algorithm, const char *mode, MCRYPT td, int key_len,
			 int iv_kind)
{
	unsigned char key[MAX_DATA], iv[MAX_DATA], pt[MAX_DATA], ct[MAX_DATA], state[MAX_DATA];
	int block = mcrypt_enc_get_block_size(td), iv_len = mcrypt_enc_get_iv_size(td);
	int len, state_len = 0, rc, with_iv;

	if (mcrypt_enc_is_block_mode(td))
		len = 3 * block;
	else if (block > 1)
		len = 2 * block + 5;	/* ends inside a block */
	else
		len = 41;

	make_key(algorithm, key, key_len);
	rng_bytes(iv, iv_len);
	rng_bytes(pt, len);
	if (iv_kind == ALL_ONES_IV)
		memset(iv, 0xff, (size_t) iv_len);
	with_iv = iv_kind != NO_IV && iv_len > 0 && mcrypt_enc_mode_has_iv(td);

	rc = encrypt_once(algorithm, mode, td, key, key_len, with_iv ? iv : NULL, pt, ct, len,
			  state, &state_len);

	line_add("kat %s %s", algorithm, mode);
	line_add_hex("key", key, key_len);
	line_add_hex("iv", with_iv ? iv : NULL, iv_len);
	line_add_hex("pt", pt, len);
	if (rc != 0) {
		line_add(" error=%d", rc);
	} else {
		line_add_hex("ct", ct, len);
		line_add_hex("state", state, state_len);
	}
	line_end();
}

static void bulk(const char *algorithm, const char *mode, MCRYPT td)
{
	unsigned char key[MAX_DATA], iv[MAX_DATA], pt[MAX_DATA], ct[MAX_DATA], state[MAX_DATA];
	int block = mcrypt_enc_get_block_size(td), iv_len = mcrypt_enc_get_iv_size(td);
	int max_key = mcrypt_enc_get_key_size(td), block_mode = mcrypt_enc_is_block_mode(td);
	int has_iv = iv_len > 0 && mcrypt_enc_mode_has_iv(td);
	u64 digest = 0xcbf29ce484222325ULL;
	int i, errors = 0;

	for (i = 0; i < BULK_CASES; i++) {
		int key_len = rng_range(1, max_key), with_iv = has_iv && rng_range(0, 7) != 0;
		int len = block_mode ? block * rng_range(1, 4)
				     : rng_range(1, block > 1 ? 3 * block + 7 : 100);
		int state_len = 0;

		make_key(algorithm, key, key_len);
		rng_bytes(iv, iv_len);
		rng_bytes(pt, len);
		if (encrypt_once(algorithm, mode, td, key, key_len, with_iv ? iv : NULL, pt, ct,
				 len, state, &state_len) != 0) {
			errors++;
			continue;
		}
		digest = fnv(digest, ct, (size_t) len);
		digest = fnv(digest, state, (size_t) state_len);
	}

	line_add("bulk %s %s cases=%d errors=%d digest=%08lx%08lx", algorithm, mode, BULK_CASES,
		 errors, (unsigned long) (digest >> 32), (unsigned long) (digest & 0xffffffffUL));
	line_end();
}

static void refused_keys(const char *algorithm, const char *mode, MCRYPT td)
{
	unsigned char key[2 * MAX_DATA], iv[MAX_DATA];
	int max = mcrypt_enc_get_key_size(td), empty, too_long;

	memset(key, 0x41, sizeof(key));
	memset(iv, 0, sizeof(iv));
	empty = mcrypt_generic_init(td, key, 0, iv);
	too_long = mcrypt_generic_init(td, key, max + 1, iv);
	line_add("init %s %s keylen=0 rc=%d keylen=%d rc=%d", algorithm, mode, empty, max + 1,
		 too_long);
	line_end();
}

static void encrypt_pair(const char *algorithm, const char *mode)
{
	MCRYPT td = OPEN(algorithm, mode);
	int lengths[16], n, i;

	if (td == MCRYPT_FAILED)
		return;

	refused_keys(algorithm, mode, td);

	rng_seed(algorithm, mode, "kat");
	n = key_lengths(td, lengths);
	for (i = 0; i < n; i++)
		known_answer(algorithm, mode, td, lengths[i], RANDOM_IV);
	known_answer(algorithm, mode, td, mcrypt_enc_get_key_size(td), NO_IV);
	/* in ctr the IV is the counter: this one has to carry through every
	 * byte and start again from zero */
	if (mcrypt_enc_get_iv_size(td) > 0 && mcrypt_enc_mode_has_iv(td))
		known_answer(algorithm, mode, td, mcrypt_enc_get_key_size(td), ALL_ONES_IV);

	rng_seed(algorithm, mode, "bulk");
	bulk(algorithm, mode, td);

	mcrypt_module_close(td);
}

/* ------------------------------------------------------------------------ */

static void all_lines(void)
{
	int n_algorithms = 0, n_modes = 0, i, j;
	char **algorithms = LIST_ALGORITHMS(&n_algorithms);
	char **modes = LIST_MODES(&n_modes);

	describe_lists(algorithms, n_algorithms, modes, n_modes);

	for (i = 0; i < n_algorithms; i++)
		for (j = 0; j < n_modes; j++)
			describe_pair(algorithms[i], modes[j]);

	describe_open("rijndael_128", "cbc");	/* '_' stands for '-' */
	describe_open("blowfish_compat", "cfb");
	describe_open("cast_256", "ecb");
	describe_open("Rijndael-128", "cbc");
	describe_open("aes", "cbc");
	describe_open("rijndael-128", "CBC");
	describe_open("rijndael-128", "gcm");
	describe_open("", "");
	describe_open(NULL, "cbc");
	describe_open("des", NULL);
	describe_open(NULL, NULL);

	describe_errors();

	for (i = 0; i < n_algorithms; i++)
		for (j = 0; j < n_modes; j++)
			encrypt_pair(algorithms[i], modes[j]);

	mcrypt_free_p(algorithms, n_algorithms);
	mcrypt_free_p(modes, n_modes);
}

/* Compares this library with the answers in a file. Returns 0 when they all
 * agree, otherwise the number of problems. */
int libmcrypt_vectors_check(const char *path)
{
	size_t i;

	lines = differences = failures = 0;
	line_len = 0;

	if (!load_wanted(path)) {
		printf("FAILED     cannot read %s\n", path);
		fflush(stdout);
		return 1;
	}

	checking = 1;
	all_lines();
	checking = 0;

	for (i = 0; i < wanted_count; i++) {
		if (!wanted_seen[i] && differences++ < MAX_REPORTED)
			printf("DIFFERENT  in upstream's file but not here: %.80s\n", wanted[i]);
	}
	free_wanted();

	printf("libmcrypt %s vectors: %ld answers compared with upstream, %ld different, "
	       "%ld other failure%s\n", mcrypt_check_version(NULL), lines, differences,
	       failures, failures == 1 ? "" : "s");
	fflush(stdout);

	return (int) (differences + failures);
}

#ifndef LIBMCRYPT_VECTORS_NO_MAIN
int main(int argc, char **argv)
{
	if (argc == 3 && strcmp(argv[1], "check") == 0)
		return libmcrypt_vectors_check(argv[2]) ? 1 : 0;

	if (argc == 2 && strcmp(argv[1], "generate") == 0) {
#ifdef VECTORS_UPSTREAM_API
		puts("# Known answers of libmcrypt 2.5.8, written by test/vectors.c linked with");
		puts("# the unmodified upstream sources. Do not edit: \"vectors check\" compares");
		puts("# this file line by line with what the library answers.");
		puts("#");
		puts("# test/vectors.c describes the lines and how to make the file again.");
#else
		puts("# Written by test/vectors.c linked with this library, not with upstream.");
		puts("# For comparison only: do not replace test/vectors-2.5.8.txt with it.");
#endif
		all_lines();
		if (failures) {
			fprintf(stderr, "%ld failure%s while generating\n", failures,
				failures == 1 ? "" : "s");
			return 1;
		}
		return 0;
	}

	fprintf(stderr, "usage: %s generate | check FILE\n", argv[0]);
	return 2;
}
#endif
