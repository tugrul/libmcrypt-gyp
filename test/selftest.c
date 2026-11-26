/*
 * Self-test for the static libmcrypt build.
 *
 *   1. every algorithm's built-in known-answer test
 *   2. AES-128 (rijndael-128) known answers in all seven block modes
 *   3. an encrypt/decrypt round trip through every algorithm/mode pair
 *   4. for every pair, a message handed over in several calls must give the
 *      same result as in one call
 *
 * Exits 0 when everything passes. Run it through CTest or directly.
 *
 * With LIBMCRYPT_SELFTEST_NO_MAIN defined, only libmcrypt_selftest() is
 * compiled, for callers that have their own entry point (test/addon/addon.c).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mcrypt.h>

static int failures = 0;

static void fail(const char *what, const char *algo, const char *mode)
{
	printf("FAILED  %-22s %s%s%s\n", what, algo, mode ? "/" : "", mode ? mode : "");
	failures++;
}

static int unhex(const char *hex, unsigned char *out)
{
	int n = 0;
	unsigned int byte;

	for (; hex[0] && hex[1]; hex += 2) {
		sscanf(hex, "%2x", &byte);
		out[n++] = (unsigned char) byte;
	}
	return n;
}

/* Key, IV and first plaintext block of NIST SP 800-38A, appendix F. */
#define AES_KEY "2b7e151628aed2a6abf7158809cf4f3c"
#define AES_IV  "000102030405060708090a0b0c0d0e0f"
#define AES_CTR "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
#define AES_PT  "6bc1bee22e409f96e93d7e117393172a"

static const struct {
	const char *mode, *iv, *cipher;
} aes_vectors[] = {
	{ "ecb",  NULL,    "3ad77bb40d7a3660a89ecaf32466ef97" },	/* F.1.1 */
	{ "cbc",  AES_IV,  "7649abac8119b246cee98e9b12e9197d" },	/* F.2.1 */
	{ "cfb",  AES_IV,  "3b79424c9c0dd436bace9e0ed4586a4f" },	/* F.3.7,  CFB-8 */
	{ "ncfb", AES_IV,  "3b3fd92eb72dad20333449f8e83cfb4a" },	/* F.3.13, CFB-128 */
	{ "nofb", AES_IV,  "3b3fd92eb72dad20333449f8e83cfb4a" },	/* F.4.1,  OFB */
	{ "ctr",  AES_CTR, "874d6191b620e3261bef6864990db6ce" },	/* F.5.1 */
	/* 8-bit OFB is not a NIST mode; value from unmodified libmcrypt 2.5.8 */
	{ "ofb",  AES_IV,  "3b95b11c62c9b759f605bbce1812c67c" }
};

static void test_aes_vectors(void)
{
	unsigned char key[16], iv[16], buf[16], expect[16];
	size_t i;

	for (i = 0; i < sizeof(aes_vectors) / sizeof(aes_vectors[0]); i++) {
		MCRYPT td = mcrypt_module_open("rijndael-128", (char *) aes_vectors[i].mode);

		if (td == MCRYPT_FAILED) {
			fail("open", "rijndael-128", aes_vectors[i].mode);
			continue;
		}
		unhex(AES_KEY, key);
		unhex(AES_PT, buf);
		unhex(aes_vectors[i].cipher, expect);
		if (aes_vectors[i].iv != NULL)
			unhex(aes_vectors[i].iv, iv);

		if (mcrypt_generic_init(td, key, 16, aes_vectors[i].iv ? iv : NULL) < 0
		    || mcrypt_generic(td, buf, 16) != 0
		    || memcmp(buf, expect, 16) != 0)
			fail("known answer", "rijndael-128", aes_vectors[i].mode);

		mcrypt_generic_end(td);
	}
}

static void test_round_trip(const char *algo, const char *mode, int *pairs)
{
	unsigned char key[512], iv[512], plain[512], buf[512];
	int i, keysize, ivsize, len;
	MCRYPT td = mcrypt_module_open((char *) algo, (char *) mode);

	if (td == MCRYPT_FAILED)
		return;		/* block algorithm with a stream mode, or the reverse */
	(*pairs)++;

	keysize = mcrypt_enc_get_key_size(td);
	ivsize = mcrypt_enc_get_iv_size(td);
	len = mcrypt_enc_is_block_mode(td) ? 4 * mcrypt_enc_get_block_size(td) : 61;

	for (i = 0; i < (int) sizeof(key); i++) {
		key[i] = (unsigned char) (i * 7 + 0x81);	/* includes bytes >= 0x80 */
		iv[i] = (unsigned char) (i * 13 + 5);
		plain[i] = (unsigned char) (i * 31 + 0xc3);
	}
	memcpy(buf, plain, len);

	if (mcrypt_generic_init(td, key, keysize, ivsize > 0 ? iv : NULL) < 0
	    || mcrypt_generic(td, buf, len) != 0
	    || mcrypt_generic_deinit(td) < 0) {
		fail("encrypt", algo, mode);
	} else if (memcmp(buf, plain, len) == 0) {
		fail("ciphertext==plaintext", algo, mode);
	} else if (mcrypt_generic_init(td, key, keysize, ivsize > 0 ? iv : NULL) < 0
		   || mdecrypt_generic(td, buf, len) != 0
		   || mcrypt_generic_deinit(td) < 0) {
		fail("decrypt", algo, mode);
	} else if (memcmp(buf, plain, len) != 0) {
		fail("round trip", algo, mode);
	}

	mcrypt_module_close(td);
}

/* The size of piece number n. cbc and ecb take whole blocks only. The other
 * modes get pieces that end inside a block, exactly on a block boundary and
 * across one, which are the cases upstream's ncfb got wrong. */
static int piece_size(int n, int bs, int block_mode, int decrypting)
{
	if (block_mode)
		return bs * (1 + (n + decrypting) % 3);
	if (bs <= 5) {		/* stream algorithms */
		static const int sizes[] = { 5, 1, 30, 9, 16, 3 };
		return sizes[(n + 2 * decrypting) % 6];
	}
	if (decrypting) {
		switch (n % 6) {
		case 0: return 3;
		case 1: return bs + 5;
		case 2: return 1;
		case 3: return 2 * bs - 1;
		case 4: return bs - 4;
		default: return bs;
		}
	}
	switch (n % 9) {
	case 0: return 5;
	case 1: return bs - 5;	/* fills the block exactly */
	case 2: return 7;
	case 3: return bs;	/* a whole block starting inside a block */
	case 4: return 3;
	case 5: return 2 * bs + 1;
	case 6: return 1;
	case 7: return bs - 1;
	default: return bs + 2;
	}
}

static void test_split_calls(const char *algo, const char *mode)
{
	unsigned char key[512], iv[512], plain[512], whole[512], pieces[512];
	int i, n, off, keysize, ivsize, bs, block_mode, len;
	MCRYPT td = mcrypt_module_open((char *) algo, (char *) mode);

	if (td == MCRYPT_FAILED)
		return;

	keysize = mcrypt_enc_get_key_size(td);
	ivsize = mcrypt_enc_get_iv_size(td);
	bs = mcrypt_enc_get_block_size(td);
	block_mode = mcrypt_enc_is_block_mode(td);
	len = block_mode ? 12 * bs : 12 * bs + 13;

	for (i = 0; i < (int) sizeof(key); i++) {
		key[i] = (unsigned char) (i * 11 + 0x85);
		iv[i] = (unsigned char) (i * 17 + 9);
		plain[i] = (unsigned char) (i * 29 + 0x3b);
	}

	memcpy(whole, plain, len);
	if (mcrypt_generic_init(td, key, keysize, ivsize > 0 ? iv : NULL) < 0
	    || mcrypt_generic(td, whole, len) != 0
	    || mcrypt_generic_deinit(td) < 0) {
		fail("encrypt", algo, mode);
		mcrypt_module_close(td);
		return;
	}

	memcpy(pieces, plain, len);
	mcrypt_generic_init(td, key, keysize, ivsize > 0 ? iv : NULL);
	for (n = 0, off = 0; off < len; n++, off += i) {
		i = piece_size(n, bs, block_mode, 0);
		if (i > len - off)
			i = len - off;
		mcrypt_generic(td, pieces + off, i);
	}
	mcrypt_generic_deinit(td);
	if (memcmp(pieces, whole, len) != 0)
		fail("encrypt in pieces", algo, mode);

	memcpy(pieces, whole, len);
	mcrypt_generic_init(td, key, keysize, ivsize > 0 ? iv : NULL);
	for (n = 0, off = 0; off < len; n++, off += i) {
		i = piece_size(n, bs, block_mode, 1);
		if (i > len - off)
			i = len - off;
		mdecrypt_generic(td, pieces + off, i);
	}
	mcrypt_generic_deinit(td);
	if (memcmp(pieces, plain, len) != 0)
		fail("decrypt in pieces", algo, mode);

	mcrypt_module_close(td);
}

/* Returns the number of failures. */
int libmcrypt_selftest(void)
{
	int n_algos = 0, n_modes = 0, pairs = 0, i, j;
	char **algos = mcrypt_list_algorithms(&n_algos);
	char **modes = mcrypt_list_modes(&n_modes);

	if (algos == NULL || modes == NULL || n_algos == 0 || n_modes == 0) {
		printf("FAILED  no algorithms or modes registered\n");
		fflush(stdout);
		return 1;
	}

	for (i = 0; i < n_algos; i++) {
		if (mcrypt_module_self_test(algos[i]) != 0)
			fail("built-in self-test", algos[i], NULL);
	}

	test_aes_vectors();

	for (i = 0; i < n_algos; i++) {
		for (j = 0; j < n_modes; j++)
			test_round_trip(algos[i], modes[j], &pairs);
	}

	for (i = 0; i < n_algos; i++) {
		for (j = 0; j < n_modes; j++)
			test_split_calls(algos[i], modes[j]);
	}

	printf("libmcrypt %s: %d algorithms, %d modes, %d algorithm/mode pairs, %d failure%s\n",
	       mcrypt_check_version(NULL), n_algos, n_modes, pairs,
	       failures, failures == 1 ? "" : "s");

	fflush(stdout);

	mcrypt_free_p(algos, n_algos);
	mcrypt_free_p(modes, n_modes);

	return failures;
}

#ifndef LIBMCRYPT_SELFTEST_NO_MAIN
int main(void)
{
	return libmcrypt_selftest() ? 1 : 0;
}
#endif
