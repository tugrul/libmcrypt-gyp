/**********************************************************
   TEA - Tiny Encryption Algorithm
   Feistel cipher by David Wheeler & Roger M. Needham
   (extended version)
 **********************************************************/

/* $Id: xtea.c,v 1.13 2003/01/19 17:48:27 nmav Exp $ */

/* modified in order to use the libmcrypt API by Nikos Mavroyanopoulos 
 * All modifications are placed under the license of libmcrypt.
 */

#include <libdefs.h>

#include <mcrypt_modules.h>

#define ROUNDS 32
#define DELTA 0x9e3779b9	/* sqr(5)-1 * 2^31 */

/**********************************************************
   Input values: 	k[4]	128-bit key
			v[2]    64-bit plaintext block
   Output values:	v[2]    64-bit ciphertext block 
 **********************************************************/

static int _mcrypt_set_key(void *ctx, const void *key, int len)
{
	word32 *k = ctx;
	const word32 *input_key = key;
	k[0] = 0;
	k[2] = 0;
	k[1] = 0;
	k[3] = 0;
	memmove(k, input_key, len);
	return 0;
}

static void _mcrypt_encrypt(void *ctx, void *block)
{
	word32 *k = ctx;
	word32 *v = block;
#ifdef WORDS_BIGENDIAN
	word32 y = v[0], z = v[1];
#else
	word32 y = byteswap32(v[0]), z = byteswap32(v[1]);
#endif
	word32 limit, sum = 0;
	int N = ROUNDS;

	limit = DELTA * N;
#ifdef WORDS_BIGENDIAN
	while (sum != limit) {
		y += (((z << 4) ^ (z >> 5)) + z) ^ (sum + k[sum & 3]);
		sum += DELTA;
		z += (((y << 4) ^ (y >> 5)) + y) ^ (sum +
						    k[(sum >> 11) & 3]);
	}
#else
	while (sum != limit) {
		y += (((z << 4) ^ (z >> 5)) + z) ^ (sum +
						    byteswap32(k
							       [sum & 3]));
		sum += DELTA;
		z += (((y << 4) ^ (y >> 5)) + y) ^ (sum +
						    byteswap32(k
							       [(sum >>
								 11) &
								3]));
	}
#endif

#ifdef WORDS_BIGENDIAN
	v[0] = y;
	v[1] = z;
#else
	v[0] = byteswap32(y);
	v[1] = byteswap32(z);
#endif
}

static void _mcrypt_decrypt(void *ctx, void *block)
{
	word32 *k = ctx;
	word32 *v = block;
#ifdef WORDS_BIGENDIAN
	word32 y = v[0], z = v[1];
#else
	word32 y = byteswap32(v[0]), z = byteswap32(v[1]);
#endif
	word32 sum = 0;
	int N = (-ROUNDS);

#ifdef WORDS_BIGENDIAN

	sum = DELTA * (-N);
	while (sum) {
		z -= (((y << 4) ^ (y >> 5)) + y) ^ (sum +
						    k[(sum >> 11) & 3]);
		sum -= DELTA;
		y -= (((z << 4) ^ (z >> 5)) + z) ^ (sum + k[sum & 3]);
#else
	sum = DELTA * (-N);
	while (sum) {
		z -= (((y << 4) ^ (y >> 5)) + y) ^ (sum +
						    byteswap32(k
							       [(sum >>
								 11) &
								3]));
		sum -= DELTA;
		y -= (((z << 4) ^ (z >> 5)) + z) ^ (sum +
						    byteswap32(k
							       [sum & 3]));
#endif
	}
#ifdef WORDS_BIGENDIAN
	v[0] = y;
	v[1] = z;
#else
	v[0] = byteswap32(y);
	v[1] = byteswap32(z);
#endif
}

/*
static void _mcrypt_encrypt(void *ctx, void *block)
{
	word32 *k = ctx;
	word32 *v = block;
	_mcrypt_tean(k, v, ROUNDS);
}

static void _mcrypt_decrypt(void *ctx, void *block)
{
	word32 *k = ctx;
	word32 *v = block;
	_mcrypt_tean(k, v, -ROUNDS);
}
*/

static int _mcrypt_get_size(void)
{
	return 4 * sizeof(word32);
}
static int _mcrypt_get_block_size(void)
{
	return 8;
}
static int _is_block_algorithm(void)
{
	return 1;
}
static int _mcrypt_get_key_size(void)
{
	return 16;
}

static const int key_sizes[] = { 16 };
static const int *_mcrypt_get_supported_key_sizes(int *len)
{
	*len = sizeof(key_sizes)/sizeof(int);
	return key_sizes;
}

static const char *_mcrypt_get_algorithms_name(void)
{
return "xTEA";
}

#define CIPHER "f61e7ff6da7cdb27"

static int _mcrypt_self_test(void)
{
	char *keyword;
	unsigned char plaintext[16];
	unsigned char ciphertext[16];
	int blocksize = _mcrypt_get_block_size(), j;
	void *key;
	unsigned char cipher_tmp[200];

	keyword = calloc(1, _mcrypt_get_key_size());
	if (keyword == NULL)
		return -1;

	for (j = 0; j < _mcrypt_get_key_size(); j++) {
		keyword[j] = ((j * 2 + 10) % 256);
	}

	for (j = 0; j < blocksize; j++) {
		plaintext[j] = j % 256;
	}
	key = malloc(_mcrypt_get_size());
	if (key == NULL)
		return -1;

	memcpy(ciphertext, plaintext, blocksize);

	_mcrypt_set_key(key, (void *) keyword, _mcrypt_get_key_size());
	free(keyword);
	_mcrypt_encrypt(key, (void *) ciphertext);

	for (j = 0; j < blocksize; j++) {
		sprintf(&((char *) cipher_tmp)[2 * j], "%.2x",
			ciphertext[j]);
	}

	if (strcmp((char *) cipher_tmp, CIPHER) != 0) {
		printf("failed compatibility\n");
		printf("Expected: %s\nGot: %s\n", CIPHER,
		       (char *) cipher_tmp);
		free(key);
		return -1;
	}
	_mcrypt_decrypt(key, (void *) ciphertext);
	free(key);

	if (strcmp((const char *) ciphertext, (const char *) plaintext) != 0) {
		printf("failed internally\n");
		return -1;
	}

	return 0;
}

static word32 _mcrypt_algorithm_version(void)
{
	return 20010801;
}

const mcrypt_algo_module mcrypt_algo_xtea = {
	.name = "xtea",
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
