/********************************************************************\
*                                                                    *
* C specification of the threeway block cipher                       *
*                                                                    *
* found in ftp://ftp.funet.fi/pub/crypt/                             *
\********************************************************************/

/* modified in order to use the libmcrypt API by Nikos Mavroyanopoulos 
 * All modifications are placed under the license of libmcrypt.
 */

/* $Id: 3-way.c,v 1.12 2003/01/19 17:48:27 nmav Exp $ */

#include <libdefs.h>

#include <mcrypt_modules.h>
#include "3-way.h"

#define   STRT_E   0x0b0b	/* round constant of first encryption round */
#define   STRT_D   0xb1b1	/* round constant of first decryption round */
#define     NMBR       11	/* number of rounds is 11                   */

static int _mcrypt_set_key(void *ctx, const void *key, int len)
{
	word32 *k = ctx;
	const word32 *input_key = key;
	k[0] = 0;
	k[2] = 0;
	k[1] = 0;
	memmove(k, input_key, len);
	return 0;
}


void mu(word32 * a)
{				/* inverts the order of the bits of a */
	int i;
	word32 b[3];

	b[0] = b[1] = b[2] = 0;
	for (i = 0; i < 32; i++) {
		b[0] <<= 1;
		b[1] <<= 1;
		b[2] <<= 1;
		if (a[0] & 1)
			b[2] |= 1;
		if (a[1] & 1)
			b[1] |= 1;
		if (a[2] & 1)
			b[0] |= 1;
		a[0] >>= 1;
		a[1] >>= 1;
		a[2] >>= 1;
	}

	a[0] = b[0];
	a[1] = b[1];
	a[2] = b[2];
}

void threeway_gamma(word32 * a)
{				/* the nonlinear step */
	word32 b[3];

	b[0] = a[0] ^ (a[1] | (~a[2]));
	b[1] = a[1] ^ (a[2] | (~a[0]));
	b[2] = a[2] ^ (a[0] | (~a[1]));

	a[0] = b[0];
	a[1] = b[1];
	a[2] = b[2];
}


void theta(word32 * a)
{				/* the linear step */
	word32 b[3];

	b[0] =
	    a[0] ^ (a[0] >> 16) ^ (a[1] << 16) ^ (a[1] >> 16) ^ (a[2] <<
								 16) ^
	    (a[1] >> 24) ^ (a[2] << 8) ^ (a[2] >> 8) ^ (a[0] << 24) ^ (a[2]
								       >>
								       16)
	    ^ (a[0] << 16) ^ (a[2] >> 24) ^ (a[0] << 8);
	b[1] =
	    a[1] ^ (a[1] >> 16) ^ (a[2] << 16) ^ (a[2] >> 16) ^ (a[0] <<
								 16) ^
	    (a[2] >> 24) ^ (a[0] << 8) ^ (a[0] >> 8) ^ (a[1] << 24) ^ (a[0]
								       >>
								       16)
	    ^ (a[1] << 16) ^ (a[0] >> 24) ^ (a[1] << 8);
	b[2] =
	    a[2] ^ (a[2] >> 16) ^ (a[0] << 16) ^ (a[0] >> 16) ^ (a[1] <<
								 16) ^
	    (a[0] >> 24) ^ (a[1] << 8) ^ (a[1] >> 8) ^ (a[2] << 24) ^ (a[1]
								       >>
								       16)
	    ^ (a[2] << 16) ^ (a[1] >> 24) ^ (a[2] << 8);

	a[0] = b[0];
	a[1] = b[1];
	a[2] = b[2];
}

void pi_1(word32 * a)
{
	a[0] = (a[0] >> 10) ^ (a[0] << 22);
	a[2] = (a[2] << 1) ^ (a[2] >> 31);
}

void pi_2(word32 * a)
{
	a[0] = (a[0] << 1) ^ (a[0] >> 31);
	a[2] = (a[2] >> 10) ^ (a[2] << 22);
}

void rho(word32 * a)
{				/* the round function       */
	theta(a);
	pi_1(a);
	threeway_gamma(a);
	pi_2(a);
}

void rndcon_gen(word32 strt, word32 * rtab)
{				/* generates the round constants */
	int i;

	for (i = 0; i <= NMBR; i++) {
		rtab[i] = strt;
		strt <<= 1;
		if (strt & 0x10000)
			strt ^= 0x11011;
	}
}

static void _mcrypt_encrypt(void *ctx, void *block)
{
	word32 *tk = ctx;
	word32 *ta = block;
	int i;
	word32 rcon[NMBR + 1];
	word32 a[3], k[3];

/* Added to make it compatible with bigendian machines
 * --nikos
 */

#ifndef WORDS_BIGENDIAN
	a[0] = byteswap32(ta[0]);
	a[1] = byteswap32(ta[1]);
	a[2] = byteswap32(ta[2]);
	k[0] = byteswap32(tk[0]);
	k[1] = byteswap32(tk[1]);
	k[2] = byteswap32(tk[2]);
#else
	a[0] = ta[0];
	a[1] = ta[1];
	a[2] = ta[2];
	k[0] = (tk[0]);
	k[1] = (tk[1]);
	k[2] = (tk[2]);
#endif

	rndcon_gen(STRT_E, rcon);
	for (i = 0; i < NMBR; i++) {
		a[0] ^= k[0] ^ (rcon[i] << 16);
		a[1] ^= k[1];
		a[2] ^= k[2] ^ rcon[i];
		rho(a);
	}
	a[0] ^= k[0] ^ (rcon[NMBR] << 16);
	a[1] ^= k[1];
	a[2] ^= k[2] ^ rcon[NMBR];
	theta(a);

#ifndef WORDS_BIGENDIAN
	ta[0] = byteswap32(a[0]);
	ta[1] = byteswap32(a[1]);
	ta[2] = byteswap32(a[2]);
#else
	ta[0] = a[0];
	ta[1] = a[1];
	ta[2] = a[2];
#endif

}


static void _mcrypt_decrypt(void *ctx, void *block)
{
	word32 *k = ctx;
	word32 *ta = block;
	int i;
	word32 ki[3];		/* the `inverse' key             */
	word32 rcon[NMBR + 1];	/* the `inverse' round constants */
	word32 a[3];

#ifndef WORDS_BIGENDIAN
	a[0] = byteswap32(ta[0]);
	a[1] = byteswap32(ta[1]);
	a[2] = byteswap32(ta[2]);
	ki[0] = byteswap32(k[0]);
	ki[1] = byteswap32(k[1]);
	ki[2] = byteswap32(k[2]);
#else
	a[0] = ta[0];
	a[1] = ta[1];
	a[2] = ta[2];
	ki[0] = k[0];
	ki[1] = k[1];
	ki[2] = k[2];
#endif

	theta(ki);
	mu(ki);

	rndcon_gen(STRT_D, rcon);

	mu(a);
	for (i = 0; i < NMBR; i++) {
		a[0] ^= ki[0] ^ (rcon[i] << 16);
		a[1] ^= ki[1];
		a[2] ^= ki[2] ^ rcon[i];
		rho(a);
	}
	a[0] ^= ki[0] ^ (rcon[NMBR] << 16);
	a[1] ^= ki[1];
	a[2] ^= ki[2] ^ rcon[NMBR];
	theta(a);
	mu(a);

#ifndef WORDS_BIGENDIAN
	ta[0] = byteswap32(a[0]);
	ta[1] = byteswap32(a[1]);
	ta[2] = byteswap32(a[2]);

#else
	ta[0] = a[0];
	ta[1] = a[1];
	ta[2] = a[2];
#endif

}

static int _mcrypt_get_size(void)
{
	return 3 * sizeof(word32);
}
static int _mcrypt_get_block_size(void)
{
	return 12;
}
static int _is_block_algorithm(void)
{
	return 1;
}
static int _mcrypt_get_key_size(void)
{
	return 12;
}

static const int key_sizes[] = { 12 };
static const int *_mcrypt_get_supported_key_sizes(int *len)
{
	*len = sizeof(key_sizes)/sizeof(int);
	return key_sizes;

}
static const char *_mcrypt_get_algorithms_name(void)
{
return "3-WAY";
}

#define CIPHER "46823287358d68f6e034ca62"

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

const mcrypt_algo_module mcrypt_algo_threeway = {
	.name = "threeway",
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
