/* 
 * Copyright (C) 1998,1999,2000,2001 Nikos Mavroyanopoulos
 *
 * This library is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU Library General Public License as published 
 * by the Free Software Foundation; either version 2 of the License, or 
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <libdefs.h>

#include <mcrypt_modules.h>
#include "wake.h"

/* WAKE reference C-code, based on the description in David J. Wheeler's
 * paper "A bulk Data Encryption Algorithm"
 */

/* #define USE_IV */
/* IV is an mcrypt extension */

static const word32 tt[10] = {
	0x726a8f3bUL,
	0xe69a3b5cUL,
	0xd3c71fe5UL,
	0xab3c73d2UL,
	0x4d3a8eb3UL,
	0x0396d6e8UL,
	0x3d4c2f7aUL,
	0x9ee27cf3UL
};

static int _mcrypt_set_key(void *ctx, const void *user_key, int len,
                           const void *iv, int ivlen)
{
	WAKE_KEY *wake_key = ctx;
	const word32 *key = user_key;
#ifdef USE_IV
	const word32 *IV = iv;
#endif
	word32 x, z, p;
	word32 k[4];
/* the key must be exactly 256 bits */
	if (len != 32)
		return -1;

#ifdef WORDS_BIGENDIAN
	k[0] = byteswap32(key[0]);
	k[1] = byteswap32(key[1]);
	k[2] = byteswap32(key[2]);
	k[3] = byteswap32(key[3]);
#else
	k[0] = key[0];
	k[1] = key[1];
	k[2] = key[2];
	k[3] = key[3];
#endif

	for (p = 0; p < 4; p++) {
		wake_key->t[p] = k[p];
	}

	for (p = 4; p < 256; p++) {
		x = wake_key->t[p - 4] + wake_key->t[p - 1];
		wake_key->t[p] = x >> 3 ^ tt[x & 7];
	}

	for (p = 0; p < 23; p++)
		wake_key->t[p] += wake_key->t[p + 89];

	x = wake_key->t[33];
	z = wake_key->t[59] | 0x01000001;
	z &= 0xff7fffff;

	for (p = 0; p < 256; p++) {
		x = (x & 0xff7fffff) + z;
		wake_key->t[p] = (wake_key->t[p] & 0x00ffffff) ^ x;
	}

	wake_key->t[256] = wake_key->t[0];
	x &= 0xff;

	for (p = 0; p < 256; p++) {
		wake_key->t[p] = wake_key->t[x =
					     (wake_key->t[p ^ x] ^ x) &
					     0xff];
		wake_key->t[x] = wake_key->t[p + 1];
	}

	wake_key->counter = 0;
	wake_key->r[0] = k[0];
	wake_key->r[1] = k[1];
	wake_key->r[2] = k[2];
#ifdef WORDS_BIGENDIAN
	wake_key->r[3] = byteswap32(k[3]);
#else
	wake_key->r[3] = k[3];
#endif
#ifdef USE_IV
	wake_key->started = 0;
	if (ivlen > 32)
		wake_key->ivsize = 32;
	else
		wake_key->ivsize = ivlen / 4 * 4;

	if (IV == NULL)
		wake_key->ivsize = 0;
	if (wake_key->ivsize > 0 && IV != NULL)
		memcpy(&wake_key->iv, IV, wake_key->ivsize);
#endif

	return 0;
}

/* in order to read the code easier */
#define r2 wake_key->tmp
#define r1 wake_key->tmp
#define counter wake_key->counter

/* M(X,Y) = (X+Y)>>8 XOR t[(X+Y) & 0xff] */
#define M(X,Y) _int_M(X,Y, wake_key)
inline static word32 _int_M(word32 X, word32 Y, WAKE_KEY * wake_key)
{
	register word32 TMP;

	TMP = X + Y;
	return ((((TMP) >> 8) & 0x00ffffff) ^ wake_key->t[(TMP) & 0xff]);
}

static void _mcrypt_encrypt(void *ctx, void *data, int len)
{
	WAKE_KEY *wake_key = ctx;
	byte *input = data;
	register word32 r3, r4, r5;
	word32 r6;
	int i;

	if (len == 0)
		return;

	r3 = wake_key->r[0];
	r4 = wake_key->r[1];
	r5 = wake_key->r[2];
	r6 = wake_key->r[3];

#ifdef USE_IV
	if (wake_key->started == 0) {
		wake_key->started = 1;
		_mcrypt_encrypt(wake_key, (byte *) & wake_key->iv,
				wake_key->ivsize);
	}
#endif

	for (i = 0; i < len; i++) {
		/* R1 = V[n] = V[n] XOR R6 - here we do it per byte --sloooow */
		/* R1 is ignored */
		input[i] ^= ((byte *) & r6)[counter];

		/* R2 = V[n] = R1 - per byte also */
		((byte *) & r2)[counter] = input[i];
		counter++;

		if (counter == 4) {	/* r6 was used - update it! */
			counter = 0;

#ifdef WORDS_BIGENDIAN
			/* these swaps are because we do operations per byte */
			r2 = byteswap32(r2);
			r6 = byteswap32(r6);
#endif
			r3 = M(r3, r2);
			r4 = M(r4, r3);
			r5 = M(r5, r4);
			r6 = M(r6, r5);

#ifdef WORDS_BIGENDIAN
			r6 = byteswap32(r6);
#endif
		}
	}

	wake_key->r[0] = r3;
	wake_key->r[1] = r4;
	wake_key->r[2] = r5;
	wake_key->r[3] = r6;

}


static void _mcrypt_decrypt(void *ctx, void *data, int len)
{
	WAKE_KEY *wake_key = ctx;
	byte *input = data;
	register word32 r3, r4, r5;
	word32 r6;
	int i;

	if (len == 0)
		return;

	r3 = wake_key->r[0];
	r4 = wake_key->r[1];
	r5 = wake_key->r[2];
	r6 = wake_key->r[3];

#ifdef USE_IV
	if (wake_key->started == 0) {
		wake_key->started = 1;
		_mcrypt_encrypt(wake_key, (byte *) & wake_key->iv,
				wake_key->ivsize);
		wake_key->r[0] = r3;
		wake_key->r[1] = r4;
		wake_key->r[2] = r5;
		wake_key->r[3] = r6;
		_mcrypt_decrypt(wake_key, (byte *) & wake_key->iv,
				wake_key->ivsize);
	}
#endif

	for (i = 0; i < len; i++) {
		/* R1 = V[n] */
		((byte *) & r1)[counter] = input[i];
		/* R2 = V[n] = V[n] ^ R6 */
		/* R2 is ignored */
		input[i] ^= ((byte *) & r6)[counter];
		counter++;

		if (counter == 4) {
			counter = 0;

#ifdef WORDS_BIGENDIAN
			r1 = byteswap32(r1);
			r6 = byteswap32(r6);
#endif
			r3 = M(r3, r1);
			r4 = M(r4, r3);
			r5 = M(r5, r4);
			r6 = M(r6, r5);

#ifdef WORDS_BIGENDIAN
			r6 = byteswap32(r6);
#endif
		}
	}

	wake_key->r[0] = r3;
	wake_key->r[1] = r4;
	wake_key->r[2] = r5;
	wake_key->r[3] = r6;

}


static int _mcrypt_get_size(void)
{
	return sizeof(WAKE_KEY);
}
static int _mcrypt_get_block_size(void)
{
	return 1;
}
static int _mcrypt_get_algo_iv_size(void)
{
#ifdef USE_IV
	return 32;
#else
	return 0;
#endif
}
static int _is_block_algorithm(void)
{
	return 0;
}
static int _mcrypt_get_key_size(void)
{
	return 32;
}

static const int key_sizes[] = { 32 };
static const int *_mcrypt_get_supported_key_sizes(int *len)
{
	*len = sizeof(key_sizes)/sizeof(int);
	return key_sizes;
}

static const char *_mcrypt_get_algorithms_name(void)
{
return "WAKE";
}

#define CIPHER "434d575db053acfe6e4076f05298bedbd5f4f000be555d029b1367cffc7cd51bba61c76aa17da3530fb7d9"

static int _mcrypt_self_test(void)
{
	unsigned char *keyword;
	unsigned char plaintext[43];
	unsigned char ciphertext[43];
	int blocksize = 43, j;
	void *key, *key2;
	unsigned char cipher_tmp[200];

	keyword = calloc(1, _mcrypt_get_key_size());
	for (j = 0; j < _mcrypt_get_key_size(); j++) {
		keyword[j] = (j * 5 + 10) & 0xff;
	}

	for (j = 0; j < blocksize; j++) {
		plaintext[j] = (j + 5) % 0xff;
	}
	key = malloc(_mcrypt_get_size());
	key2 = malloc(_mcrypt_get_size());

	memcpy(ciphertext, plaintext, blocksize);

	_mcrypt_set_key(key, (void *) keyword, _mcrypt_get_key_size(),
			NULL, 0);
	_mcrypt_encrypt(key, (void *) ciphertext, blocksize);
	free(key);

	for (j = 0; j < blocksize; j++) {
		sprintf(&((char *) cipher_tmp)[2 * j], "%.2x",
			ciphertext[j]);
	}

	if (strcmp((char *) cipher_tmp, CIPHER) != 0) {
		printf("failed compatibility\n");
		printf("Expected: %s\nGot: %s\n", CIPHER,
		       (char *) cipher_tmp);
		free(keyword);
		free(key2);
		return -1;
	}
	_mcrypt_set_key(key2, (void *) keyword, _mcrypt_get_key_size(),
			NULL, 0);
	free(keyword);

	_mcrypt_decrypt(key2, (void *) ciphertext, blocksize);
	free(key2);

	if (memcmp(ciphertext, plaintext, blocksize) != 0) {
		printf("failed internally\n");
		return -1;
	}

	return 0;
}

static word32 _mcrypt_algorithm_version(void)
{
	return 20010801;
}

const mcrypt_algo_module mcrypt_algo_wake = {
	.name = "wake",
	.stream_set_key = _mcrypt_set_key,
	.stream_encrypt = _mcrypt_encrypt,
	.stream_decrypt = _mcrypt_decrypt,
	.get_size = _mcrypt_get_size,
	.get_block_size = _mcrypt_get_block_size,
	.is_block_algo = _is_block_algorithm,
	.get_key_size = _mcrypt_get_key_size,
	.get_algo_iv_size = _mcrypt_get_algo_iv_size,
	.get_supported_key_sizes = _mcrypt_get_supported_key_sizes,
	.get_name = _mcrypt_get_algorithms_name,
	.self_test = _mcrypt_self_test,
	.get_version = _mcrypt_algorithm_version
};
