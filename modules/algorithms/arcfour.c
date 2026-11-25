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

#include <lib/libdefs.h>
#include <lib/mcrypt_modules.h>
#include <stdlib.h>
#include "arcfour.h"

#define swap_byte(x,y) tmp = (x); (x) = (y); (y) = tmp

/* #define USE_IV */
/* IV was an mcrypt extension */

static void _mcrypt_encrypt(void *ctx, void *data, int buffer_len);

/* key is the state that should be allocated by the caller */
#define STATE key->state
#define I key->i
#define J key->j
static int _mcrypt_set_key(void *ctx, const void *user_key, int key_len,
                           const void *iv, int iv_len)
{
	arcfour_key *key = ctx;
	const byte *key_data = user_key;
#ifdef USE_IV
	const char *IV = iv;
#endif
	register int tmp, j, i;
	byte *state = STATE;
    #ifdef USE_IV
	int ivindex;
    ivindex = 0;
    #endif

	for (i = 0; i < 256; i++)
		state[i] = i;

	I = 0;
	J = 0;
	

	for (j = i = 0; i < 256; i++) {
		j += state[i] + key_data[i % key_len];
#ifdef USE_IV
		if (iv_len > 0 && IV != NULL)
			j += IV[ivindex];
#endif
		j &= 0xff;
		swap_byte(state[i], state[j]);
#ifdef USE_IV
		if (iv_len > 0)
			ivindex = (ivindex + 1) % iv_len;
#endif
	}

	return 0;
}

static void _mcrypt_encrypt(void *ctx, void *data, int buffer_len)
{
	arcfour_key *key = ctx;
	byte *buffer_ptr = data;
	register int tmp;
	register int counter;
	register int i = I, j = J;
	byte *state = STATE;


	for (counter = 0; counter < buffer_len; counter++) {
		i++;
		i &= 0xff;
		j += state[i];
		j &= 0xff;

		/* swap state[i] and state[j] */
		swap_byte(state[i], state[j]);
		buffer_ptr[counter] ^= state[(state[i] + tmp) & 0xff];
	}
	J = j;
	I = i;
}

/* this is the same with mcrypt_encrypt */
static void _mcrypt_decrypt(void *ctx, void *data, int buffer_len)
{
	arcfour_key *key = ctx;
	byte *buffer_ptr = data;
	_mcrypt_encrypt(key, buffer_ptr, buffer_len);
}

static int _mcrypt_get_size(void)
{
	return sizeof(arcfour_key);
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
	return 256;
}
static const int *_mcrypt_get_supported_key_sizes(int *len)
{
	*len = 0;
	return NULL;
}
static const char *_mcrypt_get_algorithms_name(void)
{
return "RC4";
}

#define CIPHER "3abaa03a286e24c4196d292ab72934d6854c3eee"

static int _mcrypt_self_test(void)
{
	char *keyword;
	unsigned char plaintext[20];
	unsigned char ciphertext[20];
	int blocksize = 20, j;
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

	_mcrypt_set_key(key, (void *) keyword, _mcrypt_get_key_size(),
			NULL, 0);
	_mcrypt_encrypt(key, (void *) ciphertext, blocksize);

	for (j = 0; j < blocksize; j++) {
		sprintf(&((char *) cipher_tmp)[2 * j], "%.2x",
			ciphertext[j]);
	}

	if (strcmp((char *) cipher_tmp, CIPHER) != 0) {
		printf("failed compatibility\n");
		printf("Expected: %s\nGot: %s\n", CIPHER,
		       (char *) cipher_tmp);
		free(keyword);
		free(key);
		return -1;
	}

	_mcrypt_set_key(key, (void *) keyword, _mcrypt_get_key_size(),
			NULL, 0);
	_mcrypt_decrypt(key, (void *) ciphertext, blocksize);

	free(keyword);
	free(key);
	if (strcmp((const char *) ciphertext, (const char *) plaintext) != 0) {
		printf("failed internally\n");
		return -1;
	}

	return 0;
}

static word32 _mcrypt_algorithm_version(void)
{
	return 20020610;
}

const mcrypt_algo_module mcrypt_algo_arcfour = {
	.name = "arcfour",
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
