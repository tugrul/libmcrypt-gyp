/*
 *    "enigma.c" is in file cbw.tar from
 *      anonymous FTP host watmsg.waterloo.edu: pub/crypt/cbw.tar.Z
 *
 *      A one-rotor machine designed along the lines of Enigma
 *      but considerably trivialized.
 *
 *      A public-domain replacement for the UNIX "crypt" command.
 *      Changed to fit in mcrypt by nmav@hellug.gr
 */

/* modified in order to use the libmcrypt API by Nikos Mavroyanopoulos 
 * All modifications are placed under the license of libmcrypt.
 */

/* $Id: enigma.c,v 1.13 2003/01/19 17:48:27 nmav Exp $ */

#include <libdefs.h>

#include <mcrypt_modules.h>
#include "enigma.h"

/* it needs to be linked against libufc or libcrypt */
/* it no longer needs that. It just needs the password to be
 * transformed by unix crypt() or the mhash SCRYPT 
 */

/* The key generator below depends on 32-bit wrap-around. Signed overflow is
 * undefined in C and optimisers act on that, so multiply and add as unsigned
 * and convert back. The values are the same as with wrapping signed ints. */
#define MUL_ADD(a, b, c) ((sword32) ((word32) (a) * (word32) (b) + (word32) (c)))

static int _mcrypt_set_key(void *ctx, const void *key, int plen,
                           const void *u1, int u2)
{
	CRYPT_KEY *ckey = ctx;
	const char *password = key;
	int ic, i, k, temp;
	unsigned random;
	sword32 seed;


	Bzero(ckey, sizeof(CRYPT_KEY));
	ckey->n1 = ckey->n2 = ckey->nr1 = ckey->nr2 = 0;

	if (plen > 13)
		plen = 13;

	memmove(ckey->cbuf, password, plen);

	seed = 123;
	for (i = 0; i < 13; i++)
		seed = MUL_ADD(seed, ckey->cbuf[i], i);
	for (i = 0; i < ROTORSZ; i++) {
		ckey->t1[i] = i;
		ckey->deck[i] = i;
	}
	for (i = 0; i < ROTORSZ; i++) {
		seed = MUL_ADD(5, seed, ckey->cbuf[i % 13]);
		random = seed % 65521;
		k = ROTORSZ - 1 - i;
		ic = (random & MASK) % (k + 1);
		random >>= 8;

		temp = ckey->t1[k];
		ckey->t1[k] = ckey->t1[ic];
		ckey->t1[ic] = temp;
		if (ckey->t3[k] != 0)
			continue;

		ic = (random & MASK) % k;
		while (ckey->t3[ic] != 0)
			ic = (ic + 1) % k;
		ckey->t3[k] = ic;
		ckey->t3[ic] = k;
	}

	for (i = 0; i < ROTORSZ; i++)
		ckey->t2[ckey->t1[i] & MASK] = i;

	return 0;
}


int shuffle(CRYPT_KEY * ckey)
{
	int i, ic, k, temp;
	unsigned random;
	static sword32 seed = 123;

	for (i = 0; i < ROTORSZ; i++) {
		seed = MUL_ADD(5, seed, ckey->cbuf[i % 13]);
		random = seed % 65521;
		k = ROTORSZ - 1 - i;
		ic = (random & MASK) % (k + 1);
		temp = ckey->deck[k];
		ckey->deck[k] = ckey->deck[ic];
		ckey->deck[ic] = temp;
	}
	return 0;
}

static void _mcrypt_encrypt(void *ctx, void *gtext, int textlen)
{				/* 0 or 1 */
	CRYPT_KEY *ckey = ctx;
	int i, j;
	int secureflg = 0;
	char *text = gtext;

	for (j = 0; j < textlen; j++) {

		i = text[j];
		if (secureflg) {
			ckey->nr1 = ckey->deck[ckey->n1] & MASK;
			ckey->nr2 = ckey->deck[ckey->nr1] & MASK;
		} else {
			ckey->nr1 = ckey->n1;
		}
		i = ckey->
		    t2[(ckey->
			t3[(ckey->t1[(i + ckey->nr1) & MASK] +
			    ckey->nr2) & MASK] - ckey->nr2) & MASK] -
		    ckey->nr1;
		text[j] = i;
		ckey->n1++;
		if (ckey->n1 == ROTORSZ) {
			ckey->n1 = 0;
			ckey->n2++;
			if (ckey->n2 == ROTORSZ)
				ckey->n2 = 0;
			if (secureflg) {
				shuffle(ckey);
			} else {
				ckey->nr2 = ckey->n2;
			}
		}
	}

	return;
}

static void _mcrypt_decrypt(void *ctx, void *gtext, int textlen)
{				/* 0 or 1 */
	CRYPT_KEY *ckey = ctx;
	int i, j;
	int secureflg = 0;
	char *text = gtext;


	for (j = 0; j < textlen; j++) {

		i = text[j];
		if (secureflg) {
			ckey->nr1 = ckey->deck[ckey->n1] & MASK;
			ckey->nr2 = ckey->deck[ckey->nr1] & MASK;
		} else {
			ckey->nr1 = ckey->n1;
		}
		i = ckey->
		    t2[(ckey->
			t3[(ckey->t1[(i + ckey->nr1) & MASK] +
			    ckey->nr2) & MASK] - ckey->nr2) & MASK] -
		    ckey->nr1;
		text[j] = i;
		ckey->n1++;
		if (ckey->n1 == ROTORSZ) {
			ckey->n1 = 0;
			ckey->n2++;
			if (ckey->n2 == ROTORSZ)
				ckey->n2 = 0;
			if (secureflg) {
				shuffle(ckey);
			} else {
				ckey->nr2 = ckey->n2;
			}
		}
	}

	return;
}


static int _mcrypt_get_size(void)
{
	return sizeof(CRYPT_KEY);
}
static int _mcrypt_get_block_size(void)
{
	return 1;
}
static int _mcrypt_get_algo_iv_size(void)
{
	return 0;
}
static int _is_block_algorithm(void)
{
	return 0;
}
static int _mcrypt_get_key_size(void)
{
	return 13;
}
static const int *_mcrypt_get_supported_key_sizes(int *len)
{
	*len = 0;
	return NULL;
}

static const char *_mcrypt_get_algorithms_name(void)
{
return "enigma";
}

#define CIPHER "f3edda7da20f8975884600f014d32c7a08e59d7b"

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

	strcpy(keyword, "enadyotr");

	for (j = 0; j < blocksize; j++) {
		plaintext[j] = j % 256;
	}
	key = malloc(_mcrypt_get_size());
	if (key == NULL) {
		free(keyword);
		return -1;
	}
	memmove(ciphertext, plaintext, blocksize);

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
	free(keyword);
	
	_mcrypt_decrypt(key, (void *) ciphertext, blocksize);
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

const mcrypt_algo_module mcrypt_algo_enigma = {
	.name = "enigma",
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
