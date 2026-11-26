/* This is an independent implementation of the encryption algorithm:   */
/*                                                                      */
/*         LOKI97 by Brown and Pieprzyk                                 */
/*                                                                      */
/* which is a candidate algorithm in the Advanced Encryption Standard   */
/* programme of the US National Institute of Standards and Technology.  */
/*                                                                      */
/* Copyright in this implementation is held by Dr B R Gladman but I     */
/* hereby give permission for its free direct or derivative use subject */
/* to acknowledgment of its origin and compliance with any conditions   */
/* that the originators of the algorithm place on its exploitation.     */
/*                                                                      */
/* Dr Brian Gladman (gladman@seven77.demon.co.uk) 14th January 1999     */

/* $Id: loki97.c,v 1.14 2003/01/19 17:48:27 nmav Exp $ */

/* modified in order to use the libmcrypt API by Nikos Mavroyanopoulos 
 * All modifications are placed under the license of libmcrypt.
 */

/* Timing data for LOKI97 (loki.c)

Core timing without I/O endian conversion:

128 bit key:
Key Setup:    7430 cycles
Encrypt:      2134 cycles =    12.0 mbits/sec
Decrypt:      2192 cycles =    11.7 mbits/sec
Mean:         2163 cycles =    11.8 mbits/sec

192 bit key:
Key Setup:    7303 cycles
Encrypt:      2138 cycles =    12.0 mbits/sec
Decrypt:      2189 cycles =    11.7 mbits/sec
Mean:         2164 cycles =    11.8 mbits/sec

256 bit key:
Key Setup:    7166 cycles
Encrypt:      2131 cycles =    12.0 mbits/sec
Decrypt:      2184 cycles =    11.7 mbits/sec
Mean:         2158 cycles =    11.9 mbits/sec

Full timing with I/O endian conversion:

128 bit key:
Key Setup:    7582 cycles
Encrypt:      2174 cycles =    11.8 mbits/sec
Decrypt:      2235 cycles =    11.5 mbits/sec
Mean:         2205 cycles =    11.6 mbits/sec

192 bit key:
Key Setup:    7477 cycles
Encrypt:      2167 cycles =    11.8 mbits/sec
Decrypt:      2223 cycles =    11.5 mbits/sec
Mean:         2195 cycles =    11.7 mbits/sec

256 bit key:
Key Setup:    7365 cycles
Encrypt:      2177 cycles =    11.8 mbits/sec
Decrypt:      2194 cycles =    11.7 mbits/sec
Mean:         2186 cycles =    11.7 mbits/sec

*/


#include <libdefs.h>

#include <mcrypt_modules.h>

#define byte(x,n)   ((byte)((x) >> (8 * n)))

#define S1_SIZE     13
#define S1_LEN      (1 << S1_SIZE)
#define S1_MASK     (S1_LEN - 1)
#define S1_HMASK    (S1_MASK & ~0xff)
#define S1_POLY     0x2911

#define S2_SIZE     11
#define S2_LEN      (1 << S2_SIZE)
#define S2_MASK     (S2_LEN - 1)
#define S2_HMASK    (S2_MASK & ~0xff)
#define S2_POLY     0x0aa7

static const word32 delta[2] = { 0x7f4a7c15, 0x9e3779b9 };

/* sb1 (the GF(2^13) S box), sb2 (the GF(2^11) S box) and prm */
#include "loki97-tables.h"

/* word32  l_key[96]; */

#define add_eq(x,y)     (x)[1] += (y)[1] + (((x)[0] += (y)[0]) < (y)[0] ? 1 : 0)
#define sub_eq(x,y)     xs = (x)[0]; (x)[1] -= (y)[1] + (((x)[0] -= (y)[0]) > xs ? 1 : 0)

void f_fun(word32 res[2], const word32 in[2], const word32 key[2])
{
	word32 i, tt[2], pp[2];

/*    tt[0] = in[0] & ~key[0] | in[1] & key[0];
 *    tt[1] = in[1] & ~key[0] | in[0] & key[0]; 
 */
	tt[0] = (in[0] & ~key[0]) | (in[1] & key[0]);
	tt[1] = (in[1] & ~key[0]) | (in[0] & key[0]);

	i = sb1[((tt[1] >> 24) | (tt[0] << 8)) & S1_MASK];
	pp[0] = prm[i][0] >> 7;
	pp[1] = prm[i][1] >> 7;
	i = sb2[(tt[1] >> 16) & S2_MASK];
	pp[0] |= prm[i][0] >> 6;
	pp[1] |= prm[i][1] >> 6;
	i = sb1[(tt[1] >> 8) & S1_MASK];
	pp[0] |= prm[i][0] >> 5;
	pp[1] |= prm[i][1] >> 5;
	i = sb2[tt[1] & S2_MASK];
	pp[0] |= prm[i][0] >> 4;
	pp[1] |= prm[i][1] >> 4;
	i = sb2[((tt[0] >> 24) | (tt[1] << 8)) & S2_MASK];
	pp[0] |= prm[i][0] >> 3;
	pp[1] |= prm[i][1] >> 3;
	i = sb1[(tt[0] >> 16) & S1_MASK];
	pp[0] |= prm[i][0] >> 2;
	pp[1] |= prm[i][1] >> 2;
	i = sb2[(tt[0] >> 8) & S2_MASK];
	pp[0] |= prm[i][0] >> 1;
	pp[1] |= prm[i][1] >> 1;
	i = sb1[tt[0] & S1_MASK];
	pp[0] |= prm[i][0];
	pp[1] |= prm[i][1];

/*
    res[0] ^=  sb1[byte(pp[0], 0) | (key[1] <<  8) & S1_HMASK]
            | (sb1[byte(pp[0], 1) | (key[1] <<  3) & S1_HMASK] << 8)
            | (sb2[byte(pp[0], 2) | (key[1] >>  2) & S2_HMASK] << 16)
            | (sb2[byte(pp[0], 3) | (key[1] >>  5) & S2_HMASK] << 24);
    res[1] ^=  sb1[byte(pp[1], 0) | (key[1] >>  8) & S1_HMASK]
            | (sb1[byte(pp[1], 1) | (key[1] >> 13) & S1_HMASK] << 8)
            | (sb2[byte(pp[1], 2) | (key[1] >> 18) & S2_HMASK] << 16)
            | (sb2[byte(pp[1], 3) | (key[1] >> 21) & S2_HMASK] << 24);
*/
	res[0] ^= sb1[byte(pp[0], 0) | ((key[1] << 8) & S1_HMASK)]
	    | ((sb1[byte(pp[0], 1) | ((key[1] << 3) & S1_HMASK)] << 8))
	    | ((sb2[byte(pp[0], 2) | ((key[1] >> 2) & S2_HMASK)] << 16))
	    | (((word32) sb2[byte(pp[0], 3) | ((key[1] >> 5) & S2_HMASK)] << 24));
	res[1] ^= sb1[byte(pp[1], 0) | ((key[1] >> 8) & S1_HMASK)]
	    | ((sb1[byte(pp[1], 1) | ((key[1] >> 13) & S1_HMASK)] << 8))
	    | ((sb2[byte(pp[1], 2) | ((key[1] >> 18) & S2_HMASK)] << 16))
	    | (((word32) sb2[byte(pp[1], 3) | ((key[1] >> 21) & S2_HMASK)] << 24));

}

/* 256 bit version only */
static int _mcrypt_set_key(void *ctx, const void *key, int len)
{
	word32 *l_key = ctx;
	const word32 *in_key = key;
	word32 i, k1[2], k2[2], k3[2], k4[2], del[2], tt[2], sk[2];

#ifdef WORDS_BIGENDIAN
	k4[0] = byteswap32(in_key[1]);
	k4[1] = byteswap32(in_key[0]);
	k3[0] = byteswap32(in_key[3]);
	k3[1] = byteswap32(in_key[2]);
#else
	k4[0] = (in_key[1]);
	k4[1] = (in_key[0]);
	k3[0] = (in_key[3]);
	k3[1] = (in_key[2]);
#endif


#ifdef WORDS_BIGENDIAN
	k2[0] = byteswap32(in_key[5]);
	k2[1] = byteswap32(in_key[4]);
	k1[0] = byteswap32(in_key[7]);
	k1[1] = byteswap32(in_key[6]);
#else
	k2[0] = (in_key[5]);
	k2[1] = (in_key[4]);
	k1[0] = (in_key[7]);
	k1[1] = (in_key[6]);
#endif

	del[0] = delta[0];
	del[1] = delta[1];

	for (i = 0; i < 48; ++i) {
		tt[0] = k1[0];
		tt[1] = k1[1];
		add_eq(tt, k3);
		add_eq(tt, del);
		add_eq(del, delta);
		sk[0] = k4[0];
		sk[1] = k4[1];
		k4[0] = k3[0];
		k4[1] = k3[1];
		k3[0] = k2[0];
		k3[1] = k2[1];
		k2[0] = k1[0];
		k2[1] = k1[1];
		k1[0] = sk[0];
		k1[1] = sk[1];
		f_fun(k1, tt, k3);
		l_key[i + i] = k1[0];
		l_key[i + i + 1] = k1[1];
	}

	return 0;
}

#define r_fun(l,r,k)        \
    add_eq((l),(k));        \
    f_fun((r),(l),(k) + 2); \
    add_eq((l), (k) + 4)

static void _mcrypt_encrypt(void *ctx, void *block)
{
	word32 *l_key = ctx;
	word32 *_blk = block;
	word32 blk[4];

#ifdef WORDS_BIGENDIAN
	blk[3] = byteswap32(_blk[0]);
	blk[2] = byteswap32(_blk[1]);
	blk[1] = byteswap32(_blk[2]);
	blk[0] = byteswap32(_blk[3]);
#else
	blk[3] = (_blk[0]);
	blk[2] = (_blk[1]);
	blk[1] = (_blk[2]);
	blk[0] = (_blk[3]);
#endif

	r_fun(blk, blk + 2, l_key + 0);
	r_fun(blk + 2, blk, l_key + 6);
	r_fun(blk, blk + 2, l_key + 12);
	r_fun(blk + 2, blk, l_key + 18);
	r_fun(blk, blk + 2, l_key + 24);
	r_fun(blk + 2, blk, l_key + 30);
	r_fun(blk, blk + 2, l_key + 36);
	r_fun(blk + 2, blk, l_key + 42);
	r_fun(blk, blk + 2, l_key + 48);
	r_fun(blk + 2, blk, l_key + 54);
	r_fun(blk, blk + 2, l_key + 60);
	r_fun(blk + 2, blk, l_key + 66);
	r_fun(blk, blk + 2, l_key + 72);
	r_fun(blk + 2, blk, l_key + 78);
	r_fun(blk, blk + 2, l_key + 84);
	r_fun(blk + 2, blk, l_key + 90);

#ifdef WORDS_BIGENDIAN
	_blk[3] = byteswap32(blk[2]);
	_blk[2] = byteswap32(blk[3]);
	_blk[1] = byteswap32(blk[0]);
	_blk[0] = byteswap32(blk[1]);
#else
	_blk[3] = (blk[2]);
	_blk[2] = (blk[3]);
	_blk[1] = (blk[0]);
	_blk[0] = (blk[1]);
#endif
}

#define ir_fun(l,r,k)       \
    sub_eq((l),(k) + 4);    \
    f_fun((r),(l),(k) + 2); \
    sub_eq((l),(k))

static void _mcrypt_decrypt(void *ctx, void *block)
{
	word32 *l_key = ctx;
	word32 *_blk = block;
	word32 xs, blk[4];

#ifdef WORDS_BIGENDIAN
	blk[3] = byteswap32(_blk[0]);
	blk[2] = byteswap32(_blk[1]);
	blk[1] = byteswap32(_blk[2]);
	blk[0] = byteswap32(_blk[3]);
#else
	blk[3] = (_blk[0]);
	blk[2] = (_blk[1]);
	blk[1] = (_blk[2]);
	blk[0] = (_blk[3]);
#endif

	ir_fun(blk, blk + 2, l_key + 90);
	ir_fun(blk + 2, blk, l_key + 84);
	ir_fun(blk, blk + 2, l_key + 78);
	ir_fun(blk + 2, blk, l_key + 72);
	ir_fun(blk, blk + 2, l_key + 66);
	ir_fun(blk + 2, blk, l_key + 60);
	ir_fun(blk, blk + 2, l_key + 54);
	ir_fun(blk + 2, blk, l_key + 48);
	ir_fun(blk, blk + 2, l_key + 42);
	ir_fun(blk + 2, blk, l_key + 36);
	ir_fun(blk, blk + 2, l_key + 30);
	ir_fun(blk + 2, blk, l_key + 24);
	ir_fun(blk, blk + 2, l_key + 18);
	ir_fun(blk + 2, blk, l_key + 12);
	ir_fun(blk, blk + 2, l_key + 6);
	ir_fun(blk + 2, blk, l_key);

#ifdef WORDS_BIGENDIAN
	_blk[3] = byteswap32(blk[2]);
	_blk[2] = byteswap32(blk[3]);
	_blk[1] = byteswap32(blk[0]);
	_blk[0] = byteswap32(blk[1]);
#else
	_blk[3] = (blk[2]);
	_blk[2] = (blk[3]);
	_blk[1] = (blk[0]);
	_blk[0] = (blk[1]);
#endif
}


static int _mcrypt_get_size(void)
{
	return 96 * sizeof(word32);
}
static int _mcrypt_get_block_size(void)
{
	return 16;
}
static int _is_block_algorithm(void)
{
	return 1;
}
static int _mcrypt_get_key_size(void)
{
	return 32;
}

static const int key_sizes[] = { 16, 24, 32 };
static const int *_mcrypt_get_supported_key_sizes(int *len)
{
	*len = sizeof(key_sizes)/sizeof(int);
	return key_sizes;

}

static const char *_mcrypt_get_algorithms_name(void)
{
return "LOKI97";
}

#define CIPHER "8cb28c958024bae27a94c698f96f12a9"

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
	if (key == NULL) {
		free(keyword);
		return -1;
	}

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

const mcrypt_algo_module mcrypt_algo_loki97 = {
	.name = "loki97",
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
