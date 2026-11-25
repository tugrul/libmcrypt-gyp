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

typedef struct cbc_buf {
	word32 *previous_ciphertext;
	word32 *previous_cipher;
	int blocksize;
} CBC_BUFFER;

/* CBC MODE */


static int _init_mcrypt(void *abuf, const void *key, int lenofkey,
                        const void *IV, int size)
{
	CBC_BUFFER *buf = abuf;
/* For cbc */
	buf->previous_ciphertext =
	buf->previous_cipher = NULL;

	buf->blocksize = size;
		
	buf->previous_ciphertext = malloc( size);
	buf->previous_cipher = malloc( size);
	
	if (buf->previous_ciphertext==NULL ||
		buf->previous_cipher==NULL) goto freeall;
	
	if (IV!=NULL) {
		memcpy(buf->previous_ciphertext, IV, size);
	} else {
	        memset(buf->previous_ciphertext, 0, size);
	}

	return 0;

	freeall:
		free(buf->previous_ciphertext);
		free(buf->previous_cipher);
		return -1;
}

static int _mcrypt_set_state(void *abuf, const void *IV, int size)
{
	CBC_BUFFER *buf = abuf;
/* For cbc */

	memcpy(buf->previous_ciphertext, IV, size);
	memcpy(buf->previous_cipher, IV, size);
 
	return 0;
}

static int _mcrypt_get_state(void *abuf, void *IV, int *size)
{
	CBC_BUFFER *buf = abuf;
	if (*size < buf->blocksize) {
		*size = buf->blocksize;
		return -1;
	}
	*size = buf->blocksize;

	memcpy( IV, buf->previous_ciphertext, buf->blocksize);

	return 0;
}


static int _end_mcrypt(void *abuf) {
	CBC_BUFFER *buf = abuf;
	free(buf->previous_ciphertext);
	free(buf->previous_cipher);
	return 0;
}

static int _mcrypt(void *abuf, void *plaintext, int len, int blocksize,
                   void *akey, const mcrypt_algo_module *algo)
{
	CBC_BUFFER *buf = abuf;
	word32 *fplain = plaintext;
	word32 *plain;
	unsigned int i;
    int j; 
	void (*_mcrypt_block_encrypt) (void *, void *);

	_mcrypt_block_encrypt = algo->encrypt;
	
	for (j = 0; j < len / blocksize; j++) {

		plain = &fplain[j * blocksize / sizeof(word32)];

		for (i = 0; i < blocksize / sizeof(word32); i++) {
			plain[i] ^= buf->previous_ciphertext[i];
		}

		_mcrypt_block_encrypt(akey, plain);

		/* Copy the ciphertext to prev_ciphertext */
		memcpy(buf->previous_ciphertext, plain, blocksize);
	}
	if (j==0 && len!=0) return -1;
	return 0;
}



static int _mdecrypt(void *abuf, void *ciphertext, int len, int blocksize,
                     void *akey, const mcrypt_algo_module *algo)
{
	CBC_BUFFER *buf = abuf;
	word32 *cipher;
	word32 *fcipher = ciphertext;
	unsigned int i;
    int j; 
	void (*_mcrypt_block_decrypt) (void *, void *);

	_mcrypt_block_decrypt = algo->decrypt;


	for (j = 0; j < len / blocksize; j++) {

		cipher = &fcipher[j * blocksize / sizeof(word32)];
		memcpy(buf->previous_cipher, cipher, blocksize);

		_mcrypt_block_decrypt(akey, cipher);
		for (i = 0; i < blocksize / sizeof(word32); i++) {
			cipher[i] ^= buf->previous_ciphertext[i];
		}

		/* Copy the ciphertext to prev_cipher */
		memcpy(buf->previous_ciphertext, buf->previous_cipher, blocksize);

	}
	if (j==0 && len!=0) return -1;
	return 0;
}

static int _has_iv(void) { return 1; }
static int _is_block_mode(void) { return 1; }
static int _is_block_algorithm_mode(void) { return 1; }
static const char *_mcrypt_get_modes_name(void) { return "CBC";}
static int _mcrypt_mode_get_size(void) {return sizeof(CBC_BUFFER);}

static word32 _mcrypt_mode_version(void) {
	return 20010801;
}

const mcrypt_mode_module mcrypt_mode_cbc = {
	.name = "cbc",
	.init = _init_mcrypt,
	.set_state = _mcrypt_set_state,
	.get_state = _mcrypt_get_state,
	.end = _end_mcrypt,
	.encrypt = _mcrypt,
	.decrypt = _mdecrypt,
	.has_iv = _has_iv,
	.is_block_mode = _is_block_mode,
	.is_block_algo_mode = _is_block_algorithm_mode,
	.get_name = _mcrypt_get_modes_name,
	.get_size = _mcrypt_mode_get_size,
	.get_version = _mcrypt_mode_version
};
