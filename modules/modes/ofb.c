/*
 * Copyright (C) 1998,1999,2000,2001,2002 Nikos Mavroyanopoulos
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

typedef struct ofb_buf {
	byte* s_register;
	byte* enc_s_register;
	int blocksize;
} OFB_BUFFER;


/* OFB MODE */

static int _init_mcrypt(void *abuf, const void *key, int lenofkey,
                        const void *IV, int size)
{
	OFB_BUFFER *buf = abuf;

    buf->s_register = buf->enc_s_register = NULL;

    buf->blocksize = size;
    
    /* For ofb */
	buf->s_register=malloc( size);
    if (buf->s_register==NULL) goto freeall;

	buf->enc_s_register=malloc( size);
    if (buf->enc_s_register==NULL) goto freeall;

	if (IV!=NULL) {
		memcpy(buf->s_register, IV, size);
	} else {
		memset(buf->s_register, 0, size);
	}
/* End ofb */

	return 0;

	freeall:
		free(buf->s_register);
		free(buf->enc_s_register);
		return -1;
}

static int _mcrypt_get_state(void *abuf, void *iv, int *size)
{
	OFB_BUFFER *buf = abuf;
	byte *IV = iv;
	if (*size < buf->blocksize) {
		*size = buf->blocksize;
		return -1;
	}
	*size = buf->blocksize;

	memcpy( IV, buf->s_register, buf->blocksize);

	return 0;
}

static int _mcrypt_set_state(void *abuf, const void *IV, int size)
{
	OFB_BUFFER *buf = abuf;
	memcpy(buf->enc_s_register, IV, size);
	memcpy(buf->s_register, IV, size);

	return 0;
}


static int _end_mcrypt(void *abuf) {
	OFB_BUFFER *buf = abuf;
	free(buf->s_register);
	free(buf->enc_s_register);
	return 0;
}


static int _mcrypt(void *abuf, void *plaintext, int len, int blocksize,
                   void *akey, const mcrypt_algo_module *algo)
{				/* plaintext is 1 byte (8bit ofb) */
	OFB_BUFFER *buf = abuf;
	char *plain = plaintext;
	int i, j;
	void (*_mcrypt_block_encrypt) (void *, void *);

	_mcrypt_block_encrypt = algo->encrypt;

	for (j = 0; j < len; j++) {

		memcpy(buf->enc_s_register, buf->s_register, blocksize);

		_mcrypt_block_encrypt(akey, buf->enc_s_register);

		plain[j] ^= buf->enc_s_register[0];

/* Shift the register */
		for (i = 0; i < (blocksize - 1); i++)
			buf->s_register[i] = buf->s_register[i + 1];

		buf->s_register[blocksize - 1] = buf->enc_s_register[0];
	}

	return 0;

}


static int _mdecrypt(void *abuf, void *plaintext, int len, int blocksize,
                     void *akey, const mcrypt_algo_module *algo)
{				/* plaintext is 1 byte (8bit ofb) */
	OFB_BUFFER *buf = abuf;
	char *plain = plaintext;
	int i, j;
	void (*_mcrypt_block_encrypt) (void *, void *);

	_mcrypt_block_encrypt = algo->encrypt;

	for (j = 0; j < len; j++) {

		memcpy(buf->enc_s_register, buf->s_register, blocksize);

		_mcrypt_block_encrypt(akey, buf->enc_s_register);

/* Shift the register */
		for (i = 0; i < (blocksize - 1); i++)
			buf->s_register[i] = buf->s_register[i + 1];

		buf->s_register[blocksize - 1] = buf->enc_s_register[0];

		plain[j] ^= buf->enc_s_register[0];

	}

	return 0;
}

static int _is_block_mode(void) { return 0; }
static int _has_iv(void) { return 1; }
static int _is_block_algorithm_mode(void) { return 1; }
static const char *_mcrypt_get_modes_name(void) { return "OFB"; }
static int _mcrypt_mode_get_size(void) {return sizeof(OFB_BUFFER);}

static word32 _mcrypt_mode_version(void) {
	return 20010310;
}

const mcrypt_mode_module mcrypt_mode_ofb = {
	.name = "ofb",
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
