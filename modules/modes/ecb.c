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

/* EBC MODE */

static int _init_mcrypt(void *ign, const void *key, int lenofkey,
                        const void *IV, int size)
{
	return 0;

}

static int _mcrypt_set_state(void *buf, const void *IV, int size) { return -1; }
static int _mcrypt_get_state(void *buf, void *IV, int *size) { return -1; }

static int _end_mcrypt(void *buf) {return 0;}

static int _mcrypt(void *ign, void *plaintext, int len, int blocksize,
                   void *akey, const mcrypt_algo_module *algo)
{
	int j;
	char *plain = plaintext;
	void (*_mcrypt_block_encrypt) (void *, void *);

	_mcrypt_block_encrypt = algo->encrypt;
	
	for (j = 0; j < len / blocksize; j++) {
		_mcrypt_block_encrypt(akey, &plain[j * blocksize]);
	}
	if (j==0 && len!=0) return -1; /* no blocks were encrypted */
	return 0;
}



static int _mdecrypt(void *ign, void *ciphertext, int len, int blocksize,
                     void *akey, const mcrypt_algo_module *algo)
{
	int j;
	char *cipher = ciphertext;
	void (*_mcrypt_block_decrypt) (void *, void *);

	_mcrypt_block_decrypt = algo->decrypt;
	
	for (j = 0; j < len / blocksize; j++) {
		_mcrypt_block_decrypt(akey, &cipher[j * blocksize]);
	}
	if (j==0 && len!=0) return -1; /* no blocks were encrypted */
	return 0;
}

static int _has_iv(void) { return 0; }
static int _is_block_mode(void) { return 1; }
static int _is_block_algorithm_mode(void) { return 1; }
static const char *_mcrypt_get_modes_name(void) { return "ECB";}
static int _mcrypt_mode_get_size(void) {return 0;}

static word32 _mcrypt_mode_version(void) {
	return 20010801;
}

const mcrypt_mode_module mcrypt_mode_ecb = {
	.name = "ecb",
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
