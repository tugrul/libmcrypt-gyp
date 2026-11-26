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

typedef struct ncfb_buf {
	byte*   enc_s_register;
	byte* s_register;
	int   s_register_pos;
	int   blocksize;
} nCFB_BUFFER;

/* nCFB MODE */

static int _init_mcrypt(void *abuf, const void *key, int lenofkey,
                        const void *IV, int size)
{
	nCFB_BUFFER *buf = abuf;
    buf->enc_s_register = buf->s_register = NULL;
    buf->s_register_pos = 0;
    
    buf->blocksize = size;

/* For cfb */
	buf->enc_s_register=malloc( size);
    if (buf->enc_s_register==NULL) goto freeall;
    
	buf->s_register=malloc( size);
    if (buf->s_register==NULL) goto freeall;

	if (IV!=NULL) {
		memcpy(buf->enc_s_register, IV, size);
		memcpy(buf->s_register, IV, size);
	} else {
		memset(buf->enc_s_register, 0, size);
		memset(buf->s_register, 0, size);
	}

/* End ncfb */

	return 0;
	freeall:
		free(buf->enc_s_register);
		free(buf->s_register);
		return -1;
}

static int _mcrypt_set_state(void *abuf, const void *iv, int size)
{
	nCFB_BUFFER *buf = abuf;
	const byte *IV = iv;
	buf->s_register_pos = IV[0];
	memcpy(buf->enc_s_register, &IV[1], size-1);
	memcpy(buf->s_register, &IV[1], size-1);

	return 0;
}

static int _mcrypt_get_state(void *abuf, void *iv, int *size)
{
	nCFB_BUFFER *buf = abuf;
	byte *IV = iv;
	if (*size < buf->blocksize + 1) {
		*size = buf->blocksize + 1;
		return -1;
	}
	*size = buf->blocksize + 1;

	IV[0] = buf->s_register_pos;
	memcpy( &IV[1], buf->s_register, buf->blocksize);

	return 0;
}

static int _end_mcrypt(void *abuf) {
	nCFB_BUFFER *buf = abuf;
	free(buf->enc_s_register);
	free(buf->s_register);
	return 0;
}

inline static
void xor_stuff_en( nCFB_BUFFER *buf, void* akey, void (*func)(void*,void*), byte* plain,  int blocksize, int xor_size)
{
	void (*_mcrypt_block_encrypt) (void *, void *);

	_mcrypt_block_encrypt = func;

	if (xor_size == blocksize) {
		if (buf->s_register_pos == 0) {

			memcpy(buf->enc_s_register, buf->s_register, blocksize);

			_mcrypt_block_encrypt(akey, buf->enc_s_register);
			
			memxor( plain, buf->enc_s_register, blocksize);

			memcpy(buf->s_register, plain, blocksize);

		} else {
			int size = blocksize - buf->s_register_pos;

			memxor( plain, &buf->enc_s_register[buf->s_register_pos],
				size); 

			/* these bytes complete the ciphertext block in the
			 * register, which is what gets encrypted next */
			memcpy( &buf->s_register[buf->s_register_pos],
				plain, size);
		
			memcpy(buf->enc_s_register, buf->s_register, blocksize);

			_mcrypt_block_encrypt(akey, buf->enc_s_register);

			memxor( &plain[size], buf->enc_s_register,
				buf->s_register_pos);

			memcpy( buf->s_register,
				&plain[size], buf->s_register_pos);

			/* buf->s_register_pos remains the same */
		}
	} else { /* xor_size != blocksize */
		if (buf->s_register_pos == 0) {
			memcpy(buf->enc_s_register, buf->s_register, blocksize);

			_mcrypt_block_encrypt(akey, buf->enc_s_register);
			
			memxor( plain, buf->enc_s_register, xor_size);

			memcpy(buf->s_register, plain, xor_size);

			buf->s_register_pos = xor_size;
		} else {
			int size = blocksize - buf->s_register_pos;
			int min_size =  size < xor_size ? size: xor_size;

			memxor( plain, &buf->enc_s_register[buf->s_register_pos],
				min_size);

			memcpy( &buf->s_register[buf->s_register_pos], plain, min_size);

			buf->s_register_pos += min_size;

			if (min_size >= xor_size)
				return;

			memcpy(buf->enc_s_register, buf->s_register, blocksize);

			_mcrypt_block_encrypt(akey, buf->enc_s_register);

			memxor( &plain[min_size], buf->enc_s_register,
				xor_size - min_size);

			buf->s_register_pos = xor_size - min_size;

			memcpy(buf->s_register, &plain[min_size], xor_size - min_size);
		}
	
	}
	return;
}

inline static
void xor_stuff_de( nCFB_BUFFER *buf, void* akey, void (*func)(void*,void*), byte* cipher,  int blocksize, int xor_size)
{
	void (*_mcrypt_block_encrypt) (void *, void *);

	_mcrypt_block_encrypt = func;

	if (xor_size == blocksize) {
		if (buf->s_register_pos == 0) {

			memcpy(buf->enc_s_register, buf->s_register, blocksize);

			_mcrypt_block_encrypt(akey, buf->enc_s_register);

			memcpy(buf->s_register, cipher, blocksize);
			
			memxor( cipher, buf->enc_s_register, blocksize);


		} else {
			int size = blocksize - buf->s_register_pos;

			/* the register takes the ciphertext, so copy it
			 * before it is decrypted in place */
			memcpy( &buf->s_register[buf->s_register_pos],
				cipher, size);

			memxor( cipher, &buf->enc_s_register[buf->s_register_pos],
				size); 
		
			memcpy(buf->enc_s_register, buf->s_register, blocksize);

			_mcrypt_block_encrypt(akey, buf->enc_s_register);

			memcpy( buf->s_register,
				&cipher[size], buf->s_register_pos);

			memxor( &cipher[size], buf->enc_s_register,
				buf->s_register_pos);


			/* buf->s_register_pos remains the same */
		}
	} else { /* xor_size != blocksize */
		if (buf->s_register_pos == 0) {
			memcpy(buf->enc_s_register, buf->s_register, blocksize);

			_mcrypt_block_encrypt(akey, buf->enc_s_register);

			memcpy(buf->s_register, cipher, xor_size);
			
			memxor( cipher, buf->enc_s_register, xor_size);


			buf->s_register_pos = xor_size;
		} else {
			int size = blocksize - buf->s_register_pos;
			int min_size =  size < xor_size ? size: xor_size;

			memcpy( &buf->s_register[buf->s_register_pos], cipher, min_size);

			memxor( cipher, &buf->enc_s_register[buf->s_register_pos],
				min_size);

			buf->s_register_pos += min_size;

			if (min_size >= xor_size)
				return;

			memcpy(buf->enc_s_register, buf->s_register, blocksize);

			_mcrypt_block_encrypt(akey, buf->enc_s_register);

			memcpy(buf->s_register, &cipher[min_size], xor_size - min_size);

			memxor( &cipher[min_size], buf->enc_s_register,
				xor_size - min_size);

			buf->s_register_pos = xor_size - min_size;

		}
	
	}
	return;
}


static int _mcrypt(void *abuf, void *plaintext, int len, int blocksize,
                   void *akey, const mcrypt_algo_module *algo)
{				/* plaintext is n*blocksize bytes (nbit cfb) */
	nCFB_BUFFER *buf = abuf;
	byte* plain;
	int j=0;
	int modlen;

	plain = plaintext;
	for (j = 0; j < len / blocksize; j++) {
		xor_stuff_en( buf, akey, algo->encrypt, plain, blocksize, blocksize); 
		
		plain += blocksize;

	}
	modlen = len % blocksize;
	if (modlen > 0) {
		xor_stuff_en( buf, akey, algo->encrypt, plain, blocksize, modlen); 
	}
	
	return 0;
}


static int _mdecrypt(void *abuf, void *plaintext, int len, int blocksize,
                     void *akey, const mcrypt_algo_module *algo)
{				/* plaintext is n*blocksize bytes (nbit cfb) */
	nCFB_BUFFER *buf = abuf;
	byte* plain;
	int j=0;
	int modlen;

	plain = plaintext;
	for (j = 0; j < len / blocksize; j++) {
		xor_stuff_de( buf, akey, algo->encrypt, plain, blocksize, blocksize); 
		
		plain += blocksize;

	}
	modlen = len % blocksize;
	if (modlen > 0) {
		xor_stuff_de( buf, akey, algo->encrypt, plain, blocksize, modlen); 
	}
	
	return 0;
}


static int _has_iv(void) { return 1; }
static int _is_block_mode(void) { return 0; }
static int _is_block_algorithm_mode(void) { return 1; }
static const char *_mcrypt_get_modes_name(void) { return "nCFB";}
static int _mcrypt_mode_get_size(void) {return sizeof(nCFB_BUFFER);}


static word32 _mcrypt_mode_version(void) {
	return 20020307;
}

const mcrypt_mode_module mcrypt_mode_ncfb = {
	.name = "ncfb",
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
