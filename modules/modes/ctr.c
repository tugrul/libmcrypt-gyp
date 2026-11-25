/*
 * Copyright (C) 2002 Nikos Mavroyanopoulos
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

typedef struct ctr_buf {
	byte* enc_counter;
	byte* c_counter;
	int c_counter_pos;
	int blocksize;
} CTR_BUFFER;

/* CTR MODE */

/* This function will add one to the given number (as a byte string).
 * has been reached.
 */
static void increase_counter( byte *x, int x_size) {
register int i, y=0;

	for (i=x_size-1;i>=0;i--) {
		y = 0;
		if ( x[i] == 0xff) {
			x[i] = 0;
			y = 1;
		} else x[i]++;

		if (y==0) break;
	}

	return;
}


/* size holds the size of the IV (counter in this mode).
 * This is the block size.
 */
static int _init_mcrypt(void *abuf, const void *key, int lenofkey,
                        const void *IV, int size)
{
	CTR_BUFFER *buf = abuf;
    buf->c_counter = buf->enc_counter = NULL;
    
/* For ctr */
    buf->c_counter_pos = 0;
    buf->blocksize = size;

	buf->c_counter=calloc( 1, size);
    if (buf->c_counter==NULL) goto freeall;

	buf->enc_counter=calloc( 1, size);
    if (buf->enc_counter==NULL) goto freeall;
    
    if (IV!=NULL) {
	memcpy(buf->enc_counter, IV, size);
	memcpy(buf->c_counter, IV, size);
    }

/* End ctr */

	return 0;
	freeall:
		free(buf->c_counter);
		free(buf->enc_counter);
		return -1;
}

static int _mcrypt_set_state(void *abuf, const void *iv, int size)
{
	CTR_BUFFER *buf = abuf;
	const byte *IV = iv;
	buf->c_counter_pos = IV[0];
	memcpy(buf->c_counter, &IV[1], size-1);
	memcpy(buf->enc_counter, &IV[1], size-1);

	return 0;
}

static int _mcrypt_get_state(void *abuf, void *iv, int *size)
{
	CTR_BUFFER *buf = abuf;
	byte *IV = iv;
	if (*size < buf->blocksize + 1) {
		*size = buf->blocksize + 1;
		return -1;
	}
	*size = buf->blocksize + 1;

	IV[0] = buf->c_counter_pos;
	memcpy( &IV[1], buf->c_counter, buf->blocksize);

	return 0;
}


static int _end_mcrypt(void *abuf) {
	CTR_BUFFER *buf = abuf;
	free(buf->c_counter);
	free(buf->enc_counter);
	return 0;
}

inline static
void xor_stuff( CTR_BUFFER *buf, void* akey, void (*func)(void*,void*), byte* plain,  int blocksize, int xor_size) 
{
	void (*_mcrypt_block_encrypt) (void *, void *);

	_mcrypt_block_encrypt = func;

	if (xor_size == blocksize) {
		if (buf->c_counter_pos == 0) {

			memcpy( buf->enc_counter, buf->c_counter, blocksize);
			_mcrypt_block_encrypt(akey, buf->enc_counter);

			memxor( plain, buf->enc_counter, blocksize);

			increase_counter( buf->c_counter, blocksize);


		} else {
			int size = blocksize - buf->c_counter_pos;

			memxor( plain, &buf->enc_counter[buf->c_counter_pos],
				size);
		
			increase_counter( buf->c_counter, blocksize);

			memcpy( buf->enc_counter, buf->c_counter, blocksize);
			_mcrypt_block_encrypt(akey, buf->enc_counter);

			memxor( &plain[size], buf->enc_counter,
				buf->c_counter_pos);

			/* buf->c_counter_pos remains the same */

		}
	} else { /* xor_size != blocksize */
		if (buf->c_counter_pos == 0) {
			memcpy( buf->enc_counter, buf->c_counter, blocksize);
			_mcrypt_block_encrypt(akey, buf->enc_counter);

			memxor( plain, buf->enc_counter, xor_size);
			buf->c_counter_pos = xor_size;
		} else {
			int size = blocksize - buf->c_counter_pos;
			int min_size =  size < xor_size ? size: xor_size;

			memxor( plain, &buf->enc_counter[buf->c_counter_pos],
				min_size); 

			buf->c_counter_pos += min_size;

			if (min_size >= xor_size)
				return;

			increase_counter( buf->c_counter, blocksize);

			memcpy( buf->enc_counter, buf->c_counter, blocksize);
			_mcrypt_block_encrypt(akey, buf->enc_counter);

			memxor( &plain[min_size], buf->enc_counter,
				xor_size - min_size);

			buf->c_counter_pos = xor_size - min_size;

		}
	
	}
	return;
}

static int _mcrypt(void *abuf, void *plaintext, int len, int blocksize,
                   void *akey, const mcrypt_algo_module *algo)
{				/* plaintext can be any size */
	CTR_BUFFER *buf = abuf;
	byte *plain;
	int j=0;
	int modlen;

	plain = plaintext;
	for (j = 0; j < len / blocksize; j++) {

		xor_stuff( buf, akey, algo->encrypt, plain, blocksize, blocksize);

		plain += blocksize;

/* Put the new register */

	}
	modlen = len % blocksize;
	if (modlen > 0) {
		/* This is only usefull if encrypting the
		 * final block. Otherwise you'll not be
		 * able to decrypt it.
		 */

		xor_stuff( buf, akey, algo->encrypt, plain, blocksize, modlen);

	}
	
	return 0;
}


static int _mdecrypt(void *abuf, void *plaintext, int len, int blocksize,
                     void *akey, const mcrypt_algo_module *algo)
{				/* plaintext can be any size */
	CTR_BUFFER *buf = abuf;
	return _mcrypt( buf, plaintext, len, blocksize, akey, algo);
}

static int _has_iv(void) { return 1; }
static int _is_block_mode(void) { return 0; }
static int _is_block_algorithm_mode(void) { return 1; }
static const char *_mcrypt_get_modes_name(void) { return "CTR";}
static int _mcrypt_mode_get_size(void) {return sizeof(CTR_BUFFER);}


static word32 _mcrypt_mode_version(void) {
	return 20020307;
}

const mcrypt_mode_module mcrypt_mode_ctr = {
	.name = "ctr",
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
