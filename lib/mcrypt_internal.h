#ifndef LIBDEFS_H
#define LIBDEFS_H
#include <libdefs.h>
#endif

/* Local Defines */

typedef struct {
	char* name;
	void* address;
} mcrypt_preloaded;

typedef struct {
	char* algorithm_handle;
	char* mode_handle;

	/* Holds the algorithm's internal key */
	byte *akey;

	byte *abuf; /* holds the mode's internal buffers */

	/* holds the key */
	byte *keyword_given;

/* These were included to speed up encryption/decryption proccess, so
 * there is not need for resolving symbols every time.
 */
	void* m_encrypt;
	void* m_decrypt;
	void* a_encrypt;
	void* a_decrypt;
	void* a_block_size;
} CRYPT_STREAM;

typedef CRYPT_STREAM* MCRYPT;

#define MCRYPT_FAILED 0x0

WIN32DLL_DEFINE int mcrypt_module_close(MCRYPT td);

/* frontends */

WIN32DLL_DEFINE int end_mcrypt( MCRYPT td, void *buf);
WIN32DLL_DEFINE int mcrypt_enc_get_size(MCRYPT td);
WIN32DLL_DEFINE int mcrypt_mode_get_size(MCRYPT td);
WIN32DLL_DEFINE int mcrypt_set_key(MCRYPT td, void *a, const void *, int c, const void *, int e);
WIN32DLL_DEFINE int mcrypt_enc_get_block_size(MCRYPT td);
WIN32DLL_DEFINE int __mcrypt_get_block_size(MCRYPT td);
WIN32DLL_DEFINE int mcrypt_enc_get_algo_iv_size(MCRYPT td);
WIN32DLL_DEFINE int mcrypt_enc_get_iv_size(MCRYPT td);
WIN32DLL_DEFINE int mcrypt_enc_get_key_size(MCRYPT td);
WIN32DLL_DEFINE int* mcrypt_enc_get_supported_key_sizes(MCRYPT td, int* out_size);
WIN32DLL_DEFINE int mcrypt_enc_is_block_algorithm(MCRYPT td);
WIN32DLL_DEFINE char *mcrypt_enc_get_algorithms_name(MCRYPT td);
WIN32DLL_DEFINE int init_mcrypt(MCRYPT td, void*buf, const void *, int, const void *);
WIN32DLL_DEFINE int mcrypt(MCRYPT td, void* buf, void *a, int b);
WIN32DLL_DEFINE int mdecrypt(MCRYPT td, void* buf, void *a, int b);
WIN32DLL_DEFINE char *mcrypt_enc_get_modes_name(MCRYPT td);
WIN32DLL_DEFINE int mcrypt_enc_is_block_mode(MCRYPT td);
WIN32DLL_DEFINE int mcrypt_enc_mode_has_iv(MCRYPT td);
WIN32DLL_DEFINE int mcrypt_enc_is_block_algorithm_mode(MCRYPT td);
WIN32DLL_DEFINE int mcrypt_module_algorithm_version(const char *algorithm);
WIN32DLL_DEFINE int mcrypt_module_mode_version(const char *mode);
WIN32DLL_DEFINE int mcrypt_get_size(MCRYPT td);


#define MCRYPT_UNKNOWN_ERROR -1
#define MCRYPT_ALGORITHM_MODE_INCOMPATIBILITY -2
#define MCRYPT_KEY_LEN_ERROR -3
#define MCRYPT_MEMORY_ALLOCATION_ERROR -4
#define MCRYPT_UNKNOWN_MODE -5
#define MCRYPT_UNKNOWN_ALGORITHM -6

void* mcrypt_module_get_sym(const char*, const char*);
int _mcrypt_search_symlist_lib(const char* name);
