/*
 * The module interface.
 *
 * Every algorithm and every mode is one source file that keeps its entry
 * points static and exports a single descriptor, a constant structure of
 * function pointers:
 *
 *     const mcrypt_algo_module mcrypt_algo_rijndael_128 = {
 *         .name = "rijndael-128",
 *         .set_key = _mcrypt_set_key,
 *         ...
 *     };
 *
 * lib/mcrypt_registry.c lists the descriptors that mcrypt_module_open()
 * can find by name. Adding a module means writing the file, declaring its
 * descriptor at the end of this header and adding it to that list.
 *
 * The function pointer types below are the real types of the functions
 * they point to, so a module whose signature does not match fails to
 * compile instead of being called through an incompatible pointer.
 *
 * This header needs word32: include it after libdefs.h.
 */

#ifndef LIBMCRYPT_REGISTRY_H
#define LIBMCRYPT_REGISTRY_H

typedef struct mcrypt_algo_module {
	/* The name mcrypt_module_open() looks for. */
	const char *name;

	/* Block algorithms: one block of get_block_size() bytes is
	 * transformed in place. Stream algorithms leave these three NULL. */
	int (*set_key) (void *ctx, const void *key, int len);
	void (*encrypt) (void *ctx, void *block);
	void (*decrypt) (void *ctx, void *block);

	/* Stream algorithms: len bytes are transformed in place. Block
	 * algorithms leave these three NULL. */
	int (*stream_set_key) (void *ctx, const void *key, int len,
			       const void *iv, int iv_len);
	void (*stream_encrypt) (void *ctx, void *data, int len);
	void (*stream_decrypt) (void *ctx, void *data, int len);

	int (*get_size) (void);		/* size of ctx in bytes */
	int (*get_block_size) (void);
	int (*is_block_algo) (void);
	int (*get_key_size) (void);	/* largest key size */
	int (*get_algo_iv_size) (void);	/* stream algorithms only, may be NULL */
	const int *(*get_supported_key_sizes) (int *count);
	const char *(*get_name) (void);	/* the name shown to users */
	int (*self_test) (void);
	word32 (*get_version) (void);
} mcrypt_algo_module;

typedef struct mcrypt_mode_module {
	/* The name mcrypt_module_open() looks for. */
	const char *name;

	int (*init) (void *buf, const void *key, int key_len,
		     const void *iv, int size);
	int (*set_state) (void *buf, const void *iv, int size);
	int (*get_state) (void *buf, void *iv, int *size);
	int (*end) (void *buf);

	/* akey is the algorithm's context, already keyed. The mode calls
	 * algo->encrypt and algo->decrypt (the stream mode calls
	 * algo->stream_encrypt and algo->stream_decrypt) on it. */
	int (*encrypt) (void *buf, void *data, int len, int blocksize,
			void *akey, const mcrypt_algo_module *algo);
	int (*decrypt) (void *buf, void *data, int len, int blocksize,
			void *akey, const mcrypt_algo_module *algo);

	int (*has_iv) (void);
	int (*is_block_mode) (void);
	int (*is_block_algo_mode) (void);
	const char *(*get_name) (void);	/* the name shown to users */
	int (*get_size) (void);		/* size of buf in bytes */
	word32 (*get_version) (void);
} mcrypt_mode_module;

/* The registered modules, each list ended by NULL (lib/mcrypt_registry.c). */
extern const mcrypt_algo_module *const mcrypt_algo_modules[];
extern const mcrypt_mode_module *const mcrypt_mode_modules[];

/* Modes */
extern const mcrypt_mode_module mcrypt_mode_cbc;
extern const mcrypt_mode_module mcrypt_mode_cfb;
extern const mcrypt_mode_module mcrypt_mode_ctr;
extern const mcrypt_mode_module mcrypt_mode_ecb;
extern const mcrypt_mode_module mcrypt_mode_ncfb;
extern const mcrypt_mode_module mcrypt_mode_nofb;
extern const mcrypt_mode_module mcrypt_mode_ofb;
extern const mcrypt_mode_module mcrypt_mode_stream;

/* Algorithms */
extern const mcrypt_algo_module mcrypt_algo_arcfour;
extern const mcrypt_algo_module mcrypt_algo_blowfish;
extern const mcrypt_algo_module mcrypt_algo_blowfish_compat;
extern const mcrypt_algo_module mcrypt_algo_cast_128;
extern const mcrypt_algo_module mcrypt_algo_cast_256;
extern const mcrypt_algo_module mcrypt_algo_des;
extern const mcrypt_algo_module mcrypt_algo_enigma;
extern const mcrypt_algo_module mcrypt_algo_gost;
extern const mcrypt_algo_module mcrypt_algo_loki97;
extern const mcrypt_algo_module mcrypt_algo_rc2;
extern const mcrypt_algo_module mcrypt_algo_rijndael_128;
extern const mcrypt_algo_module mcrypt_algo_rijndael_192;
extern const mcrypt_algo_module mcrypt_algo_rijndael_256;
extern const mcrypt_algo_module mcrypt_algo_saferplus;
extern const mcrypt_algo_module mcrypt_algo_serpent;
extern const mcrypt_algo_module mcrypt_algo_tripledes;
extern const mcrypt_algo_module mcrypt_algo_twofish;
extern const mcrypt_algo_module mcrypt_algo_wake;
extern const mcrypt_algo_module mcrypt_algo_xtea;

/* Compiled but, as in upstream's default build, not registered. */
extern const mcrypt_algo_module mcrypt_algo_panama;
extern const mcrypt_algo_module mcrypt_algo_safer_sk64;
extern const mcrypt_algo_module mcrypt_algo_safer_sk128;
extern const mcrypt_algo_module mcrypt_algo_threeway;

#endif
