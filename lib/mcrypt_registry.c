/*
 * The modules mcrypt_module_open() can find by name.
 *
 * Each entry is a descriptor that the module's own source file defines
 * (see mcrypt_registry.h). mcrypt_list_algorithms() and mcrypt_list_modes()
 * return the names in the order given here, which is the order upstream's
 * generated table had.
 */

#include <libdefs.h>
#include <mcrypt_registry.h>

const mcrypt_mode_module *const mcrypt_mode_modules[] = {
	&mcrypt_mode_cbc,
	&mcrypt_mode_cfb,
	&mcrypt_mode_ctr,
	&mcrypt_mode_ecb,
	&mcrypt_mode_ncfb,
	&mcrypt_mode_nofb,
	&mcrypt_mode_ofb,
	&mcrypt_mode_stream,
	NULL
};

const mcrypt_algo_module *const mcrypt_algo_modules[] = {
	&mcrypt_algo_cast_128,
	&mcrypt_algo_gost,
	&mcrypt_algo_rijndael_128,
	&mcrypt_algo_twofish,
	&mcrypt_algo_arcfour,
	&mcrypt_algo_cast_256,
	&mcrypt_algo_loki97,
	&mcrypt_algo_rijndael_192,
	&mcrypt_algo_saferplus,
	&mcrypt_algo_wake,
	&mcrypt_algo_blowfish_compat,
	&mcrypt_algo_des,
	&mcrypt_algo_rijndael_256,
	&mcrypt_algo_serpent,
	&mcrypt_algo_xtea,
	&mcrypt_algo_blowfish,
	&mcrypt_algo_enigma,
	&mcrypt_algo_rc2,
	&mcrypt_algo_tripledes,
	/* Compiled but not registered, as in upstream's default build:
	 * mcrypt_algo_panama, mcrypt_algo_safer_sk64,
	 * mcrypt_algo_safer_sk128, mcrypt_algo_threeway. */
	NULL
};
