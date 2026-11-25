/*
 * Minimal Node addon used by CI to exercise the gyp build the way
 * node-mcrypt consumes it: libmcrypt.gyp as a dependency, linked statically
 * into a .node file. Loading the addon runs the self-test; the number of
 * failures is exported as "failures".
 *
 * binding.gyp explains how to build it.
 */
#include <node_api.h>

int libmcrypt_selftest(void);

static napi_value init(napi_env env, napi_value exports)
{
	napi_value failures;

	if (napi_create_int32(env, libmcrypt_selftest(), &failures) != napi_ok
	    || napi_set_named_property(env, exports, "failures", failures) != napi_ok)
		napi_throw_error(env, NULL, "could not export the self-test result");

	return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
