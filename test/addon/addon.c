/*
 * Minimal Node addon used by CI to exercise the gyp build the way
 * node-mcrypt consumes it: libmcrypt.gyp as a dependency, linked statically
 * into a .node file.
 *
 * Loading the addon runs the self-test; the number of failures is exported
 * as "failures". vectors(path) compares the library with the upstream
 * answers in test/vectors-2.5.8.txt and returns the number of problems.
 *
 * binding.gyp explains how to build it.
 */
#include <node_api.h>

int libmcrypt_selftest(void);
int libmcrypt_vectors_check(const char *path);

static napi_value vectors(napi_env env, napi_callback_info info)
{
	napi_value argv[1], result;
	size_t argc = 1, length = 0;
	char path[4096];

	if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok || argc < 1
	    || napi_get_value_string_utf8(env, argv[0], path, sizeof(path), &length) != napi_ok) {
		napi_throw_type_error(env, NULL, "vectors(path): the path of the vectors file is missing");
		return NULL;
	}

	if (napi_create_int32(env, libmcrypt_vectors_check(path), &result) != napi_ok)
		return NULL;

	return result;
}

static napi_value init(napi_env env, napi_value exports)
{
	napi_value failures, function;

	if (napi_create_int32(env, libmcrypt_selftest(), &failures) != napi_ok
	    || napi_set_named_property(env, exports, "failures", failures) != napi_ok
	    || napi_create_function(env, "vectors", NAPI_AUTO_LENGTH, vectors, NULL, &function) != napi_ok
	    || napi_set_named_property(env, exports, "vectors", function) != napi_ok)
		napi_throw_error(env, NULL, "could not export the test results");

	return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
