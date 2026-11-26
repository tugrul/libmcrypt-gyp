# CI only: a test addon that links the static library the way node-mcrypt
# does. See addon.c.
#
# gyp cannot depend on a .gyp file in a parent directory (its make generator
# would write the archive on top of itself), so the library has to sit below
# this file, where node-mcrypt keeps its copy:
#
#     mkdir -p test/addon/lib/libmcrypt
#     cp -r include lib modules libmcrypt.gyp test/addon/lib/libmcrypt/
#     npx node-gyp rebuild --directory test/addon
{
    'targets': [
        {
            'target_name': 'selftest',
            'sources': [
                'addon.c',
                '../selftest.c',
                '../vectors.c'
            ],
            'defines': [
                'LIBMCRYPT_SELFTEST_NO_MAIN',
                'LIBMCRYPT_VECTORS_NO_MAIN'
            ],
            'include_dirs': [
                'lib/libmcrypt/include/'
            ],
            'dependencies': [
                'lib/libmcrypt/libmcrypt.gyp:libmcrypt'
            ]
        }
    ]
}
