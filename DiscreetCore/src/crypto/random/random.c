/**
 * Filename:    random.c
 * Author:      Brandon Koerner (bkoerner@getdiscreet.org)
 * Disclaimer:  Code is presented "as is" without guarantees.
 * Details:     RNG definitions.
 * 
 * Protected under GNU general public license v3.
 */

#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "sha/sha512.h"
#include "initializer.h"
#include "random/random.h"

#ifdef RDBG
#include <stdio.h>

static void print32(char * const msg, const unsigned char *buf)
{
    char *conv__ = "0123456789ABCDEF";
    char printable[65] = {0};
    int i;

    for (i = 0; i < 32; i++) {
        printable[2 * i] = conv__[((int) buf[i] >> 4) & 0xF];
        printable[2 * i + 1] = conv__[(int) buf[i] & 0xF];
    }

    printf("%s:\n%s\n\n\n", msg, printable);
}
#endif

static inline void *padd(void *p, size_t i) {
  return (char *) p + i;
}

static void generate_system_randombytes(size_t n, void *res);

#if defined(_WIN32)

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

static void generate_system_randombytes(size_t n, void *res) {
    HCRYPTPROV prov;
    CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
    CryptGenRandom(prov, (DWORD)n, res);
    CryptReleaseContext(prov, 0);
}

#else 

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static void generate_system_randombytes(size_t n, void *result) {
    int fd;
    if ((fd = open("/dev/urandom", O_RDONLY | O_NOCTTY | O_CLOEXEC)) < 0) {
        err(EXIT_FAILURE, "open /dev/urandom");
    }
    for (;;) {
        ssize_t res = read(fd, result, n);
        if ((size_t) res == n) {
            break;
        }
        if (res < 0) {
            if (errno != EINTR) {
                err(EXIT_FAILURE, "read /dev/urandom");
            }
        } else if (res == 0) {
            errx(EXIT_FAILURE, "read /dev/urandom: end of file");
        } else {
            result = padd(result, (size_t) res);
            n -= (size_t) res;
        }
    }
    if (close(fd) < 0) {
        err(EXIT_FAILURE, "close /dev/urandom");
    }
}

#endif

static sha512_ctx state;

FINALIZER(deinit_random) {
  memset(&state, 0, sizeof(sha512_ctx));
#ifdef RDBG
  printf("deinitialized random\n");
#endif
}

#define INIT_ROUNDS 32

INITIALIZER(init_random) {
  unsigned char _tmp[SHA512_DIGEST_SIZE];
  sha512_init(&state);
  int i;
  for (i = 0; i < INIT_ROUNDS; i++) {
    generate_system_randombytes(64, (void *) &_tmp[0]);
    sha512_update(&state, _tmp, SHA512_DIGEST_SIZE);
  }
  REGISTER_FINALIZER(deinit_random);
#ifdef RDBG
  printf("initialized random\n");
  print32("tmp0:31", _tmp);
  print32("tmp32:63", _tmp + 32);
#endif
}

void generate_randombytes(size_t n, void *res) {
    unsigned char _tmp[SHA512_DIGEST_SIZE];
    memcpy(_tmp, &state.s[0], SHA512_DIGEST_SIZE);
    for (;;) {
        sha512_update(&state, _tmp, SHA512_DIGEST_SIZE);
        if (n <= SHA512_DIGEST_SIZE) {
#ifdef RDBG
            unsigned char *_tmp2 = (unsigned char *)&state.s[0];
            print32("state.s", _tmp2);
            print32("state.s (2)", _tmp2 + 32);
#endif
            memcpy(res, &state.s[0], n);
            return;
        } else {
            memcpy(res, &state.s[0], SHA512_DIGEST_SIZE);
            res = (void*)((char*)res + SHA512_DIGEST_SIZE);
            n -= SHA512_DIGEST_SIZE;
        }
    }
}

