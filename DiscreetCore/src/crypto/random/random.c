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
#include "keccak/keccak.h"
#include "initializer.h"
#include "random/random.h"
#include "util.h"

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

#pragma pack(push, 1)
union hash_state {
    uint8_t b[200];
    uint64_t w[25];
};
#pragma pack(pop)

void hash_permutation(union hash_state* state) {
#if BYTE_ORDER == LITTLE_ENDIAN
    keccakf((uint64_t*)state, 24);
#else
    uint64_t le_state[25];
    memcpy_swap64le(le_state, state, 25);
    keccakf(le_state, 24);
    memcpy_swap64le(state, le_state, 25);
#endif
}

static inline void *padd(void *p, size_t i) {
  return (char *) p + i;
}

static void generate_system_randombytes(size_t n, void *res);

#if defined(_WIN32)

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <bcrypt.h>

static void generate_system_randombytes(size_t n, void *res) {
    HCRYPTPROV prov;
#ifdef RDBG
#define must_succeed(x) do if (!(x)) { fprintf(stderr, "Failed: " #x); _exit(1); } while (0)
#else
#define must_succeed(x) do if (!(x)) abort(); while (0)
#endif
#ifdef WINRNGLEGACY
    must_succeed(CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT));
    must_succeed(CryptGenRandom(prov, (DWORD)n, res));
    must_succeed(CryptReleaseContext(prov, 0));
#else
    NTSTATUS crypt_status;
    crypt_status = BCryptGenRandom(NULL, res, n, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(crypt_status)) {
        must_succeed(false);
    }
#endif
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

static union hash_state state;
static size_t rnginit = 0;

#if !defined(RDBG)
static volatile int curstate = 0;
#endif

FINALIZER(deinit_random) {
#if !defined(RDBG)
    assert(curstate == 1);
    curstate = 0;
#endif
  memset(&state, 0, sizeof(union hash_state));
#ifdef RDBG
  printf("deinitialized random\n");
#endif
}

#define INIT_ROUNDS 32

INITIALIZER(init_random) {
    rnginit = 1;
    generate_system_randombytes(sizeof(union hash_state), &state);
    hash_permutation(&state);
    REGISTER_FINALIZER(deinit_random);
#if !defined(RDBG)
    assert(curstate == 0);
    curstate = 1;
#endif
}

void generate_randombytes(size_t n, void *res) {
    if (!rnginit) { //failsafe to ensure rng is initialized
        rnginit = 1;
        init_random();
    }
    //generate_system_randombytes(n, res);
    //return;
#if !defined(RDBG)
    assert(curstate == 1);
    curstate = 2;
#endif
    if (n == 0) {
#if !defined(RDBG)
        assert(curstate == 2);
        curstate = 1;
#endif
        return;
    }
    for (;;) {
        hash_permutation(&state);
        if (n <= KECCAK_BLOCKLEN) {
            memcpy(res, &state, n);
#if !defined(RDBG)
            assert(curstate == 2);
            curstate = 1;
#endif
            return;
        }
        else {
            memcpy(res, &state, KECCAK_BLOCKLEN);
            res = padd(res, KECCAK_BLOCKLEN);
            n -= KECCAK_BLOCKLEN;
        }
    }
}

