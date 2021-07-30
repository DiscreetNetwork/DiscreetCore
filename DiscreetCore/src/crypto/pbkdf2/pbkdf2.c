#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "hmac/hmacsha256.h"
#include "pbkdf2/pbkdf2.h"

void pbkdf2(unsigned char *output, 
            unsigned char *password, unsigned int password_len, 
            unsigned char *salt, unsigned int salt_len,
            unsigned int iter, unsigned int keylen)
{
    hmacsha256_ctx ctx;
    unsigned char uc[hmacsha256_BYTES];
    unsigned char uc2[hmacsha256_BYTES];
    unsigned char ux[hmacsha256_BYTES];

    unsigned int no_iter = (keylen / hmacsha256_BYTES);
    unsigned int salt_trunc_len = (salt_len > hmacsha256_BYTES - 4) \
                                    ? hmacsha256_BYTES - 4 : salt_len;

    if (((keylen % hmacsha256_BYTES) != 0) || (iter == 0)) {
        abort();
    }

    uint32_t i;
    int c, j, bi = 0;

    for (i = 0U; i < no_iter; i++) {
        for (j = 0; j < hmacsha256_BYTES; j++) {
            ux[j] = 0U;
        }
        for (j = 0; j < salt_len; j++) {
            uc[j] = salt[j];
        }
        for (; j < hmacsha256_BYTES - 4; j++) {
            uc[j] = 0U;
        }
        uc[hmacsha256_BYTES - 4] = (i >> 24);
        uc[hmacsha256_BYTES - 3] = (i >> 16) & 0xFF;
        uc[hmacsha256_BYTES - 2] = (i >> 8) & 0xFF;
        uc[hmacsha256_BYTES - 1] = i & 0xFF;

        for (c = 0; c < iter; c++) {
            hmacsha256(uc2, password, password_len, uc);
            memcpy(uc, uc2, hmacsha256_BYTES);
            for (j = 0; j < hmacsha256_BYTES; j++) {
                ux[j] ^= uc[j];
            }
        }

        /* write next hmacsha256_BYTES bytes to buffer */
        for (j = 0; j < hmacsha256_BYTES; j++) {
            output[bi + j] = ux[j];
        }
        bi += hmacsha256_BYTES;
    }
}
