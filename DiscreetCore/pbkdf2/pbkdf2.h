#ifndef PBKDF2_H
#define PBKDF2_H

/*
 * PBKDF2 will use HMAC-SHA2 (SHA256) as the PRF.
 * Keys derived from this can be used for stream encryption,
 * as well as wallet encryption.
 */

#include "export.h"

EXPORT void pbkdf2(unsigned char *output,
            unsigned char *password, unsigned int password_len, 
            unsigned char *salt, unsigned int salt_len,
            unsigned int iter, unsigned int keylen);

#endif // PBKDF2_H