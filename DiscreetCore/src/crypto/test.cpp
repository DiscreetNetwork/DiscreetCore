#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "crypto.h"

extern "C" {
#include "crypto_curve.h"
}

void print32(const char * const msg, unsigned char *buf)
{
    const char *conv__ = "0123456789ABCDEF";
    char printable[65] = {0};
    int i;

    for (i = 0; i < 32; i++) {
        printable[2 * i] = conv__[((int) buf[i] >> 4) & 0xF];
        printable[2 * i + 1] = conv__[(int) buf[i] & 0xF];
    }

    printf("%s:\n%s\n\n\n", msg, printable);
}

int main(void)
{
    pubkey pub;
    seckey sec;
    schnorr_sig sig;
    generate_keypair(pub, sec);

    print32("pubkey", pub);
    print32("seckey", sec);

    unsigned char hash[32];

    hash_op((const void *) "DISCREET_SIGN", strlen("DISCREET_SIGN"), hash);

    generate_signature(hash, pub, sec, sig);

    print32("c", SIG_C(sig));
    print32("r", SIG_R(sig));

    if (check_signature(hash, pub, sig))
        printf("good!\n");
    else
        printf("bad!\n");
}