#include <stdio.h>
#include <string.h>
#include <time.h>
#include "dh.h"
#include "../csprng/csprng.h"

int main(void) {
    CSPRNG_CTX csprng;
    uint8_t seed[32];
    uint64_t t = (uint64_t)time(NULL);
    memcpy(seed, &t, 8);
    for (int i = 8; i < 32; i++) seed[i] = seed[i-1] * 33 + i;
    csprng_init(&csprng, seed);

    DH_CTX alice, bob;
    dh_init_group14(&alice);
    dh_init_group14(&bob);

    dh_generate_keys(&alice, &csprng);
    dh_generate_keys(&bob,   &csprng);

    /* exchange public keys as byte strings */
    uint8_t alice_pub[DH_KEY_BYTES], bob_pub[DH_KEY_BYTES];
    uint8_t secret_a[DH_KEY_BYTES], secret_b[DH_KEY_BYTES];

    dh_export_public(&alice, alice_pub, DH_KEY_BYTES);
    dh_export_public(&bob,   bob_pub,   DH_KEY_BYTES);

    if (dh_shared_secret(&alice, bob_pub,   DH_KEY_BYTES, secret_a) != 0 ||
        dh_shared_secret(&bob,   alice_pub, DH_KEY_BYTES, secret_b) != 0) {
        printf("DH Test FAILED: invalid peer key\n");
        return 1;
    }

    if (memcmp(secret_a, secret_b, DH_KEY_BYTES) == 0)
        printf("DH Test PASSED (2048-bit Group 14)\n");
    else
        printf("DH Test FAILED: secrets differ\n");

    return 0;
}