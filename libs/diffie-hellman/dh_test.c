#include <stdio.h>
#include <string.h>
#include <time.h>
#include "dh.h"
#include "../csprng/csprng.h"

int main() {
    CSPRNG_CTX csprng;
    uint64_t t = (uint64_t)time(NULL);
    memcpy(seed, &t, sizeof(t));

    for (int i = 8; i < 32; i++)
        seed[i] = seed[i - 1] * 33 + i;

    csprng_init(&csprng, seed);

    DH_CTX alice, bob;
    uint64_t prime = 4294967311;
    uint64_t generator = 5;

    dh_init(&alice, prime, generator);
    dh_init(&bob, prime, generator);

    dh_generate_keys(&alice, &csprng);
    dh_generate_keys(&bob, &csprng);

    uint64_t secret_a = dh_shared_secret(&alice, bob.public_key);
    uint64_t secret_b = dh_shared_secret(&bob, alice.public_key);

    printf("Alice secret: %llu\n", secret_a);
    printf("Bob secret  : %llu\n", secret_b);

    if(secret_a == secret_b)
      printf("DH Test PASSED\n");
    else
      printf("DH Test FAILED");

    return 0;
}