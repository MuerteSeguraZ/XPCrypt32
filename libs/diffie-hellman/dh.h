#ifndef DH_H
#define DH_H

#include <stdint.h>
#include <stddef.h>
#include "..\csprng\csprng.h"

typedef struct {
    uint64_t p;
    uint64_t g;
    uint64_t private_key;
    uint64_t public_key;
} DH_CTX;

void dh_init(DH_CTX *ctx, uint64_t p, uint64_t g);
void dh_generate_keys(DH_CTX *ctx, CSPRNG_CTX *csprng);
uint64_t dh_shared_secret(DH_CTX *ctx, uint64_t peer_public);

#endif