#ifndef KECCAK_H
#define KECCAK_H

#include <stdint.h>
#include <stddef.h>

// SHA3 context
typedef struct {
    uint64_t state[25];
    uint8_t buffer[200];
    size_t buflen;
    size_t rate;
    size_t output_len;
} SHA3_CTX;

// SHA3-256
void sha3_256_init(SHA3_CTX *ctx);
void sha3_256_update(SHA3_CTX *ctx, const uint8_t *data, size_t len);
void sha3_256_final(SHA3_CTX *ctx, uint8_t hash[32]);

// SHA3-512
void sha3_512_init(SHA3_CTX *ctx);
void sha3_512_update(SHA3_CTX *ctx, const uint8_t *data, size_t len);
void sha3_512_final(SHA3_CTX *ctx, uint8_t hash[64]);

#endif
