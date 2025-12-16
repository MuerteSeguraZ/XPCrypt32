#ifndef POLY1305_H
#define POLY1305_H
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t r[5];     // r key
    uint32_t h[5];     // accumulator
    uint32_t pad[4];   // pad
    size_t leftover;
    uint8_t buffer[16];
} POLY1305_CTX;

void poly1305_init(POLY1305_CTX *ctx, const uint8_t key[32]);
void poly1305_update(POLY1305_CTX *ctx, const uint8_t *m, size_t len);
void poly1305_finish(POLY1305_CTX *ctx, uint8_t mac[16]);

#endif
