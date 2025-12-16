#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t state[16];
} CHACHA20_CTX;

// Initialize ChaCha20 context with 256-bit key and 96-bit nonce
void chacha20_init(CHACHA20_CTX *ctx, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter);

// Generate `len` bytes of keystream
void chacha20_keystream(CHACHA20_CTX *ctx, uint8_t *out, size_t len);

// Encrypt/decrypt `len` bytes (XOR with keystream)
void chacha20_crypt(CHACHA20_CTX *ctx, const uint8_t *in, uint8_t *out, size_t len);

#endif
