#ifndef CHACHA20_POLY1305_H
#define CHACHA20_POLY1305_H

#include <stdint.h>
#include <stddef.h>

// ChaCha20-Poly1305 context
typedef struct {
    uint8_t key[32];
    uint8_t nonce[12];
} CHACHA20_POLY1305_CTX;

// Encrypt `plaintext` into `ciphertext` with AEAD
// `aad` is additional authenticated data
// `tag` must be 16 bytes
void chacha20_poly1305_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *plaintext,
    size_t len,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *ciphertext,
    uint8_t tag[16]
);

// Decrypt `ciphertext` into `plaintext`
// Returns 0 on success, -1 if tag fails
int chacha20_poly1305_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *ciphertext,
    size_t len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t tag[16],
    uint8_t *plaintext
);

#endif
