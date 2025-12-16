#ifndef SHA512_H
#define SHA512_H

#include <stdint.h>
#include <stddef.h>

// ================= SHA-512 =================
typedef struct {
    uint64_t state[8];
    uint64_t bitlen[2];
    uint8_t data[128];
    uint32_t datalen;
} SHA512_CTX;

void sha512_init(SHA512_CTX *ctx);
void sha512_update(SHA512_CTX *ctx, const uint8_t data[], size_t len);
void sha512_final(SHA512_CTX *ctx, uint8_t hash[64]);

// ================= HMAC-SHA512 =================
void hmac_sha512(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[64]);

// ================= HKDF-SHA512 =================
void hkdf_sha512(const uint8_t *salt, size_t salt_len,
                 const uint8_t *ikm, size_t ikm_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t *okm, size_t okm_len);

#endif
