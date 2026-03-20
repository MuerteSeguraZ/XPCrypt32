#ifndef AES_H
#define AES_H
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t round_keys[60]; // Max for AES-256
    int nr; // number of rounds (10/12/14)
} AES_CTX;

void aes_key_expansion(const uint8_t *key,int nk,AES_CTX *ctx); // nk=4,6,8 for AES128/192/256
void aes_encrypt(const AES_CTX *ctx,const uint8_t in[16],uint8_t out[16]);
void aes_decrypt(const AES_CTX *ctx,const uint8_t in[16],uint8_t out[16]);

/* --- Block modes --- */

void aes_cbc_encrypt(
    const AES_CTX *ctx,
    uint8_t *data,
    size_t len,
    const uint8_t iv[16]
);

void aes_cbc_decrypt(
    const AES_CTX *ctx,
    uint8_t *data,
    size_t len,
    const uint8_t iv[16]
);

void aes_ctr_crypt(
    const AES_CTX *ctx,
    uint8_t *data,
    size_t len,
    uint8_t nonce[16]
);

void aes_ofb_crypt(const AES_CTX *ctx, uint8_t *data, size_t len, uint8_t iv[16]);
void aes_xts_encrypt(const AES_CTX *ctx_data, const AES_CTX *ctx_tweak, uint8_t *data, size_t len, const uint8_t tweak_iv[16]);
void aes_xts_decrypt(const AES_CTX *ctx_data, const AES_CTX *ctx_tweak, uint8_t *data, size_t len, const uint8_t tweak_iv[16]);

/* --- Padding --- */

void pkcs7_pad(uint8_t *buf, size_t len, size_t block);
int  pkcs7_unpad(uint8_t *buf, size_t *len);

#endif
