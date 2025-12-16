#include "chacha20_poly1305.h"
#include "poly1305.h"
#include <string.h>
#include <stdint.h>

// ChaCha20 quarter round
#define ROTL(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define QR(a,b,c,d) (a += b, d ^= a, d=ROTL(d,16), c+=d, b^=c, b=ROTL(b,12), a+=b, d^=a, d=ROTL(d,8), c+=d, b^=c, b=ROTL(b,7))

static void chacha20_block(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t out[64]) {
    uint32_t state[16];
    int i;

    // Constants
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // Key
    for(i=0;i<8;i++){
        state[4+i] = ((uint32_t)key[i*4]) | ((uint32_t)key[i*4+1]<<8) | ((uint32_t)key[i*4+2]<<16) | ((uint32_t)key[i*4+3]<<24);
    }

    state[12] = counter;
    state[13] = ((uint32_t)nonce[0]) | ((uint32_t)nonce[1]<<8) | ((uint32_t)nonce[2]<<16) | ((uint32_t)nonce[3]<<24);
    state[14] = ((uint32_t)nonce[4]) | ((uint32_t)nonce[5]<<8) | ((uint32_t)nonce[6]<<16) | ((uint32_t)nonce[7]<<24);
    state[15] = ((uint32_t)nonce[8]) | ((uint32_t)nonce[9]<<8) | ((uint32_t)nonce[10]<<16) | ((uint32_t)nonce[11]<<24);

    uint32_t working[16];
    for(i=0;i<16;i++) working[i]=state[i];

    for(i=0;i<10;i++){ // 20 rounds
        QR(working[0],working[4],working[8],working[12]);
        QR(working[1],working[5],working[9],working[13]);
        QR(working[2],working[6],working[10],working[14]);
        QR(working[3],working[7],working[11],working[15]);

        QR(working[0],working[5],working[10],working[15]);
        QR(working[1],working[6],working[11],working[12]);
        QR(working[2],working[7],working[8],working[13]);
        QR(working[3],working[4],working[9],working[14]);
    }

    for(i=0;i<16;i++){
        uint32_t x = working[i]+state[i];
        out[i*4+0] = x & 0xFF;
        out[i*4+1] = (x >> 8) & 0xFF;
        out[i*4+2] = (x >> 16) & 0xFF;
        out[i*4+3] = (x >> 24) & 0xFF;
    }
}

static void chacha20_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, const uint8_t *in, uint8_t *out, size_t len){
    uint8_t block[64];
    size_t i,j;
    for(i=0;i<len;i+=64){
        chacha20_block(key,nonce,counter++,block);
        size_t n = (len-i)>64?64:(len-i);
        for(j=0;j<n;j++) out[i+j] = in[i+j] ^ block[j];
    }
}

static void poly1305_aead_tag(uint8_t tag[16], const uint8_t key[32], const uint8_t *aad, size_t aad_len, const uint8_t *ciphertext, size_t text_len){
    POLY1305_CTX ctx;
    poly1305_init(&ctx,key);

    if(aad && aad_len>0) poly1305_update(&ctx,aad,aad_len);
    if(aad_len%16) poly1305_update(&ctx,(uint8_t[]){0},16-(aad_len%16));

    if(ciphertext && text_len>0) poly1305_update(&ctx,ciphertext,text_len);
    if(text_len%16) poly1305_update(&ctx,(uint8_t[]){0},16-(text_len%16));

    uint8_t len_bytes[16];
    for(int i=0;i<8;i++){
        len_bytes[i] = (uint8_t)(aad_len >> (i*8));
        len_bytes[8+i] = (uint8_t)(text_len >> (i*8));
    }

    poly1305_update(&ctx,len_bytes,16);
    poly1305_finish(&ctx,tag);
}

void chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *plaintext, size_t len, const uint8_t *aad, size_t aad_len, uint8_t *ciphertext, uint8_t tag[16]){
    uint8_t poly_key[32];
    chacha20_xor(key,nonce,0,(uint8_t[32]){0},poly_key,32);

    chacha20_xor(key,nonce,1,plaintext,ciphertext,len);
    poly1305_aead_tag(tag,poly_key,aad,aad_len,ciphertext,len);
}

int chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *ciphertext, size_t len, const uint8_t *aad, size_t aad_len, const uint8_t tag[16], uint8_t *plaintext){
    uint8_t poly_key[32], computed_tag[16];
    chacha20_xor(key,nonce,0,(uint8_t[32]){0},poly_key,32);

    poly1305_aead_tag(computed_tag,poly_key,aad,aad_len,ciphertext,len);
    for(int i=0;i<16;i++) if(computed_tag[i]!=tag[i]) return -1;

    chacha20_xor(key,nonce,1,ciphertext,plaintext,len);
    return 0;
}
