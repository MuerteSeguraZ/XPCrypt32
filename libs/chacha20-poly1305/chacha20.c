#include "chacha20.h"
#include <string.h>
#include <stdint.h>

static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

#define QUARTERROUND(a,b,c,d) \
    a += b; d ^= a; d = rotl32(d,16); \
    c += d; b ^= c; b = rotl32(b,12); \
    a += b; d ^= a; d = rotl32(d,8); \
    c += d; b ^= c; b = rotl32(b,7);

static void chacha20_block(CHACHA20_CTX *ctx, uint8_t output[64]) {
    int i;
    uint32_t x[16];
    memcpy(x, ctx->state, sizeof(x));
    for (i = 0; i < 10; i++) { // 20 rounds
        QUARTERROUND(x[0],x[4],x[8],x[12])
        QUARTERROUND(x[1],x[5],x[9],x[13])
        QUARTERROUND(x[2],x[6],x[10],x[14])
        QUARTERROUND(x[3],x[7],x[11],x[15])
        QUARTERROUND(x[0],x[5],x[10],x[15])
        QUARTERROUND(x[1],x[6],x[11],x[12])
        QUARTERROUND(x[2],x[7],x[8],x[13])
        QUARTERROUND(x[3],x[4],x[9],x[14])
    }
    for(i=0;i<16;i++){
        uint32_t res = x[i] + ctx->state[i];
        output[i*4+0] = res & 0xFF;
        output[i*4+1] = (res>>8) & 0xFF;
        output[i*4+2] = (res>>16) & 0xFF;
        output[i*4+3] = (res>>24) & 0xFF;
    }
}

void chacha20_init(CHACHA20_CTX *ctx, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter){
    static const char *constants = "expand 32-byte k";
    ctx->state[0] = ((uint32_t*)constants)[0];
    ctx->state[1] = ((uint32_t*)constants)[1];
    ctx->state[2] = ((uint32_t*)constants)[2];
    ctx->state[3] = ((uint32_t*)constants)[3];
    int i;
    for(i=0;i<8;i++)
        ctx->state[4+i] = ((uint32_t*)key)[i];
    ctx->state[12] = counter;
    ctx->state[13] = ((uint32_t*)nonce)[0];
    ctx->state[14] = ((uint32_t*)nonce)[1];
    ctx->state[15] = ((uint32_t*)nonce)[2];
}

void chacha20_keystream(CHACHA20_CTX *ctx, uint8_t *out, size_t len){
    size_t i, j;
    uint8_t block[64];
    while(len>0){
        chacha20_block(ctx, block);
        size_t to_copy = len>64?64:len;
        for(i=0;i<to_copy;i++)
            out[i] = block[i];
        out += to_copy;
        len -= to_copy;
        ctx->state[12]++;
    }
}

void chacha20_crypt(CHACHA20_CTX *ctx, const uint8_t *in, uint8_t *out, size_t len){
    size_t i;
    uint8_t block[64];
    while(len>0){
        chacha20_block(ctx, block);
        size_t to_copy = len>64?64:len;
        for(i=0;i<to_copy;i++)
            out[i] = in[i] ^ block[i];
        in += to_copy;
        out += to_copy;
        len -= to_copy;
        ctx->state[12]++;
    }
}
