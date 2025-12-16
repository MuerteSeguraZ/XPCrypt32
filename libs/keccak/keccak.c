#include "keccak.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>

// ================= Keccak helpers =================
static const uint64_t keccakf_rndc[24] = {
    0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
    0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
    0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
    0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
    0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
    0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL
};

static const int keccakf_rotc[24] = {
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const int keccakf_piln[24] = {
    10,  7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

static void keccakf(uint64_t st[25]) {
    int i, j, round;
    uint64_t t, bc[5];

    for(round=0; round<24; round++) {
        // θ step
        for(i=0;i<5;i++) bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20];
        for(i=0;i<5;i++) {
            t = bc[(i+4)%5] ^ ROTL64(bc[(i+1)%5], 1);
            for(j=0;j<25;j+=5) st[j+i] ^= t;
        }

        // ρ and π steps
        t = st[1];
        for(i=0;i<24;i++) {
            j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = ROTL64(t, keccakf_rotc[i]);
            t = bc[0];
        }

        // χ step
        for(j=0;j<25;j+=5) {
            for(i=0;i<5;i++) bc[i] = st[j+i];
            for(i=0;i<5;i++) st[j+i] ^= (~bc[(i+1)%5]) & bc[(i+2)%5];
        }

        // ι step
        st[0] ^= keccakf_rndc[round];
    }
}

// ================= SHA3 =================
static void sha3_init(SHA3_CTX *ctx, size_t rate, size_t outlen) {
    memset(ctx, 0, sizeof(SHA3_CTX));
    ctx->rate = rate;
    ctx->output_len = outlen;
}

static void sha3_update(SHA3_CTX *ctx, const uint8_t *data, size_t len) {
    size_t i=0;
    while(i<len) {
        size_t n = ctx->rate - ctx->buflen;
        if(n>len-i) n=len-i;
        for(size_t j=0;j<n;j++) ctx->buffer[ctx->buflen+j] ^= data[i+j];
        ctx->buflen += n; i += n;

        if(ctx->buflen==ctx->rate) {
            keccakf(ctx->state);
            ctx->buflen=0;
        }
    }
}

static void sha3_final(SHA3_CTX *ctx, uint8_t *hash) {
    ctx->buffer[ctx->buflen] ^= 0x06; // SHA-3 padding
    ctx->buffer[ctx->rate-1] ^= 0x80;
    keccakf(ctx->state);

    size_t i, j=0;
    for(i=0;i<ctx->output_len;i++) {
        hash[i] = (uint8_t)(ctx->state[i/8] >> (8*(i%8)));
    }
}

// ================= SHA3-256 =================
void sha3_256_init(SHA3_CTX *ctx) { sha3_init(ctx, 136, 32); }
void sha3_256_update(SHA3_CTX *ctx, const uint8_t *data, size_t len) { sha3_update(ctx, data, len); }
void sha3_256_final(SHA3_CTX *ctx, uint8_t hash[32]) { sha3_final(ctx, hash); }

// ================= SHA3-512 =================
void sha3_512_init(SHA3_CTX *ctx) { sha3_init(ctx, 72, 64); }
void sha3_512_update(SHA3_CTX *ctx, const uint8_t *data, size_t len) { sha3_update(ctx, data, len); }
void sha3_512_final(SHA3_CTX *ctx, uint8_t hash[64]) { sha3_final(ctx, hash); }
