#include "poly1305.h"
#include <string.h>
#include <stdint.h>

#define U32(x) ((uint32_t)(x))

static uint32_t load32(const uint8_t *src) {
    return (uint32_t)src[0] | ((uint32_t)src[1] << 8) |
           ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
}

static void poly1305_blocks(POLY1305_CTX *ctx, const uint8_t *m, size_t bytes);

void poly1305_init(POLY1305_CTX *ctx, const uint8_t key[32]) {
    memset(ctx, 0, sizeof(*ctx));

    // r = key[0..15] with clamping
    uint64_t t0 = load32(key+0);
    uint64_t t1 = load32(key+4);
    uint64_t t2 = load32(key+8);
    uint64_t t3 = load32(key+12);

    t0 &= 0x3ffffff; 
    t1 &= 0x3ffff03;
    t2 &= 0x3ffc0ff;
    t3 &= 0x3f03fff;

    ctx->r[0] = t0 & 0x3ffffff;
    ctx->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
    ctx->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
    ctx->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
    ctx->r[4] = (t3 >> 8) & 0x3ffffff;

    ctx->pad[0] = load32(key + 16);
    ctx->pad[1] = load32(key + 20);
    ctx->pad[2] = load32(key + 24);
    ctx->pad[3] = load32(key + 28);

    ctx->leftover = 0;
}

void poly1305_update(POLY1305_CTX *ctx, const uint8_t *m, size_t len) {
    size_t i=0;

    if(ctx->leftover) {
        size_t want = 16 - ctx->leftover;
        if(want > len) want = len;
        for(size_t j=0;j<want;j++) ctx->buffer[ctx->leftover+j] = m[i+j];
        ctx->leftover += want;
        i += want;
        len -= want;
        if(ctx->leftover < 16) return;
        poly1305_blocks(ctx, ctx->buffer, 16);
        ctx->leftover = 0;
    }

    if(len >= 16) {
        size_t want = len & ~0xf;
        poly1305_blocks(ctx, m+i, want);
        i += want;
        len -= want;
    }

    if(len) {
        for(size_t j=0;j<len;j++) ctx->buffer[ctx->leftover+j] = m[i+j];
        ctx->leftover += len;
    }
}

void poly1305_finish(POLY1305_CTX *ctx, uint8_t mac[16]) {
    if(ctx->leftover) {
        for(size_t i=ctx->leftover;i<16;i++) ctx->buffer[i]=0;
        poly1305_blocks(ctx, ctx->buffer, 16);
    }

    // fully carry and reduce
    uint64_t f, g, c;
    uint32_t h[5];
    for(int i=0;i<5;i++) h[i] = ctx->h[i];

    c = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += c;
    c = h[1] >> 26; h[1] &= 0x3ffffff; h[2] += c;
    c = h[2] >> 26; h[2] &= 0x3ffffff; h[3] += c;
    c = h[3] >> 26; h[3] &= 0x3ffffff; h[4] += c;
    c = h[4] >> 26; h[4] &= 0x3ffffff; h[0] += c*5;
    c = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += c;

    uint64_t acc = 0;
    for(int i=0;i<5;i++) acc |= ((uint64_t)h[i] << (i*26));

    for(int i=0;i<4;i++){
        uint32_t t = (uint32_t)((acc >> (i*32)) & 0xffffffff);
        t += ctx->pad[i];
        mac[i*4+0] = t & 0xff;
        mac[i*4+1] = (t >> 8) & 0xff;
        mac[i*4+2] = (t >> 16) & 0xff;
        mac[i*4+3] = (t >> 24) & 0xff;
    }
}

static void poly1305_blocks(POLY1305_CTX *ctx, const uint8_t *m, size_t bytes) {
    while(bytes >= 16) {
        uint64_t t0 = load32(m+0);
        uint64_t t1 = load32(m+4);
        uint64_t t2 = load32(m+8);
        uint64_t t3 = load32(m+12);

        ctx->h[0] += t0 & 0x3ffffff;
        ctx->h[1] += ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
        ctx->h[2] += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
        ctx->h[3] += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
        ctx->h[4] += (t3 >> 8) | (1 << 24); // append high bit

        // multiply mod (2^130-5)
        uint64_t r[5]; for(int i=0;i<5;i++) r[i] = ctx->r[i];
        uint64_t h[5]; for(int i=0;i<5;i++) h[i] = ctx->h[i];

        uint64_t hr[5];
        hr[0] = h[0]*r[0] + h[1]*5*r[4] + h[2]*5*r[3] + h[3]*5*r[2] + h[4]*5*r[1];
        hr[1] = h[0]*r[1] + h[1]*r[0] + h[2]*5*r[4] + h[3]*5*r[3] + h[4]*5*r[2];
        hr[2] = h[0]*r[2] + h[1]*r[1] + h[2]*r[0] + h[3]*5*r[4] + h[4]*5*r[3];
        hr[3] = h[0]*r[3] + h[1]*r[2] + h[2]*r[1] + h[3]*r[0] + h[4]*5*r[4];
        hr[4] = h[0]*r[4] + h[1]*r[3] + h[2]*r[2] + h[3]*r[1] + h[4]*r[0];

        uint64_t c = 0;
        for(int i=0;i<5;i++){
            hr[i] += c;
            c = hr[i] >> 26;
            ctx->h[i] = hr[i] & 0x3ffffff;
        }
        ctx->h[0] += c*5;

        m += 16;
        bytes -= 16;
    }
}
