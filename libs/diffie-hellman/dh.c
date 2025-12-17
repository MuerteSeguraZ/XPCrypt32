#include "dh.h"
#include "../csprng/csprng.h"
#include <stdint.h>

// fast modular expo
static uint64_t mod_pow(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) result = (result * base) % mod;
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

void dh_init(DH_CTX *ctx, uint64_t p, uint64_t g) {
    ctx->p = p;
    ctx->g = g;
    ctx->private_key = 0;
    ctx->public_key = 0;
}

void dh_generate_keys(DH_CTX *ctx, CSPRNG_CTX *rng) {
    // private key in [2, p-2]
    ctx->private_key = 2 + csprng_uniform(rng, (uint32_t)(ctx->p - 3));
    ctx->public_key  = mod_pow(ctx->g, ctx->private_key, ctx->p);
}

uint64_t dh_shared_secret(DH_CTX *ctx, uint64_t peer_public) {
    return mod_pow(peer_public, ctx->private_key, ctx->p);
}