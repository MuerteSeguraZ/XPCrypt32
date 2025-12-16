#ifndef CSPRNG_H
#define CSPRNG_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t seed[32];   // Initial seed / entropy
    uint64_t counter;   // Incrementing counter for uniqueness
} CSPRNG_CTX;

// Initialize the CSPRNG with a 32-byte seed
void csprng_init(CSPRNG_CTX *ctx, const uint8_t seed[32]);

// Generate arbitrary-length random bytes
void csprng_random(CSPRNG_CTX *ctx, uint8_t *out, size_t out_len);

// Generate single 32-bit random integer
uint32_t csprng_random32(CSPRNG_CTX *ctx);

// Generate single 64-bit random integer
uint64_t csprng_random64(CSPRNG_CTX *ctx);

// Random integer in [0, max-1] without modulo bias
uint32_t csprng_uniform(CSPRNG_CTX *ctx, uint32_t max);

// Convert random bytes to hex string (out buffer must be 2*bytes+1)
void csprng_bytes_hex(CSPRNG_CTX *ctx, char *out, size_t bytes);

// Random float in [0,1)
float csprng_random_float(CSPRNG_CTX *ctx);

// Random double in [0,1)
double csprng_random_double(CSPRNG_CTX *ctx);

// Shuffle an array of any type (elem_size in bytes)
void csprng_shuffle(void *array, size_t n, size_t elem_size, CSPRNG_CTX *ctx);

// Random float with normal distribution (mean=0, stddev=1)
float csprng_random_normal(CSPRNG_CTX *ctx);

// Generate random string of length len from charset (null-terminated)
void csprng_random_string(CSPRNG_CTX *ctx, char *out, size_t len, const char *charset);

#ifdef __cplusplus
}
#endif

#endif // CSPRNG_H