#ifndef DH_H
#define DH_H

#include <stdint.h>
#include <stddef.h>
#include "bignum.h"
#include "..\csprng\csprng.h"

#define DH_KEY_BYTES 256   /* 2048 bits */

typedef struct {
    BigNum p;              /* prime modulus  */
    BigNum g;              /* generator      */
    BigNum private_key;
    BigNum public_key;
} DH_CTX;

/* Use RFC 3526 Group 14 (2048-bit MODP). Returns 0 on success. */
int  dh_init_group14(DH_CTX *ctx);

/* Generate a fresh keypair using the provided CSPRNG. */
void dh_generate_keys(DH_CTX *ctx, CSPRNG_CTX *rng);

/*
 * Compute shared secret from peer's public key bytes.
 * Validates peer_public before use.
 * Writes DH_KEY_BYTES into out_secret.
 * Returns 0 on success, -1 if peer key is invalid.
 */
int  dh_shared_secret(DH_CTX *ctx,
                      const uint8_t *peer_public, size_t peer_len,
                      uint8_t *out_secret);

/* Serialise our public key to DH_KEY_BYTES big-endian bytes. */
void dh_export_public(const DH_CTX *ctx, uint8_t *out, size_t len);

#endif