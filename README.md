
---

# XPCrypt32

**Modern Cryptography for Windows XP – AES, ChaCha20-Poly1305, SHA-2, HKDF & CSPRNG in Pure C**

---

## Overview

XPCrypt32 brings modern cryptographic primitives to Windows XP and other legacy systems. Written in **pure C**, it works seamlessly on 32-bit Windows without external dependencies.

**Features include:**

* AES (ECB, CBC, CTR, OFB, XTS)
* ChaCha20-Poly1305 authenticated encryption
* SHA-2 (SHA-256) hashing
* HMAC-SHA256
* HKDF (SHA-256 and SHA-512)
* Full-featured, deterministic **CSPRNG** with:

  * Arbitrary-length byte generation
  * 32-bit and 64-bit integers
  * Uniform integers and floats/doubles
  * Normal distribution sampling
  * Array shuffling
  * Random strings from custom charsets

---

## Installation

Simply include the headers and source files in your project:

```c
#include "csprng.h"
#include "aes.h"      // if AES implementation included
```

ChaCha20-Poly1305 has multiple headers, including:
```c
#include "chacha20.h"
#include "poly1305.h"
#include "chacha20_poly1305.h"
```
> chacha20.h declares:

- chacha20_init, 
- chacha20_keystream 
- chacha20_crypt

poly1305.h declares:

- poly1305_init
- poly1305_update
- poly1305_finish

and finally, chacha20_poly1305.h declares:

- chacha20_poly1305_encrypt
- chacha20_poly1305_decrypt

Compile with **Visual Studio 2005/2008** or any standard C compiler compatible with XP.

---

## Example Usage

### Initialize CSPRNG

```c
#include "csprng.h"

int main() {
    uint8_t seed[32] = {0}; // use a real 32-byte seed
    CSPRNG_CTX rng;
    csprng_init(&rng, seed);

    uint32_t random_number = csprng_random32(&rng);
    printf("Random number: %u\n", random_number);

    char rand_str[16];
    csprng_random_string(&rng, rand_str, 16, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
    printf("Random string: %s\n", rand_str);
    
    return 0;
}
```

---

## API Highlights

**CSPRNG Functions:**

* `csprng_init(seed)` – Seed the generator
* `csprng_random(ctx, buf, len)` – Generate arbitrary bytes
* `csprng_random32(ctx)` / `csprng_random64(ctx)` – Random integers
* `csprng_uniform(ctx, max)` – Bounded integers
* `csprng_random_float(ctx)` / `csprng_random_double(ctx)` – Random floats
* `csprng_shuffle(array, n, size, ctx)` – Shuffle array
* `csprng_random_normal(ctx)` – Normal distribution
* `csprng_random_string(ctx, out, len, charset)` – Random strings

**HKDF & HMAC Functions:**

* `hmac_sha256(key, key_len, data, data_len, out)`
* `hkdf(salt, salt_len, ikm, ikm_len, info, info_len, okm, okm_len)`

---

## Security Notes

* Deterministic: Using the same 32-byte seed produces the same stream.
* Security depends on **high-entropy seeding**. On XP, gathering entropy may require external sources.
* Not recommended for modern production unless combined with proper entropy sources.

---

## License

MIT License – free to use, modify, and distribute.

---