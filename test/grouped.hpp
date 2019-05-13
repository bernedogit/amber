#ifndef GROUPED_H                               
#define GROUPED_H

#include <stddef.h>

namespace grouped {

struct Ed25519_pub {
	unsigned char bytes[32];
};

struct Ed25519_sec {
	unsigned char bytes[64];
};

struct Ed25519_signature {
	unsigned char bytes[64];
};

// Create a private 64-byte key using the 32-byte seed.
void ed25519_seed2private (const unsigned char seed[32], Ed25519_sec *sec);

// Create a key pair from the seed.
void ed25519_create_keys (Ed25519_pub *pub, Ed25519_sec *sec, const unsigned char seed[32]);

void ed25519_sign (Ed25519_signature *rs,
                   const void *message, size_t message_len,
                   const Ed25519_pub *pub, const Ed25519_sec *sec);

// Return true if ok.
int ed25519_verify_ok (const Ed25519_signature *rs,
                       const void *message, size_t message_len,
                       const Ed25519_pub *pub); 

void ed25519_add_scalar(Ed25519_pub *public_key, Ed25519_sec *private_key,
                        const unsigned char scalar[32]);

void ed25519_dh (unsigned char shared_secret[32],
                 const Ed25519_pub *pub, const Ed25519_sec *sec);


}

#endif
