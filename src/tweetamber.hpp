#ifndef TWEETAMBER_HPP
#define TWEETAMBER_HPP

#include "soname.hpp"
#include <stdexcept>


namespace twamber { inline namespace AMBER_SONAME {

// Hashing
typedef struct {
	uint8_t b[128];                     // input buffer
	uint64_t h[8];                      // chained state
	uint64_t t[2];                      // total number of bytes
	size_t c;                           // pointer for b[]
	size_t outlen;                      // digest size
} blake2b_ctx;

// Initialize the hashing context "ctx" with optional key "key".
//      1 <= outlen <= 64 gives the digest size in bytes.
//      Secret key (also <= 64 bytes) is optional (keylen = 0).
int  blake2b_init(blake2b_ctx *ctx, size_t outlen,
                  const void *key, size_t keylen);
void blake2b_update (blake2b_ctx *ctx, const void *in, size_t inlen);
void blake2b_final (blake2b_ctx *ctx, void *out);
int  blake2b (void *out, size_t outlen, const void *key, size_t keylen,
              const void *in, size_t inlen);
inline void blake2b_update (blake2b_ctx *ctx, uint64_t u)
{
	uint8_t x[8];
	x[0] = u & 0xFF;
	x[1] = (u >> 8) & 0xFF;
	x[2] = (u >> 16) & 0xFF;
	x[3] = (u >> 24) & 0xFF;
	x[4] = (u >> 32) & 0xFF;
	x[5] = (u >> 40) & 0xFF;
	x[6] = (u >> 48) & 0xFF;
	x[7] = (u >> 56) & 0xFF;
	blake2b_update (ctx, x, 8);
}


typedef struct {
	uint8_t b[64];                      // input buffer
	uint32_t h[8];                      // chained state
	uint32_t t[2];                      // total number of bytes
	size_t c;                           // pointer for b[]
	size_t outlen;                      // digest size
} blake2s_ctx;

int blake2s_init (blake2s_ctx *ctx, size_t outlen,
                  const void *key, size_t keylen);
void blake2s_update (blake2s_ctx *ctx, const void *in, size_t inlen);
void blake2s_final (blake2s_ctx *ctx, void *out);



// Poly1305 donna implementation.
typedef struct poly1305_context {
	size_t aligner;
	unsigned char opaque[136];
} poly1305_context;

void poly1305_init (poly1305_context *ctx, const unsigned char key[32]);
void poly1305_finish (poly1305_context *ctx, unsigned char mac[16]);
void poly1305_update (poly1305_context *ctx, const unsigned char *m, size_t bytes);

// Return 1 if equal (not equal) or 0 otherwise. Constant time.
int crypto_equal (const unsigned char *mac1, const unsigned char *mac2, size_t n);
int crypto_neq (const void *v1, const void *v2, size_t n);

// Constant time check if v1[0..n[ is zero.
int is_zero (const void *v1, size_t n);


// kn contains the state of chacha.
void chacha20 (uint8_t out[64], const uint32_t kn[12]);

// A Chacha key as 32 bit words.
struct Chakey {
	uint32_t kw[8];
};

// Convert from bytes to words.
void load (Chakey *kw, const uint8_t bytes[32]);

// Generate a chunk based on the nonce and the block number.
void chacha20 (uint8_t out[64], const Chakey &key, uint64_t n64, uint64_t bn);
void hchacha20 (Chakey *out, const uint8_t key[32], const uint8_t n[16]);

// Encrypt and decrypt using ChaChaPoly with multiple tags.
void encrypt_multi (uint8_t *cipher, const uint8_t *m, size_t mlen,
                    const uint8_t *ad, size_t alen, const Chakey &kw,
                    const Chakey *ka, size_t nka, uint64_t nonce64,
                    uint32_t ietf_sender=0);
int decrypt_multi (uint8_t *m, const uint8_t *cipher, size_t clen,
                   const uint8_t *ad, size_t alen, const Chakey &kw,
                   const Chakey &ka, size_t nka, size_t ika, uint64_t nonce64,
                   uint32_t ietf_sender=0);

void scrypt_blake2b (uint8_t *dk, size_t dklen,
                     const char *pwd, size_t plen,
                     const uint8_t *salt, size_t slen,
                     int shifts, int r=8, int p=1);

void randombytes_buf (void *buf, size_t n);


struct Cu25519Sec { uint8_t b[32]; };   // The scalar.
struct Cu25519Pub { uint8_t b[32]; };   // Point in Montgomery X format.
struct Cu25519Rep { uint8_t b[32]; };   // Elligator representative.

inline void mask_scalar (uint8_t scb[32])
{
	scb[0] &= 0xF8;    // Clear the lower 3 bits. Multiply by cofactor.
	scb[31] &= 0x7F;   // Clear the bit 255, not used.
	scb[31] |= 0x40;   // Set the most significant bit.
}

void cu25519_generate (Cu25519Sec *xs, Cu25519Pub *xp);

// You must use mix_key() to convert the shared secret to a key. Best used
// with one of the Noise protocol patterns.
void cu25519_shared_secret (uint8_t sh[32], const Cu25519Pub &xp, const Cu25519Sec &xs);

void cu25519_sign (const char *prefix, const uint8_t *m, size_t mlen,
                   const Cu25519Pub &xp, const Cu25519Sec &xs,
                   uint8_t sig[64]);
int cu25519_verify (const char *prefix, const uint8_t *m, size_t mlen,
                    const uint8_t sig[64], const Cu25519Pub &xp);

void cu25519_elligator2_gen (Cu25519Sec *xs, Cu25519Pub *xp, Cu25519Rep *rep);
void cu25519_elligator2_rev (Cu25519Pub *u, const Cu25519Rep & rep);



// Noise protocol support. Maintain the chaining key, the running hash and
// the encryption key.
void mix_hash_init (uint8_t ck[32], uint8_t h[32], const char *protocol,
                    const uint8_t *pro, size_t plen);
void mix_hash (uint8_t h[32], const uint8_t *data, size_t n);

class Hmac {
	blake2s_ctx b;
	uint8_t key[64];
public:
	Hmac() {}
	Hmac(const uint8_t k[32]) { reset (k); }
	void reset (const uint8_t k[32]);
	void update (const uint8_t *data, size_t n) { blake2s_update (&b, data, n); }
	void final (uint8_t h[32]);
};

void mix_key (uint8_t ck[32], uint8_t k[32], const uint8_t *ikm, size_t n);
// To split call mix_key (ck, k, NULL, 0). ck is the initiator's key and k is
// the responder's key.

// Use this when you do not need the second key.
void mix_key (uint8_t ck[32], const uint8_t *ikm, size_t n);


inline void leput32(unsigned char *p, const uint32_t v)
{
	p[0] = (unsigned char)(v      );
	p[1] = (unsigned char)(v >>  8);
	p[2] = (unsigned char)(v >> 16);
	p[3] = (unsigned char)(v >> 24);
}
inline uint32_t leget32(const unsigned char *p)
{
	return
	(((uint32_t)(p[0])      ) |
	 ((uint32_t)(p[1]) <<  8) |
	 ((uint32_t)(p[2]) << 16) |
	 ((uint32_t)(p[3]) << 24));
}

}}


#endif

