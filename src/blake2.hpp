#ifndef AMBER_BLAKE2_HPP
#define AMBER_BLAKE2_HPP

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "soname.hpp"

#include <iostream>
namespace amber {  namespace AMBER_SONAME {

// BLAKE2 Hashing Context and API Prototypes Taken from RFC 7693.


// state context
typedef struct {
	uint8_t b[128];                     // input buffer
	uint64_t h[8];                      // chained state
	uint64_t t[2];                      // total number of bytes
	size_t c;                           // pointer for b[]
	size_t outlen;                      // digest size
} blake2b_ctx;

struct EXPORTFN Blake2b_param {
	uint8_t  digest_length; // 1
	uint8_t  key_length;    // 2
	uint8_t  fanout;        // 3
	uint8_t  depth;         // 4
	uint32_t leaf_length;   // 8
	uint32_t node_offset;   // 12
	uint32_t xof_digest_length; // 16
	uint8_t  node_depth;    // 17
	uint8_t  inner_length;  // 18
	uint8_t  reserved[14];  // 32
	uint8_t  salt[16];      // 48
	uint8_t  personal[16];  // 64

	Blake2b_param()
		: digest_length (64)
		, key_length (0)
		, fanout (1)
		, depth (1)
		, leaf_length (0)
		, node_offset (0)
		, xof_digest_length (0)
		, node_depth (0)
		, inner_length (0)
	{
		memset (reserved, 0, sizeof reserved);
		memset (salt, 0, sizeof salt);
		memset (personal, 0, sizeof personal);
	}
};


struct EXPORTFN Blake2s_param {
	uint8_t  digest_length; // 1
	uint8_t  key_length;    // 2
	uint8_t  fanout;        // 3
	uint8_t  depth;         // 4
	uint32_t leaf_length;   // 8
	uint32_t node_offset;   // 12
	uint16_t xof_digest_length; // 14
	uint8_t  node_depth;    // 15
	uint8_t  inner_length;  // 16
	uint8_t  salt[8];       // 24
	uint8_t  personal[8];   // 32

	Blake2s_param()
		: digest_length (32)
		, key_length (0)
		, fanout (1)
		, depth (1)
		, leaf_length (0)
		, node_offset (0)
		, xof_digest_length (0)
		, node_depth (0)
		, inner_length (0)
	{
		memset (salt, 0, sizeof salt);
		memset (personal, 0, sizeof personal);
	}
};



// Initialize the hashing context "ctx" with optional key "key".
//      1 <= outlen <= 64 gives the digest size in bytes.
//      Secret key (also <= 64 bytes) is optional (keylen = 0).
EXPORTFN
int blake2b_init(blake2b_ctx *ctx, size_t outlen,
                 const void *key=0, size_t keylen=0);    // secret key

// Initialize using the full parameter block.
EXPORTFN
int blake2b_init (blake2b_ctx *ctx, size_t outlen,
                  const void *key, size_t keylen,
                  Blake2b_param *par);

// Add "inlen" bytes from "in" into the hash.
EXPORTFN
void blake2b_update (blake2b_ctx *ctx,   // context
	const void *in, size_t inlen);      // data to be hashed

// Generate the message digest (size given in init).
//      Result placed in "out".
EXPORTFN
void blake2b_final(blake2b_ctx *ctx, void *out);

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


// All-in-one convenience function.
EXPORTFN
int blake2b(void *out, size_t outlen,   // return buffer for digest
	const void *key, size_t keylen,     // optional secret key
	const void *in, size_t inlen);      // data to be hashed


typedef struct {
	uint8_t b[64];                      // input buffer
	uint32_t h[8];                      // chained state
	uint32_t t[2];                      // total number of bytes
	size_t c;                           // pointer for b[]
	size_t outlen;                      // digest size
} blake2s_ctx;



// Initialize the hashing context "ctx" with optional key "key".
//      1 <= outlen <= 32 gives the digest size in bytes.
//      Secret key (also <= 32 bytes) is optional (keylen = 0).
EXPORTFN
int blake2s_init(blake2s_ctx *ctx, size_t outlen,
    const void *key, size_t keylen);    // secret key

// Add "inlen" bytes from "in" into the hash.
EXPORTFN
void blake2s_update (blake2s_ctx *ctx,   // context
	const void *in, size_t inlen);      // data to be hashed

// Generate the message digest (size given in init).
//      Result placed in "out".
EXPORTFN
void blake2s_final (blake2s_ctx *ctx, void *out);

// All-in-one convenience function.
EXPORTFN
int blake2s(void *out, size_t outlen,   // return buffer for digest
	const void *key, size_t keylen,     // optional secret key
	const void *in, size_t inlen);      // data to be hashed


// C++ interfaces.

class EXPORTFN Blake2s {
	blake2s_ctx bl;
public:
	enum { blocklen = 64, hashlen = 32 };
	Blake2s (size_t olen=hashlen, const void *key=NULL, size_t klen=0) {
		reset (olen, key, klen);
	}
	void reset (size_t olen=hashlen, const void *key=NULL, size_t klen=0) {
		blake2s_init (&bl, olen, key, klen);
	}
	void update (const void *data, size_t n) {
		blake2s_update (&bl, data, n);
	}
	void final (void *h) {
		blake2s_final (&bl, h);
	}
};

class EXPORTFN Blake2b {
	blake2b_ctx bl;
	uint64_t count;
public:
	enum { blocklen = 128, hashlen = 64 };
	Blake2b (size_t olen=hashlen, const void *key=NULL, size_t klen=0) {
		reset (olen, key, klen);
	}
	void reset (size_t olen=hashlen, const void *key=NULL, size_t klen=0) {
		blake2b_init (&bl, olen, key, klen);
		count = 0;
	}
	void update (const void *data, size_t n, bool finish=false) {
		blake2b_update (&bl, data, n);
		count += n;
		if (finish) finish_item();
	}
	void final (void *h) {
		blake2b_final (&bl, h);
	}
	void update (uint64_t u) {
		blake2b_update (&bl, u);
	}
	// Use this to append the length of the previous object to the hash. If
	// you do this on all inputs then the input to the hash cannot be
	// constructed in this way with other, different, inputs.
	void finish_item () {
		blake2b_update (&bl, count);
		count = 0;
	}
};


// The key derivation/extension function. Reset() with the key and desired
// output length. Then feed the key material with update(). Finally call
// output() to retrieve the output. If the output is generated blockwise then
// use output_block().
class EXPORTFN Blake2xb {
	uint32_t xof_digest_length;
	uint8_t h0[64];
	blake2b_ctx bl;
	bool expanding;

public:
	Blake2xb (size_t outlen, const void *key=NULL, size_t key_len = 0) {
		reset (outlen, key, key_len);
	}
	// Outlen is the total length of the output.
	void reset (size_t outlen, const void *key=NULL, size_t key_len = 0);
	void update (const void *data, size_t n) { blake2b_update (&bl, data, n); }
	void output_block (uint32_t bn, uint8_t block[64]);
	void output (uint8_t *dest);
};


class EXPORTFN Blake2xs {
	uint32_t xof_digest_length;
	uint8_t h0[32];
	blake2s_ctx bl;
	bool expanding;

public:
	Blake2xs (size_t outlen, const void *key=NULL, size_t key_len = 0) {
		reset (outlen, key, key_len);
	}
	// Outlen is the total length of the output.
	void reset (size_t outlen, const void *key=NULL, size_t key_len = 0);
	void update (const void *data, size_t n) { blake2s_update (&bl, data, n); }
	void output_block (uint32_t bn, uint8_t block[32]);
	void output (uint8_t *dest);
};

}}                         

#endif

