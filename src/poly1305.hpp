#ifndef AMBER_POLY1305_HPP
#define AMBER_POLY1305_HPP


/*
	Public domain by Andrew M. <liquidsun@gmail.com>

	Poly1305-donna.
*/


#ifndef __STDC_LIMIT_MACROS
	#define __STDC_LIMIT_MACROS 1
#endif
#include <stddef.h>
#include <stdint.h>

#include "soname.hpp"


namespace amber {   namespace AMBER_SONAME {


// Poly-1305 one time authentication. Donna implementation from Floodyberry.

typedef struct poly1305_context {
	size_t aligner;
	unsigned char opaque[136];
} poly1305_context;


EXPORTFN void poly1305_init (poly1305_context *ctx, const unsigned char key[32]);
EXPORTFN void poly1305_update (poly1305_context *ctx, const unsigned char *m, size_t bytes);
EXPORTFN void poly1305_finish (poly1305_context *ctx, unsigned char mac[16]);

// This combines init/update/finish.
EXPORTFN
void poly1305_auth (unsigned char mac[16], const unsigned char *m, size_t bytes,
                    const unsigned char key[32]);

// Constant time comparison. Return 1 or 0, no other values.
EXPORTFN int crypto_equal (const unsigned char *x, const unsigned char *y, size_t len);

class EXPORTFN Poly1305 {
	poly1305_context c;
public:
	Poly1305() {}
	Poly1305 (const unsigned char key[32]) { init (key); }
	void init (const unsigned char key[32]) { poly1305_init (&c, key); }
	void update (const unsigned char *m, size_t n) { poly1305_update (&c, m, n); }
	void update (const char *m, size_t n) { poly1305_update (&c, (const unsigned char*)m, n); }
	void finish (unsigned char mac[16]) { poly1305_finish (&c, mac); }
};

// Add zero padding required by previous data of n bytes.
EXPORTFN void poly1305_pad16 (poly1305_context *ctx, size_t n);
// Convert value to a little endian 8 byte sequence and add it.
EXPORTFN void poly1305_update (poly1305_context *ctx, uint64_t value);

}}

#endif
