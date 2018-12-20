#ifndef AMBER_SHA2_HPP
#define AMBER_SHA2_HPP

#include "soname.hpp"
#include <stdint.h>
#include <stddef.h>

namespace amber {   namespace AMBER_SONAME {


class EXPORTFN Sha256 {
	enum { blocklen1 = 64 };
	size_t      tot_len;
	size_t      len;
	uint8_t     block [2 * blocklen1];
	uint32_t    h[8];

	void transform (const uint8_t *message, size_t block_nb);

public:
	enum { blocklen = blocklen1, hashlen = 32 };
	Sha256 () { reset(); }
	void reset ();
	void update (const void *bytes, size_t nbytes);

	// Produce a 32 byte digest.
	void final (uint8_t digest[32]);
};


EXPORTFN
void sha256 (const void *message, size_t len, uint8_t digest[32]);




class EXPORTFN Sha512 {
	enum { blocklen1 = 128 };
	size_t          tot_len;
	size_t          len;
	unsigned char   block [2 * blocklen1];
	uint64_t        h[8];

	void transform (const uint8_t *message, size_t block_nb);

public:
	enum { blocklen = blocklen1, hashlen = 64 };
	Sha512 () { reset(); }
	void reset ();
	void update (const void *bytes, size_t nbytes);

	// Produce a 64 byte digest.
	void final (uint8_t digest[64]);
};

EXPORTFN
void sha512 (const void *message, size_t len, uint8_t digest[64]);



}}


#endif


