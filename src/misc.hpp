#ifndef AMBER_MISC_HPP
#define AMBER_MISC_HPP

/* Copyright (c) 2015-2018, Pelayo Bernedo.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */




#ifndef __STDC_LIMIT_MACROS
	#define __STDC_LIMIT_MACROS 1
#endif
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <iosfwd>
#include "soname.hpp"
#include <vector>
#include <string.h>


// Miscellaneous support functions.



// Read little endian values from unaligned storage. GCC optimizes this to
// just a single load with bswap if required.
inline uint32_t leget32 (const void *vp)
{
	return (uint32_t(((uint8_t*)vp)[3]) << 24) |
	       (uint32_t(((uint8_t*)vp)[2]) << 16) |
	       (uint32_t(((uint8_t*)vp)[1]) << 8) |
	       ((uint8_t*)vp)[0];
}
inline uint64_t leget64 (const void *vp)
{
	return (uint64_t(((uint8_t*)vp)[7]) << 56) |
	       (uint64_t(((uint8_t*)vp)[6]) << 48) |
	       (uint64_t(((uint8_t*)vp)[5]) << 40) |
	       (uint64_t(((uint8_t*)vp)[4]) << 32) |
	       (uint64_t(((uint8_t*)vp)[3]) << 24) |
	       (uint64_t(((uint8_t*)vp)[2]) << 16) |
	       (uint64_t(((uint8_t*)vp)[1]) << 8) |
	       ((uint8_t*)vp)[0];
}

// Store little endian values in unaligned storage.

#if __BYTE_ORDER__ && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ || __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
// We know that we are big endian or little endian. Therefore the byte
// swapping that may eventually be required is the same for putting and
// getting. The following get optimized by GCC to a single mov (with bswap if
// required).
inline void leput32 (void *p, uint32_t v)
{
	v = leget32 (&v);
	memcpy (p, &v, 4);
}

inline void leput64 (void *p, uint64_t v)
{
	v = leget64 (&v);
	memcpy (p, &v, 8);
}

#else
// Generic functions that work for all byte orders, even PDP if you have one.
// However GCC does not optimize them to a single instruction.
inline void leput32 (void *p, uint32_t v)
{
	uint8_t *u = (uint8_t*)p;
	u[3] = v >> 24;
	u[2] = (v >> 16) & 0xFF;
	u[1] = (v >> 8) & 0xFF;
	u[0] = v & 0xFF;
}

inline void leput64 (void *p, uint64_t v)
{
	uint8_t *u = (uint8_t*)p;
	u[7] = v >> 56;
	u[6] = (v >> 48) & 0xFF;
	u[5] = (v >> 40) & 0xFF;
	u[4] = (v >> 32) & 0xFF;
	u[3] = (v >> 24) & 0xFF;
	u[2] = (v >> 16) & 0xFF;
	u[1] = (v >> 8) & 0xFF;
	u[0] = v & 0xFF;
}

#endif



namespace amber {    namespace AMBER_SONAME  {



// Return 0 if both byte arrays are equal. Another value if they differ. This
// works in constant time.
int crypto_neq(const void *v1, const void *v2, size_t n);

// Constant time check if v1[0..n[ is zero. Returns 1 if zero. O otherwise.
int is_zero(const void *v1, size_t n);

// Out of line version of memset(0)
void crypto_bzero(void *p, size_t n);

// Helper to perform clean up of the stack.
class Janitor {
	void *p;
	size_t n;
public:
	Janitor(void *pp, size_t nn) : p(pp), n(nn) {}
	~Janitor() { crypto_bzero (p, n); }
};




// Base 32 encoding.

// Encoding and decoding in base 32. Case insensitive encoding that avoids
// the letters 1, 0, o and l. Pass sep == true if you want to group the
// resulting string in groups of 4 letters. Encodes every 5 bytes into 8
// characters (60% expansion). For a line of 80 characters pass 50 bytes. For
// line of 72 characters pass 45bytes.
void base32enc(const uint8_t *by, size_t nbytes, std::string &s, bool sep=true,
               bool terminators=false, bool lowercase=false);
int  base32dec(const char *s, std::vector<uint8_t> &v, ptrdiff_t n=-1);


// Base 58 encoding.
void base58enc(const uint8_t *num, size_t nsize, std::string &res);
void base58dec(const char *s, std::vector<uint8_t> &res, size_t = SIZE_MAX);



// Base 64 encoding.

// Encodes every 3 bytes into 4 characters (33% expansion). For a line of 80
// characters pass 60 bytes. For a line of 72 characters pass 54 bytes.

// Encode in Base 64 into the string. Pass true to wrap if you want to wrap
// the resulting text in to lines. If you want to encode incrementally make
// sure that you allways pass a multiple of 3 for the size nbytes, except for
// the last block.
void base64enc(const unsigned char *bytes, size_t nbytes,
               std::string &dest, bool wrap, bool terminators);


// Decode the text and append it to the vector. It will not clear the vector,
// it will always append. The decoding stops when n characters have read or
// when a '=' is encountered. Non base 64 characters (A-Za-z0-9+/) are
// ignored.
void base64dec(const char *s, std::vector<unsigned char> &v, size_t n=SIZE_MAX);



// Base64 encoder. encode_append() appends text to the string dest. When you
// are finished call flush_append() to append the trailing bytes. You may at
// any time clear the string dest.
class EXPORTFN Base64_encoder {
	int cols;
	int rembytes;
	unsigned char b1, b2;

public:
	Base64_encoder() : cols(0), rembytes(0) {}
	void reset() { cols = 0; rembytes = 0; }
	void encode_append(const unsigned char *bytes, size_t nbytes,
	                   std::string *dest);
	void flush_append(std::string *dest);
};

// Base 64 decoder. decode_append() appends decoded bytes to dest.
// flush_append() is called at the end of the stream to recover the trailing
// bytes. decode_append() returns true if we have read a '=' sign, which
// ends the stream.
class EXPORTFN Base64_decoder {
	uint32_t cumul;
	int pending;
public:
	Base64_decoder() : cumul(0), pending(4) {}
	void reset() { cumul = 0;  pending = 4; }
	bool decode_append(const char *s, size_t n,
	                   std::vector<unsigned char> *dest);
	void flush_append(std::vector<unsigned char> *dest);
};


// Write and read a block as a sequence of hex digits.
void show_block(std::ostream &os, const char *label, const void *b,
                size_t nbytes, int group=4);
void write_block(std::string &dst, const void *b, size_t nbytes);
ptrdiff_t read_block(const char *in, const char **next,
                     std::vector<uint8_t> &dst);


// Get a password. On UNIX hide it.
void get_password(const char *prompt, std::string &pass);


// CRC32 as defined by 802.11, TCP, zlib and PNG. To compute the CRC32 of a
// buffer call as update_crc32(buf,count). To maintain a running count (for
// instance while outputting to a stream) use crc =
// update_crc32(buf,count,crc).
uint_fast32_t update_crc32(const void *buf, size_t nbytes,
                           uint_fast32_t crc=0);

}}

#endif

