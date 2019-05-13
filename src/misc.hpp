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
// just a single load.
inline uint16_t leget16 (const void *vp)
{
	return uint16_t(((uint8_t*)vp)[1]) << 8 | ((uint8_t*)vp)[0];
}
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

inline int is_big_endian()
{
	union {
		uint32_t i;
		char b[4];
	} u = {0x01020304};

	return u.b[0] == 1;
}


inline uint64_t byte_swap_64 (uint64_t value)
{
	// Compiled into a single bswap instruction by GCC.
	return  ((value & 0xFF00000000000000u) >> 56u) |
	        ((value & 0x00FF000000000000u) >> 40u) |
	        ((value & 0x0000FF0000000000u) >> 24u) |
	        ((value & 0x000000FF00000000u) >>  8u) |
	        ((value & 0x00000000FF000000u) <<  8u) |
	        ((value & 0x0000000000FF0000u) << 24u) |
	        ((value & 0x000000000000FF00u) << 40u) |
	        ((value & 0x00000000000000FFu) << 56u);
}

// Optimized by GCC to a single mov.
inline void leput64 (void *dest, uint64_t value)
{
	if (is_big_endian()) {
		value = byte_swap_64 (value);
	}
	memcpy (dest, &value, sizeof(uint64_t));
}

inline uint32_t byte_swap_32 (uint32_t x)
{
	// Compiled into a bswap instruction by GCC.
	return ((x & 0x000000FF) << 24) |
	       ((x & 0x0000FF00) << 8)  |
	       ((x & 0x00FF0000) >> 8)  |
	       ((x & 0xFF000000) >> 24);
}

inline void leput32 (void *dest, uint32_t value)
{
	if (is_big_endian()) {
		value = byte_swap_32 (value);
	}
	memcpy (dest, &value, sizeof (uint32_t));
}

inline void leput16 (void *dest, uint16_t value)
{
	((uint8_t*)dest)[0] = value & 0xFF;
	((uint8_t*)dest)[1] = value >> 8;
}




namespace amber {    namespace AMBER_SONAME  {



// Return 0 if both byte arrays are equal. Another value if they differ. This
// works in constant time.
EXPORTFN int crypto_neq(const void *v1, const void *v2, size_t n);

// Constant time check if v1[0..n[ is zero. Returns 1 if zero. O otherwise.
EXPORTFN int is_zero(const void *v1, size_t n);

// Out of line version of memset(0)
EXPORTFN void crypto_bzero(void *p, size_t n);

// Helper to perform clean up of the stack.
class EXPORTFN Janitor {
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
EXPORTFN
void base32enc(const uint8_t *by, size_t nbytes, std::string &s, bool sep=true,
               bool terminators=false, bool lowercase=false);

EXPORTFN
int base32dec(const char *s, std::vector<uint8_t> &v, ptrdiff_t n=-1);


// Base 58 encoding.
EXPORTFN void base58enc(const uint8_t *num, size_t nsize, std::string &res);
EXPORTFN void base58dec(const char *s, std::vector<uint8_t> &res, size_t = SIZE_MAX);



// Base 64 encoding.

// Encodes every 3 bytes into 4 characters (33% expansion). For a line of 80
// characters pass 60 bytes. For a line of 72 characters pass 54 bytes.

// Encode in Base 64 into the string. Pass true to wrap if you want to wrap
// the resulting text in to lines. If you want to encode incrementally make
// sure that you allways pass a multiple of 3 for the size nbytes, except for
// the last block.
EXPORTFN
void base64enc(const unsigned char *bytes, size_t nbytes,
               std::string &dest, bool wrap, bool terminators);


// Decode the text and append it to the vector. It will not clear the vector,
// it will always append. The decoding stops when n characters have read or
// when a '=' is encountered. Non base 64 characters (A-Za-z0-9+/) are
// ignored.
EXPORTFN
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
EXPORTFN
void show_block(std::ostream &os, const char *label, const void *b,
                size_t nbytes, int group=4);

EXPORTFN
void write_block(std::string &dst, const void *b, size_t nbytes);

// Read from in and store in dst. Store in *next the pointer to the next non
// hex character in in (may be the terminating null). It skips spaces.
EXPORTFN
ptrdiff_t read_block(const char *in, const char **next,
                     std::vector<uint8_t> &dst);


// Get a password. On UNIX hide it.
EXPORTFN
void get_password(const char *prompt, std::string &pass);


// CRC32 as defined by 802.11, TCP, zlib and PNG. To compute the CRC32 of a
// buffer call as update_crc32(buf,count). To maintain a running count (for
// instance while outputting to a stream) use crc =
// update_crc32(buf,count,crc).
EXPORTFN
uint_fast32_t update_crc32(const void *buf, size_t nbytes,
                           uint_fast32_t crc=0);

// Write u in LEB128 format to buf. Return the number of bytes written.
EXPORTFN size_t    write_uleb (uint64_t u, uint8_t *buf);
// Read a LEB128 from sbuf up to lim bytes and store it in *u. Return the
// number of bytes read or -1 if there was an error.
EXPORTFN ptrdiff_t read_uleb (uint64_t *u, const uint8_t *sbuf, size_t lim=10);


// Conversion between signed and unsigned forms.
inline uint64_t i64tozigzag (int64_t i)
{
	enum { scount = 64 - 1 };
	return  (i << 1) ^ (i >> scount);
}

inline int64_t zigzagtoi64 (uint64_t u)
{
	int64_t sbit = u & 1;
	return int64_t(u >> 1) ^ (-sbit);
}

inline uint32_t i32tozigzag (int32_t i)
{
	enum { scount = 32 - 1 };
	return  (i << 1) ^ (i >> scount);
}

inline int32_t zigzagtoi32 (uint32_t u)
{
	int32_t sbit = u & 1;
	return int32_t(u >> 1) ^ (-sbit);
}




}}

#endif

