/* Copyright (c) 2015-2017, Pelayo Bernedo.
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



#include "misc.hpp"
#include "blake2.hpp"
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <fstream>
#include <stdexcept>
#include <limits>
#include <iomanip>
#include <sstream>


#ifndef _WIN32
#include <unistd.h>
#endif


namespace amber {    namespace AMBER_SONAME {


int crypto_neq(const void *vp1, const void *vp2, size_t n)
{
	const unsigned char *v1 = (const unsigned char*)vp1;
	const unsigned char *v2 = (const unsigned char*)vp2;
	unsigned diff = 0;
	size_t i;
	for (i = 0; i < n; ++i) {
		diff |= v1[i] ^ v2[i];
	}
	// Only the lower 8 bits may be non zero. diff-1 will have the high bit
	// set only and only if diff was zero.
	diff = (diff - 1) >> (sizeof(unsigned)*CHAR_BIT - 1);
	return diff ^ 1;
}


int is_zero(const void *vp1, size_t n)
{
	const unsigned char *v1 = (const unsigned char*)vp1;
	unsigned diff = 0;
	size_t i;
	for (i = 0; i < n; ++i) {
		diff |= v1[i];
	}

	diff = (diff - 1) >> (sizeof(unsigned)*CHAR_BIT - 1);
	return diff;
}



void crypto_bzero(void *p, size_t n)
{
	char *pc = (char*)p;
	while (n > 0) {
		*pc++ = 0;
		--n;
	}
}





// Encoding in base 32. Not case sensitive and readable over the phone.

// Endoding of RFC 4648
static const char letters_enc[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
static char letters_low[32];
static int8_t letters_dec[256];

namespace {

struct Fill_dec_table {
	Fill_dec_table();
};

Fill_dec_table::Fill_dec_table()
{
	for (unsigned i = 0; i < sizeof(letters_dec)/sizeof(letters_dec[0]); ++i) {
		letters_dec[i] = -1;
	}
	for (unsigned i = 0; i < sizeof(letters_enc) - 1; ++i) {
		letters_dec[(unsigned char)toupper(letters_enc[i])] = i;
		letters_dec[(unsigned char)tolower(letters_enc[i])] = i;
	}
	for (unsigned i = 0; i < sizeof(letters_low); ++i) {
		letters_low[i] = tolower(letters_enc[i]);
	}
}

}

static Fill_dec_table initer;


void base32enc(const uint8_t *by, size_t nbytes, std::string &s, bool sep,
               bool terminators, bool lowercase)
{
	const char *letters = lowercase ? letters_low : letters_enc;
	size_t equals = nbytes % 5;
	if (equals != 0) {
		equals = 5 - equals;
	}
	s.clear();
	uint32_t x = *by++;
	int nbits = 8;
	--nbytes;
	int group_count = sep ? 0 : std::numeric_limits<int>::min();
	while (nbits >= 5) {
		uint32_t v = (x >> (nbits - 5)) & 0x1F;
		s.push_back(letters[v]);
		if (++group_count == 4) {
			s.push_back(' ');
			group_count = 0;
		}
		nbits -= 5;
		if (nbits < 5 && nbytes > 0) {
			x = (x << 8) | *by;
			++by;
			--nbytes;
			nbits += 8;
		}
	}

	if (nbits > 0) {
		uint32_t v = (x << (5 - nbits)) & 0x1F;
		s.push_back(letters[v]);
	}
	if (equals && terminators) {
		while (equals--) {
			s.push_back('=');
		}
	}
}


int base32dec(const char *s, std::vector<uint8_t> &v, ptrdiff_t n)
{
	v.clear();
	uint32_t cumul = 0;
	int nbits = 0;
	if (n == -1) {
		n = std::numeric_limits<ptrdiff_t>::max();
	}

	while (*s && n > 0) {
		--n;
		if (*s == ' ' || *s == '=') {
			++s;
			continue;
		}
		unsigned char idx = *s++;
		int val = letters_dec[idx];
		if (val < 0) {
			return -1;
		}
		cumul = (cumul << 5) | val;
		nbits += 5;
		if (nbits >= 8) {
			unsigned x = (cumul >> (nbits - 8)) & 0xFF;
			v.push_back(x);
			nbits -= 8;
		}
	}
	return 0;
}



// Base 64 encoding.


static const char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
						"abcdefghijklmnopqrstuvwxyz"
						"0123456789+/";


inline void base64_add_three(const uint32_t beval, std::string *dest)
{
	dest->push_back(base64[beval >> 18]);
	dest->push_back(base64[(beval >> 12) & 0x3F]);
	dest->push_back(base64[(beval >> 6) & 0x3F]);
	dest->push_back(base64[beval & 0x3F]);
}

inline void base64_add_three(unsigned char b0, unsigned char b1,
                             unsigned char b2, std::string *dest)
{
	uint32_t beval = (uint32_t(b0) << 16) | (uint32_t(b1) << 8) | b2;
	base64_add_three (beval, dest);
}




void base64enc(const unsigned char *bytes, size_t nbytes,
               std::string &dest, bool wrap, bool terminators)
{
	int cols = 0;

	dest.clear();
	while (nbytes >= 3) {
		// Big endian representation of the first 3 bytes.
		uint32_t three_bytes = (uint32_t(bytes[0]) << 16)
				| (uint32_t(bytes[1]) << 8) | bytes[2];

		base64_add_three(three_bytes, &dest);

		if (wrap) {
			cols += 4;
			if (cols >= 72) {
				dest.push_back('\n');
				cols = 0;
			}
		}
		bytes += 3;
		nbytes -= 3;
	}

	if (nbytes == 1) {
		dest.push_back(base64[bytes[0] >> 2]);
		dest.push_back(base64[(bytes[0] & 3) << 4]);
		if (terminators) {
			dest.push_back('=');
			dest.push_back('=');
		}
	} else if (nbytes == 2) {
		dest.push_back(base64[bytes[0] >> 2]);
		dest.push_back(base64[((bytes[0] << 4) | (bytes[1] >> 4)) & 0x3F]);
		dest.push_back(base64[((bytes[1] & 0xF) << 2) & 0x3F]);
		if (terminators) {
			dest.push_back('=');
		}
	}
}



void base64dec(const char *s, std::vector<unsigned char> &v, size_t n)
{
	uint32_t val, cumul = 0;
	int pending = 4;

	v.clear();

	while (n > 0 && *s) {
		if (*s >= 'A' && *s <= 'Z') {
			val = *s - 'A';
		} else if (*s >= 'a'&& *s <= 'z') {
			val = *s - 'a' + 26;
		} else if (*s >= '0' && *s <= '9') {
			val = *s - '0' + 52;
		} else if (*s == '+') {
			val = 62;
		} else if (*s == '/') {
			val = 63;
		} else if (*s == '=') {
			break;
		} else {
			++s;
			--n;
			continue;
		}
		++s;
		--n;
		cumul = (cumul << 6) | val;
		if (--pending == 0) {
			v.push_back (cumul >> 16);
			v.push_back ((cumul >> 8) & 0xFF);
			v.push_back (cumul & 0xFF);
			pending = 4;
			cumul = 0;
		}
	}

	if (pending == 1) {
		// We read 3 base64s. We have 18 bits in cumul.
		v.push_back (cumul >> 10);
		v.push_back ((cumul >> 2) & 0xFF);
	} else if (pending == 2) {
		// We have 2 base64s. We have 12 bits in cumul.
		v.push_back (cumul >> 4);
	} else if (pending == 3) {
		// Can't happen. Ignore it.
	}
}


void Base64_encoder::encode_append(const unsigned char *bytes, size_t nbytes, std::string *dest)
{
	if (nbytes == 0) return;

	if (rembytes == 2) {
		base64_add_three(b1, b2, bytes[0], dest);
		cols += 4;
		if (cols >= 68) {
			dest->push_back('\n');
			cols = 0;
		}
		++bytes;
		--nbytes;
		rembytes = 0;
	} else if (rembytes == 1) {
		if (nbytes == 1) {
			b2 = bytes[0];
			rembytes = 2;
			return;
		} else {
			base64_add_three(b1, bytes[0], bytes[1], dest);
			cols += 4;
			if (cols >= 68) {
				dest->push_back('\n');
				cols = 0;
			}
			rembytes = 0;
			bytes += 2;
			nbytes -= 2;
		}
	}

	while (nbytes >= 3) {
		base64_add_three(bytes[0], bytes[1], bytes[2], dest);
		cols += 4;
		if (cols >= 68) {
			dest->push_back('\n');
			cols = 0;
		}
		bytes += 3;
		nbytes -= 3;
	}

	if (nbytes == 1) {
		rembytes = 1;
		b1 = bytes[0];
	} else if (nbytes == 2) {
		rembytes = 2;
		b1 = bytes[0];
		b2 = bytes[1];
	}
}


void Base64_encoder::flush_append(std::string *dest)
{
	if (rembytes == 1) {
		dest->push_back (base64[b1 >> 2]);
		dest->push_back (base64[(b1 & 3) << 4]);
		dest->push_back ('=');
		dest->push_back ('=');
	} else if (rembytes == 2) {
		dest->push_back (base64[b1 >> 2]);
		dest->push_back (base64[((b1 << 4) | (b2 >> 4)) & 0x3F]);
		dest->push_back (base64[((b2 & 0xF) << 2) & 0x3F]);
		dest->push_back ('=');
	}
}


bool Base64_decoder::decode_append(const char *s, size_t n, std::vector<unsigned char> *v)
{
	uint32_t val = 0;

	while (n > 0) {
		if (*s >= 'A' && *s <= 'Z') {
			val = *s - 'A';
		} else if (*s >= 'a'&& *s <= 'z') {
			val = *s - 'a' + 26;
		} else if (*s >= '0' && *s <= '9') {
			val = *s - '0' + 52;
		} else if (*s == '+') {
			val = 62;
		} else if (*s == '/') {
			val = 63;
		} else if (*s == '=') {
			break;
		} else {
			++s;
			--n;
			continue;
		}
		++s;
		--n;
		cumul = (cumul << 6) | val;
		if (--pending == 0) {
			v->push_back (cumul >> 16);
			v->push_back ((cumul >> 8) & 0xFF);
			v->push_back (cumul & 0xFF);
			pending = 4;
			cumul = 0;
		}
	}
	return *s == '=';
}



void Base64_decoder::flush_append (std::vector<unsigned char> *v)
{
	if (pending == 1) {
		// We read 3 base64s. We have 18 bits in cumul.
		v->push_back (cumul >> 10);
		v->push_back ((cumul >> 2) & 0xFF);
	} else if (pending == 2) {
		// We have 2 base64s. We have 12 bits in cumul.
		v->push_back (cumul >> 4);
	} else if (pending == 3) {
		// Can't happen. Ignore it.
	}
}



// Just show a block of bytes in hexadecimal notation, with grouping.

void show_block(std::ostream &os, const char *label, const void *vb, size_t nbytes, int group)
{
	const uint8_t *b = (const uint8_t*)vb;
	os << label << ": ";
	os << std::hex << std::uppercase << std::setfill ('0') << std::noshowbase;
	for (unsigned i = 0; i < nbytes; ++i) {
		os << std::setw(2) << unsigned(*b++);
		if (int(i) % group == group-1) os << " ";
	}
	os << std::dec << std::setfill (' ') << std::nouppercase << '\n';
}

// Write an hexadecimal block.

void write_block(std::string &dst, const void *vb, size_t nbytes)
{
	std::ostringstream os;
	const uint8_t *b = (const uint8_t*)vb;
	os << std::hex << std::setfill ('0') << std::noshowbase << std::uppercase;
	for (unsigned i = 0; i < nbytes; ++i) {
		os << std::setw(2) << unsigned(*b++);
		if (i % 4 == 3) os << " ";
	}
	dst = os.str();
}

inline int hexval(char c)
{
	if ('0' <= c && c <= '9') {
		return c - '0';
	} else if ('a' <= c && c <= 'f') {
		return c - 'a' + 10;
	} else if ('A' <= c && c <= 'F') {
		return c - 'A' + 10;
	} else {
		return -1;
	}
}




ptrdiff_t read_block(const char *in, const char **next, std::vector<uint8_t> &dst)
{
	dst.clear();
	unsigned char val;
	int xval;
	size_t res = 0;
	while (*in) {
		while (isspace(*in)) ++in;
		xval = hexval(*in++);
		if (xval == -1) {
			*next = in - 1;
			return res;
		}
		val = xval << 4;
		while (isspace(*in)) ++in;
		xval = hexval(*in++);
		if (xval == -1) return -1;
		val |= xval;
		dst.push_back(val);
	}
	*next = in;
	return res;
}

#ifdef _WIN32


void get_password (const char *prompt, std::string &pass)
{
	std::cout << prompt << " ";
	getline (std::cin, pass);
}

#else


void get_password(const char *prompt, std::string &pass)
{
	pass = getpass(prompt);
}

#endif

template <class It>
static uint8_t divmod58(It beg, It end)
{
	unsigned rem = 0;
	while (beg != end) {
		unsigned tmp = rem * 256 + *beg;
		*beg = tmp / 58;
		rem = tmp % 58;
		++beg;
	}
	return rem;
}

static uint8_t divmod256(uint8_t *num, size_t len)
{
	unsigned rem = 0;
	for (unsigned i = 0; i < len; ++i) {
		unsigned tmp = rem * 58 + num[i];
		num[i] = tmp / 256;
		rem = tmp % 256;
	}
	return rem;
}

static const unsigned char symbols[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static unsigned char values[256];

struct Init_values {
	Init_values();
};

Init_values::Init_values()
{
	memset(values, 255, sizeof values);
	for (unsigned i = 0; i < sizeof symbols; ++i) {
		values[symbols[i]] = i;
	}
}
static Init_values init_values;


void base58enc(const uint8_t *num, size_t nsize, std::string &res)
{
	std::vector<uint8_t> copy(nsize);
	memcpy(&copy[0], num, nsize);
	res.clear();

	int leading_zeros = 0;
	std::vector<uint8_t>::iterator beg = copy.begin();
	std::vector<uint8_t>::iterator lim = copy.end();
	std::string tmp;
	while (beg < lim && *beg == 0) {
		leading_zeros++;
		res.push_back('1');
		++beg;
	}
	while (beg < lim) {
		uint8_t val = divmod58(beg, lim);
		tmp.push_back(symbols[val]);
		if (*beg == 0) ++beg;
	}
	res.append(tmp.rbegin(), tmp.rend());
}

void base58dec(const char *s, std::vector<uint8_t> &res, size_t n)
{
	std::vector<uint8_t> input;
	const unsigned char *us = (const unsigned char*)s;
	while (n > 0 && *us) {
		if (values[*us] <= 58) {
			input.push_back(values[*us]);
		}
		++us;
		--n;
	}

	res.clear();
	int leading_zeros = 0;
	uint8_t *beg = &input[0];
	uint8_t *lim = &input[input.size()];
	std::vector<uint8_t> tmp;
	while (beg < lim && *beg == 0) {
		leading_zeros++;
		res.push_back(0);
		++beg;
	}
	while (beg < lim) {
		unsigned u = divmod256(beg, lim - beg);
		tmp.push_back(u);
		if (*beg == 0) ++beg;
	}
	auto i = tmp.rbegin();
	auto e = tmp.rend();
	while (i != e && *i == 0) ++i;
	while (i != e) res.push_back(*i++);
}


static uint_fast32_t crc_table[] = {
			 0, 0x77073096, 0xee0e612c, 0x990951ba,  0x76dc419, 0x706af48f,
	0xe963a535, 0x9e6495a3,  0xedb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	 0x9b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
	0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
	0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
	0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
	0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190,  0x1db7106,
	0x98d220bc, 0xefd5102a, 0x71b18589,  0x6b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2,  0xf00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb,  0x86d3d2d,
	0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
	0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
	0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
	0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
	0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6,  0x3b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af,  0x4db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
	 0xd6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d,  0xa00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
	0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
	0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
	0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
	0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c,  0x26d930a, 0x9c0906a9, 0xeb0e363f,
	0x72076785,  0x5005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae,  0xcb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7,  0xbdbdf21, 0x86d3d2d4, 0xf1d4e242,
	0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
	0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
	0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
	0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};



uint_fast32_t update_crc32(const void *buf, size_t nbytes, uint_fast32_t crc)
{
	crc ^= 0xffffffffL;
	const uint_least8_t *bytes = static_cast<const uint_least8_t*>(buf);
	while (nbytes-- > 0) {
		crc = crc_table[(crc ^ *bytes++) & 0xff] ^ (crc >> 8);
	}
	return crc ^ 0xffffffffL;
}


// Write an unsigned 64 bit value in LEB128 format. Up to 10 bytes required.
size_t write_uleb (uint64_t u, uint8_t *buf)
{
	uint8_t lb;
	uint8_t *wp = buf;

	lb = u & 0x7F;
	u >>= 7;

	while (u) {
		*wp++ = lb | 0x80;
		lb = u & 0x7F;
		u >>= 7;
	}
	*wp++ = lb;

	return wp - buf;
}

// Read a LEB128 from sbuf[0..lim[ and store the value in u. Return the
// number of bytes read or -1 if there was an error.
ptrdiff_t read_uleb (uint64_t *u, const uint8_t *buf, size_t lim)
{
	if (lim > 10) lim = 10;

	uint64_t val = 0;
	unsigned shifts = 0;
	unsigned count = 0;
	unsigned llim = lim > 9 ? 9 : lim;
	uint8_t ch;

	while (count < llim) {
		ch = *buf++;
		val |= uint64_t(ch & 0x7F) << shifts;
		shifts += 7;
		++count;
		if ((ch & 0x80) == 0) {
			*u = val;
			return count;
		}
	}
	if (count == 9 && lim > 9) {
		if (ch <= 1) {
			val |= uint64_t(ch) << shifts;
			*u = val;
			return 10;
		}
	}
	return -1;
}


}}

