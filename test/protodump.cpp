/*
 * Copyright (c) 2015-2018, Pelayo Bernedo
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

#include "protobuf.hpp"
#include <fstream>
#include <iomanip>
#include <iostream>

using namespace amber;

// Dump the contents of a Protocol Buffers file.


void prefix (int level)
{
	while (level > 0) {
		std::cout << "   ";
		--level;
	}
}

void show_head (const char *bytes, size_t n)
{
	enum { maxn = 16 };
	if (n > maxn) {
		n = maxn;
	}
	std::cout << std::hex << std::setfill ('0');
	int count = 0;
	for (unsigned i = 0; i < n; ++i) {
		std::cout << std::setw(2) << (unsigned)(unsigned char)bytes[i];
		if (++count == 4) {
			count = 0;
			std::cout << " ";
		}
	}
	std::cout << std::dec << '\n';
}


// Reads a code point using the input iterator s. It reads the current
// multibyte character and returns the input iterator pointing to the
// start of next multibyte character. If s is a istreambuf_iterator all its
// iterators will point to the start of the next multibyte character.
template <class In>
In mbtouc (char32_t *wc, In s, In end)
{
	static unsigned char headval[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
		0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
		0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
		0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
		0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0, 0, 0, 0, 0, 0, 0, 0
	};

	static signed char pending[] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
		3, 3, 3, 3, 3, 3, 3, 3, -1, -1, -1, -1, -1, -1, -1, -1
	};

	static char32_t limits[] = { 0, 0x80, 0x800, 0x10000, 0x110000 };

	if (s == end) {
		*wc = 0xFFFD;
		return s;
	}

	unsigned char val = *s;
	int ntail = pending[val];
	*wc = headval[val];
	++s;

	if (ntail == 0) {
		return s;
	}

	switch (ntail) {
	case 3:
		if (s == end) {
			*wc = 0xFFFD;
			break;
		}
		val = *s;
		if ((val & 0xC0) != 0x80) {
			*wc = 0xFFFD;
			break;
		}
		*wc = (*wc << 6) | (val & 0x3F);
		++s;
	case 2:
		if (s == end) {
			*wc = 0xFFFD;
			break;
		}
		val = *s;
		if ((val & 0xC0) != 0x80) {
			*wc = 0xFFFD;
			break;
		}
		*wc = (*wc << 6) | (val & 0x3F);
		++s;
	case 1:
		if (s == end) {
			*wc = 0xFFFD;
			break;
		}
		val = *s;
		if ((val & 0xC0) != 0x80) {
		 *wc = 0xFFFD;
			break;
		}
		*wc = (*wc << 6) | (val & 0x3F);
		++s;
		break;

	default:
		*wc = 0xFFFD;
	}

	if (*wc < limits[ntail] || (*wc & 0xFFFF800) == 0xD800) {
		*wc = 0xFFFD;
	}

	return s;
}


int ucs_validstr (const char * s, const char *limit)
{
	char32_t x;

	while (s != limit && *s != 0) {
		s = mbtouc (&x, s, limit);
		if (x == 0xFFFD) {
			return 0;
		}
	}

	return 1;
}



void show (uint32_t tag, const std::vector<char> &vc)
{
	std::cout << "id: " << tag << "  ";
	if (ucs_validstr (&vc[0], &vc[vc.size()])) {
		std::cout << vc.size() << " bytes string \"";
		size_t n = vc.size();
		if (n > 100) n = 100;
		std::cout.write (&vc[0], n);
		std::cout << "\"\n";
	} else {
		std::cout << vc.size() << " bytes: ";
		show_head (&vc[0], vc.size());
	}
}


void dump_level (Protobuf_reader &pr, int level)
{
	uint32_t tagwt;
	uint64_t u;
	std::vector<char> vc;

	while (pr.read_tagval (&tagwt, &u, level == 0)) {
		switch (tagwt & 7) {
		case varint:
		case fixed32:
		case fixed64:
			prefix (level);
			std::cout << "id: " << (tagwt >> 3) << "  value: " << u << '\n';
			break;

		case length_val:
			prefix (level);
			if (u > 500) {
				std::cout << "id: " << (tagwt >> 3) << "  " << u << " bytes\n";
				pr.skip (tagwt, u);
			} else {
				vc.resize(u);
				pr.get_bytes (&vc[0], u);
				show (tagwt >> 3, vc);
			}
			break;

		case group_len:
			prefix (level);
			std::cout << "id: " << (tagwt >> 3) << "  group start\n";
			dump_level (pr, level + 1);
			break;


		case group_start:
			prefix (level);
			std::cout << "id: " << (tagwt >> 3) << "  group start\n";
			++level;
			break;

		case group_end:
			prefix (level);
			std::cout << "group end\n";
			--level;
			break;
		}
	}
}

void dump_file (const char *name)
{
	std::ifstream is (name, is.binary);
	if (!is) {
		std::cout << "could not open the file " << name << " for reading\n";
		return;
	}

	Protobuf_reader pr (&is);
	dump_level (pr, 0);
}

int real_main (int argc, char **argv)
{
	for (int i = 1; i < argc; ++i) {
		dump_file (argv[i]);
	}
	return 0;
}

int main (int argc, char **argv)
{
	return run_main (argc, argv, real_main);
}



