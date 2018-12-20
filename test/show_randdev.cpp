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

#include "symmetric.hpp"
#include "misc.hpp"
#include <fstream>
#include <random>
#include <string.h>

// Get random bytes from /dev/urandom. Return 0 on success.
static int read_urandom(void *vp, size_t n)
{
	std::ifstream is;
	is.rdbuf()->pubsetbuf(0, 0);    // Make it non buffered.
	is.open("/dev/urandom", is.binary);
	if (!is) {
		return -1;
	}
	is.read((char*)vp, n);
	if (is.gcount() != std::streamsize(n)) {
		return -1;
	}
	return 0;
}

static void cxx_random_device(void *vp, size_t n)
{
	static std::random_device rd;
	typedef std::random_device::result_type Re; // C++11 defines this to be unsigned int.

	// C++11 also defined rd.min() to be 0 and rd.max() to be UINT_MAX.
	uint8_t *dest = (uint8_t*) vp;
	Re v;
	while (n > sizeof(v)) {
		v = rd();
		memcpy (dest, &v, sizeof v);
		n -= sizeof v;
		dest += sizeof v;
	}
	if (n > 0) {
		v = rd();
		memcpy(dest, &v, n);
	}
}

int main()
{
	uint8_t b[32];

	cxx_random_device (b, sizeof b);
	amber::show_block (std::cout, "RD", b, sizeof b);

	read_urandom (b, sizeof b);
	amber::show_block (std::cout, "UR", b, sizeof b);

	amber::Keyed_random kr;
	kr.get_bytes (b, sizeof b);
	amber::show_block (std::cout, "KR", b, sizeof b);

	amber::randombytes_buf (b, sizeof b);
	amber::show_block (std::cout, "RB", b, sizeof b);

}

