/*
 * Copyright (c) 2017-2018, Pelayo Bernedo
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

#include "blockbuf.hpp"
#include "hasopt.hpp"
#include <unistd.h>
#include <math.h>

namespace amber { namespace AMBER_SONAME {

// We read one block in advance. When we write the encrypted block we have
// already read the next one. Each encrypted block is bigger than the plain
// text block and therefore at some point the block would be written beyond
// the block that has been read (and not processed yet). However if we
// select a block size that is big enough this will happen so late that no
// file will reach this size. The number of allowable blocks is (block_size
// - 56)/16. The password based header has 56 bytes and each block adds 16
// bytes of authentication tag.

void inplace_encrypt (const char *name, const char *pass, int shifts)
{
	static const int bszmin = 20000;
	std::fstream fs (name, fs.in | fs.out | fs.binary);

	fs.seekg (0, fs.end);
	std::streamoff flen = fs.tellg();
	fs.seekg (0, fs.beg);

	// Solve (bs - 56)/16 * bs >= flen
	long long bmin = (56 + ::sqrt (56*56 + 4*16*flen)) / 2 + 1;
	long long bsz = bmin > bszmin ? bmin : bszmin;

	std::vector<char> buf1 (bsz), buf2 (bsz);
	char *p1 = &buf1[0], *p2 = &buf2[0];

	fs.read (p1, bsz);
	size_t nr1 = fs.gcount();
	fs.clear();
	std::streamoff posr = fs.tellg();

	fs.seekp (0, fs.beg);
	Blockbuf bbe;
	bbe.init_write (fs.rdbuf(), pass, bsz, 0, shifts);
	std::ostream os (&bbe);
	std::streamoff posw = fs.tellp();

	while (nr1 > 0) {
		fs.seekg (posr, fs.beg);
		fs.read (p2, bsz);
		size_t nr2 = fs.gcount();
		fs.clear();
		posr = fs.tellg();

		fs.seekp (posw, fs.beg);
		os.write (p1, nr1);
		posw = fs.tellp();
		char *tmp = p1;
		p1 = p2;
		p2 = tmp;
		nr1 = nr2;
	}

	fs.seekp (posw, fs.beg);
	os.flush();
	bbe.close();

	std::string new_name(name);
	new_name += ".cha";
	rename (name, new_name.c_str());
}

void inplace_decrypt (const char *name, const char *pass, int max_shifts)
{
	enum { bsz = 10000 };
	std::fstream fs (name, fs.in | fs.out | fs.binary);

	Blockbuf bbe;
	bbe.init_read (fs.rdbuf(), pass, max_shifts);

	std::istream is (&bbe);

	char buf[bsz];
	std::streamoff posw = 0, posr = fs.tellg();

	while (!is.eof()) {
		fs.seekg (posr, fs.beg);
		is.read (buf, bsz);
		posr = fs.tellg();
		size_t nr = is.gcount();

		fs.seekp (posw, fs.beg);
		fs.write (buf, nr);
		posw = fs.tellp();
	}
	bbe.close();
	fs.close();
	int errc = truncate (name, posw);
	if (errc != 0) {
		throw_rte (_("Cannot truncate the file %s to %d bytes. Aborting.\n"),
		        name, posw);
	}
	size_t nl = strlen (name);
	if (nl > 4 && strcmp(name + nl - 4, ".cha") == 0) {
		std::string new_name (name, nl - 4);
		rename (name, new_name.c_str());
	}
}

}}


