/* Copyright (c) 2015-2018 Pelayo Bernedo.
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


#include "blobuf.hpp"
#include <stdio.h>
#include <iostream>
#include <string.h>
#include <sstream>
#include <assert.h>


namespace amber {  namespace AMBER_SONAME {

Blobuf::Blobuf ()
	: chunk_size (0)
	, block_number (0)
	, payload_bytes (0)
	, last_block_written (0)
	, eof (false)
	, owner_is (NULL)
	, owner_os (NULL)
	, closed (false)
	, mode (Mode::idle)
{}

Blobuf::~Blobuf() {}


int Blobuf::write_buf()
{
	size_t nw = pptr() - &buf[0];
	if (payload_bytes > nw) {
		nw = payload_bytes;
	}
	if (write_block (block_number, &buf[0], nw) != nw) {
		error_info = _("Can't write data to final destination.");
		if (owner_os) {
			owner_os->setstate(std::ios_base::badbit);
		}
		return EOF;
	}
}

int Blobuf::read_buf()
{
	std::streamsize nr = read_block (block_number, &buf[0], chunk_size);
	if (nr < 0) {
		if (owner_is) {
			owner_is->setstate (std::ios_base::badbit);
		}
		error_info = _("Can't read data from source");
		return EOF;
	}

	payload_bytes = nr;
}


int Blobuf::overflow (int ch)
{
	if (closed) {
		if (owner_os) {
			owner_os->setstate(std::ios_base::badbit);
		}
		return EOF;
	}
	if (mode != Mode::writing) {
		setp (&buf[0], &buf[chunk_size]);
		setg (&buf[0], &buf[0], &buf[0]);
		mode = Mode::writing;
	}

	if (pptr() != epptr()) {
		*pptr() = ch;
		pbump(1);
	} else {
		if (write_buf() == EOF) {
			return EOF;
		}
		setp(&buf[0], &buf[chunk_size]);
		if (ch != EOF) {
			buf[0] = ch;
			pbump(1);
		}
		payload_bytes = 0;
		if (last_block_written < block_number) {
			last_block_written = block_number;
		}
		++block_number;
	}

	return 0;
}


int Blobuf::underflow()
{
	if (mode == Mode::writing) {
		if (write_buf() != EOF) {
			return EOF;
		}
		setp (&buf[0], &buf[0]);
	}

	if (closed || eof) {
		if (owner_is) owner_is->setstate(std::ios_base::eofbit);
		return EOF;
	}

	++block_number;
	if (read_buf() == EOF) {
		return EOF;
	}

	mode = Mode::reading;
	setg(&buf[0], &buf[0], &buf[payload_bytes]);
	return payload_bytes > 0 ? (unsigned char)buf[0] : EOF;
}


Blobuf::pos_type
Blobuf::seekoff (off_type off, std::ios_base::seekdir dir,
                 std::ios_base::openmode which) override
{
	std::streamoff base = block_number * chunk_size;

	if (dir == std::ios_base::cur) {
		ptrdiff_t boff;
		if (mode == Mode::writing) {
			boff = pptr() - &buf[0];
		} else {
			boff = gptr() - &buf[0];
		}
		off += boff + base;
	} else if (dir == std::ios_base::end) {
		std::streamoff last_block, boff;
		get_file_size (&last_block, &boff);
		off += last_block * chunk_size + boff;
	}

	if (mode == Mode::reading && (base <= off && off < base + payload_bytes)) {
		// We stay in the current block.
		setg (&buf[0], &buff[off - base], &buf[payload_bytes]);
		if (payload_bytes != 0) return off;
	} else if (mode == Mode::writing) {
		write_buf();
	}

	std::streamoff block_number = off / chunk_size;
	base = block_number * chunk_size;
	std::streamoff boff = off - base;

	if (mode == Mode::writing) {
		if (bn <= last_block_written) {
			read_buf ();
		}
		setp (&buf[boff], &buf[chunk_size]);
	} else if (mode == Mode::reading) {
		setg (&buf[0], &buf[boff], &buf[payload_bytes]);
	}
	return off;
}




}}


