#ifndef AMBER_BLOBUF_HPP
#define AMBER_BLOBUF_HPP

/* Copyright (c) 2015, 2018  Pelayo Bernedo.
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


#include <streambuf>
#include <fstream>
#include <vector>

#ifndef __STDC_LIMIT_MACROS
	#define __STDC_LIMIT_MACROS 1
#endif
#include <stddef.h>

namespace amber {  namespace AMBER_SONAME {


class EXPORTFN Blobuf : public std::streambuf {
	size_t            chunk_size;       // Size of the block chunk.
	ptrdiff_t         block_number;     // Number of the block currently in the buffer.
	size_t            payload_bytes;    // Number of bytes that are valid in the current buffer.
	ptrdiff_t         last_block_written;  // The block at the end of the file.
	bool              eof;
	std::istream      *owner_is;
	std::ostream      *owner_os;
	std::vector<char> buf;
	bool              closed;
	enum class Mode { reading, writing, idle } mode;

	void write_buffer();

protected:
	std::string error_info;
	virtual int overflow(int ch);
	virtual int underflow();
	virtual std::streamsize showmanyc();
	virtual pos_type seekoff (off_type off, std::ios_base::seekdir dir,
	                    std::ios_base::openmode which) override;
	virtual pos_type seekpos(std::streampos pos, std::ios_base::openmode which) override;

	virtual ptrdiff_t write_block (long long bn, const char *bytes, size_t nbytes) = 0;
	virtual ptrdiff_t read_block (long long bn, char *bytes, size_t nbytes) = 0;
	virtual void get_file_size (std::streamoff *last_block, std::streamoff *last_bytes);


public:
	Blockbuf();
	~Blockbuf();

	void set_owner(std::istream *is) { owner_is = is; }
	void set_owner(std::ostream *os) { owner_os = os; }
	virtual void close();
	void clear() { eof = false; }

	const std::string & get_error_info() const { return error_info; }
};


}}

#endif

