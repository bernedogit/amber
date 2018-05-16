/*
 * Copyright (c) 2012-2017, Pelayo Bernedo.
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



#ifndef AMBER_ZWRAP_HPP
#define AMBER_ZWRAP_HPP

#include "soname.hpp"
#include "buffer.hpp"
#include <iostream>

namespace amber {  namespace AMBER_SONAME {


// Wrappers around the zlib or miniz library. Just create a ZWrapper object.
// Pass chunks of input to either compress or expand. They will put the
// compressed or expanded data in *res. When all input data has been passed
// through compress() or expand() call flush() or the corresponding function
// with finish==true. Call reset() if you need to switch to a new stream or
// mode.

// The library initializes and frees the zlib correctly and takes care of
// managing the buffers.

// If there are errors the functions will return a zlib error code and will
// set the state so that bad() will return true. You must call reset() to
// clear the error condition.

// The library supports compressing or expanding a single stream at a time.
// To process a new stream you must call reset() between the streams. If you
// start compressing a stream and then call expand() without an intervening
// reset() the library will throw a logic_error exception. Same for calling
// compress() while expanding. Note that these two conditions are programmer
// errors.


class EXPORTFN ZWrapper {
	struct Data;
	struct Data *pimpl;
	bool ok;

public:

	ZWrapper(int level = 9);
	ZWrapper (const ZWrapper &rhs);
	~ZWrapper();
	ZWrapper & operator= (const ZWrapper &rhs);

	// The following return 0 on success or one of the Z_... error codes
	// from the zlib. If there is an error use the error_messge() to get
	// the info.

	// Accept an additional chunk for compression and put compressed data
	// in *res. If finish is true then perform the compression in a single
	// step (there won't be any further calls to compress). If finish is
	// false you call compress as many times as you need and then either
	// call compress once more with finish==true or call flush.
	int compress (const unsigned char *buf, size_t n,
	              buffer<unsigned char> *b, bool finish=false);
	int compress (const char *buf, size_t n,
	              buffer<unsigned char> *b, bool finish=false) {
		return compress ((unsigned char*)buf, n, b, finish);
	}
	int compress (const char *buf, size_t n,
	              buffer<char> *b, bool finish=false) {
		return compress ((unsigned char*)buf, n,
		            reinterpret_cast<buffer<unsigned char>*>(b), finish);
	}

	// Accept an additional chunk of compressed data and put some of the
	// expanded data in *res. If finish is true perform the expansion in a
	// single step (there won't be any further calls to expand).
	int expand(const unsigned char *buf, size_t n,
	           buffer<unsigned char> *res, bool finish=false);

	int expand (const char *buf, size_t n,
	            buffer<unsigned char> *b, bool finish=false) {
		return expand ((unsigned char*)buf, n, b, finish);
	}
	int expand (const char *buf, size_t n,
	            buffer<char> *b, bool finish=false) {
		return expand ((unsigned char*)buf, n,
		        reinterpret_cast<buffer<unsigned char>*>(b), finish);
	}

	// Put all remaining output in *res.
	int flush(buffer<unsigned char> *res);
	int flush(buffer<char> *res) {
		return flush (reinterpret_cast<buffer<unsigned char>*>(res));
	}

	// Finish and free all resources. Called automatically by the
	// destructor.
	void reset();

	// State of the stream.
	bool good() const { return ok; }
	bool bad() const  { return !ok; }
	std::streamoff tail_offset() const;
	bool finished() const;
};




}}

#endif

