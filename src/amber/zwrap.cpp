/*               
 * Copyright (C) 2012-2017 Pelayo Bernedo.
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




#include "zwrap.hpp"
#include <stdexcept>
#include <iostream>
#include <string.h>

#include <zlib.h>
#undef compress

namespace amber {  namespace AMBER_SONAME {

enum Mode { none, compressing, expanding };

struct ZWrapper::Data {
	z_stream zs;
	int      level;
	Mode     mode;
	std::streamoff length;
	bool     finished;
};

ZWrapper::ZWrapper(int lev)
	: ok(true)
{
	pimpl = new Data;
	pimpl->level = lev;
	pimpl->mode = none;
	pimpl->length = 0;
	pimpl->finished = false;
}

ZWrapper::ZWrapper (const ZWrapper &rhs)
{
	pimpl = new Data;
//    deflateCopy (pimpl->zs, rhs.pimpl->zs);
	pimpl->level = rhs.pimpl->level;
	pimpl->mode = none;
	pimpl->length = rhs.pimpl->length;
	pimpl->finished = rhs.pimpl->finished;
}

ZWrapper::~ZWrapper()
{
	if (pimpl->mode == compressing) {
		deflateEnd (&pimpl->zs);
	} else if (pimpl->mode == expanding) {
		inflateEnd (&pimpl->zs);
	}
	delete pimpl;
}

ZWrapper & ZWrapper::operator= (const ZWrapper &rhs)
{
	if (pimpl->mode == compressing) {
		deflateEnd (&pimpl->zs);
	} else if (pimpl->mode == expanding) {
		inflateEnd (&pimpl->zs);
	}
	delete pimpl;

	pimpl = new Data;
	pimpl->level = rhs.pimpl->level;
	pimpl->mode = none;
	pimpl->length = rhs.pimpl->length;
	pimpl->finished = rhs.pimpl->finished;

	return *this;
}


int ZWrapper::compress(const unsigned char *buf, size_t n, buffer<unsigned char> *res, bool finish)
{
	if (pimpl->mode == expanding) {
		throw std::logic_error ("ZWrapper::compress() called while in expanding mode");
	}
	if (pimpl->mode == none) {
		memset (&pimpl->zs, 0, sizeof pimpl->zs);
		ok = Z_OK == deflateInit (&pimpl->zs, pimpl->level);
		pimpl->mode = compressing;
	}

	res->resize(res->capacity());
	if (n > res->size()) {
		res->resize(n);
	}

	size_t cap = res->size();

	pimpl->zs.next_in   = (Bytef*)buf;
	pimpl->zs.avail_in  = n;
	pimpl->zs.next_out  = (Bytef*)&(*res)[0];
	pimpl->zs.avail_out = cap;

	int mode = finish ? Z_FINISH : Z_NO_FLUSH;
	int count = 0;

	for (;;) {
		int rc = deflate(&pimpl->zs, mode);
		if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
			ok = false;
			return rc;
		}
		if (pimpl->zs.avail_out != 0) {
			res->resize(count + cap - pimpl->zs.avail_out);
			break;
		}

		count += cap;
		size_t ncap = cap * 2;
		res->resize(count + ncap);
		pimpl->zs.next_out = (Bytef*) &(*res)[count];
		pimpl->zs.avail_out = ncap;
		cap = ncap;
	}

	return 0;
}


int ZWrapper::expand(const unsigned char *buf, size_t n,
                     buffer<unsigned char> *res, bool finish)
{
	if (pimpl->mode == compressing) {
		throw std::logic_error ("ZWrapper::expand() called while in compressing mode");
	}
	if (pimpl->mode == none) {
		memset (&pimpl->zs, 0, sizeof pimpl->zs);
		ok = Z_OK == inflateInit (&pimpl->zs);
		pimpl->mode = expanding;
	}

	res->resize(res->capacity());
	if (n > res->size()) {
		res->resize(n);
	}
	size_t cap = res->size();

	pimpl->zs.next_in   = (unsigned char*) buf;
	pimpl->zs.avail_in  = n;
	pimpl->zs.next_out  = (Bytef*) &((*res)[0]);
	pimpl->zs.avail_out = cap;

	int mode = finish ? Z_FINISH : Z_NO_FLUSH;
	for (;;) {
		int rc = inflate(&pimpl->zs, mode);
		if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
			ok = false;
			return rc;
		}

		if (pimpl->zs.avail_out != 0) {
			res->resize(cap - pimpl->zs.avail_out);
			pimpl->length += n - pimpl->zs.avail_in;
			if (rc == Z_STREAM_END) {
				pimpl->finished = true;
			}
			break;
		}

		size_t ncap = cap * 2;
		res->resize(ncap);
		pimpl->zs.next_out = (Bytef*) &(*res)[cap];
		pimpl->zs.avail_out = cap;
		cap = ncap;
	}

	return 0;
}



int ZWrapper::flush (buffer<unsigned char> *res)
{
	if (pimpl->mode == expanding) {
		return expand ((char*)0, 0, res, true);
	} else if (pimpl->mode == compressing) {
		return compress ((char*)0, 0, res, true);
	}
	return 0;
}

void ZWrapper::reset()
{
	if (pimpl->mode == compressing) {
		deflateEnd (&pimpl->zs);
	} else if (pimpl->mode == expanding) {
		inflateEnd (&pimpl->zs);
	}
	pimpl->mode = none;
	pimpl->length = 0;
	pimpl->finished = false;
	ok = true;
}

std::streamoff ZWrapper::tail_offset() const
{
	return pimpl->length;
}

bool ZWrapper::finished() const
{
	return pimpl->finished;
}



}}

