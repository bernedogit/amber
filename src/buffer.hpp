/* Copyright (C) 2012-2019 Pelayo Bernedo.
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


#ifndef AMBER_BUFFER_HPP
#define AMBER_BUFFER_HPP


#include "soname.hpp"
#include <stddef.h>
#include <memory>

namespace amber {  namespace AMBER_SONAME {

// Simple buffer. Differences with std::vector: it uses a small buffer
// optimization and when resizing it does not change the contents. You
// declare a buffer as buffer<int, 200> b. In this case, if the size of the
// buffer never exceeds 200 there won't be any dynamic memory allocation.
// When resizing the buffer to expand it, only the length is changed but the
// contents are not modified.

/* Typical use case:
	buffer<int, 100> b;
	...
	// C++ usage.
	for each item i {
		b.push_back(i);
	}

	// call C function
	size_t num_filled = fill_buffer (&b[0], b.capacity());
	b.resize(num_filled);
*/

// In the example, if b were a std::vector and its previous size were less
// than num_filled it would overwrite the items between the previous size
// and num_filled. This buffer does not touch the contents when resizing.
// When you declare a buffer you also give the size of the small buffer. When
// declaring interfaces that use buffer you just use buffer<T>. buffer<T,N>
// is derived from buffer<T> and you can just pass any buffer<T,N> to a
// function expecting buffer<T>.


template <class T, size_t N=0> class buffer;


template <class T>
class EXPORTFN buffer<T,0> {
protected:
	T *buf;
	T *fixed_buf;
	size_t cap, sz;
	buffer (T *b, size_t n);
	void copy_from (const buffer<T> &rhs);
public:
	buffer();
	buffer(const buffer<T> &rhs);
	buffer& operator=(const buffer<T> &rhs);
	~buffer();
	T& operator[] (ptrdiff_t i) { return buf[i]; }
	const T& operator[] (ptrdiff_t i) const { return buf[i]; }
	size_t size() const { return sz; }
	size_t capacity() const { return cap; }
	bool empty() const { return sz == 0; }
	void resize (size_t newsz, bool keep_contents=true);
	buffer<T,0> & push_back (const T &t);
	T * begin() { return buf; }
	T * end() { return buf + sz; }
	const T * begin() const { return buf; }
	const T * end() const { return buf + sz; }
	const T * cbegin() const { return buf; }
	const T * cend() const { return buf + sz; }
	typedef T *iterator;
	typedef const T *const_iterator;

	void clear() { sz = 0; }
	template <class In> void assign (In first, In end);
	template <class In> void append (In first, In end);
};


template <class T>
buffer<T,0>::buffer (T *b, size_t n)
	: buf (b)
	, fixed_buf (b)
	, cap (n)
	, sz (0)
{}

template <class T>
void buffer<T>::copy_from (const buffer<T> &rhs)
{
	const T *psrc = rhs.begin();
	const T *plim = rhs.end();
	T *pdst = buf;

	while (psrc != plim) {
		*pdst++ = *psrc++;
	}
}

template <class T>
buffer<T,0>::buffer()
	: fixed_buf(0)
{
	cap = 10;
	buf = new T[cap];
	sz = 0;
}


template <class T>
buffer<T>::buffer(const buffer<T> &rhs)
	: fixed_buf (0)
{
	cap = rhs.size();
	if (cap == 0) {
		cap = 1;
	}
	std::unique_ptr<T> holder (new T[cap]);
	buf = holder.get();
	cap = cap;
	sz = rhs.size();
	copy_from (rhs);
	holder.release();
}

template <class T>
buffer<T>& buffer<T>::operator=(const buffer<T> &rhs)
{
	if (cap < rhs.size()) {
		if (buf != fixed_buf) {
			delete [] buf;
		}
		buf = new T[rhs.size()];
		cap = rhs.size();
	}
	copy_from (rhs);
	sz = rhs.size();

	return *this;
}


template <class T>
buffer<T,0>::~buffer()
{
	if (buf != fixed_buf) {
		delete [] buf;
	}
}




// Contrary to std::vector we do not overwrite the tail when expanding.
template <class T>
void buffer<T,0>::resize (size_t newsz, bool keep_contents)
{
	if (newsz > cap) {
		std::unique_ptr<T> newbuf (new T [newsz]);
		if (keep_contents) {
			T *psrc = buf;
			T *pdst = newbuf.get();
			T *lim  = buf + sz;
			while (psrc < lim) {
				*pdst++ = *psrc++;
			}
		}
		if (buf != fixed_buf) {
			delete [] buf;
		}
		buf = newbuf.release();
		cap = newsz;
	}
	sz = newsz;
}


template <class T>
inline buffer<T,0> & buffer<T,0>::push_back (const T &t)
{
	if (sz >= cap) {
		size_t newcap = cap * 1.3;
		while (newcap < sz) {
			newcap *= 1.3 + 1;
		}
		size_t tmp = sz;
		resize (newcap);
		sz = tmp;
	}
	buf[sz++] = t;
	return *this;
}


template <class T>
template <class In>
void buffer<T,0>::assign (In first, In end)
{
	clear();
	while (first != end) {
		push_back(*first);
		++first;
	}
}


template <class T>
template <class In>
void buffer<T,0>::append (In first, In end)
{
	while (first != end) {
		push_back(*first);
		++first;
	}
}


template <class T, size_t N>
class buffer : public buffer<T,0> {
	T fixed[N];
public:
	buffer() : buffer<T,0>(fixed, N) {}

	buffer(const buffer<T> &rhs);

	buffer<T,N> & operator=(const buffer<T> &rhs) {
		buffer<T,0>::operator=(rhs);
		return *this;
	}
	// ~buffer(); default is valid.
};


template <class T, size_t N>
buffer<T,N>::buffer(const buffer<T> &rhs)
{
	buffer<T>::fixed_buf = fixed;
	this->sz = rhs.size();
	if (this->sz <= N) {
		this->cap = N;
		this->buf = fixed;
	} else {
		this->buf = new T[this->sz];
		this->cap = this->sz;
	}
	this->copy_from (rhs);
}



}}
#endif


