/*
 * Copyright (c) 2015-2019, Pelayo Bernedo.
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

#ifndef AMBER_PROTOBUF_HPP

#include "soname.hpp"
#include "hasopt.hpp"
#include <stdint.h>
#include <stddef.h>
#include <iostream>
#include <vector>
#include <stack>
#include <limits>
#include <memory>

namespace amber { namespace AMBER_SONAME {

// Conversion between signed and unsigned forms. The signed forms use Zig
// Zag encoding.
inline uint64_t z2uleb (int64_t i)
{
	enum { scount = 64 - 1 };
	return  (i << 1) ^ (i >> scount);
}

inline int64_t u2zleb (uint64_t u)
{
	int64_t sbit = u & 1;
	return int64_t(u >> 1) ^ (-sbit);
}


// The following return the number of bytes written. Buf must have at least
// 10 bytes.

// Write a signed int in LEB128 with ZigZag encoding. Return the number of
// bytes written.
EXPORTFN size_t write_zleb (int64_t i, char *buf);
// Write an unsigned int in LEB128. Return the number of bytes written.
EXPORTFN size_t write_uleb (uint64_t i, char *buf);


// See https://tools.ietf.org/html/draft-rfernando-protocol-buffers-00 for a
// definition of the format.

enum Wire_type {
	varint      = 0,    // The following value is a ULEB128/ZLEB128.
	fixed64     = 1,    // The following value are 8 bytes.
	length_val  = 2,    // uleb128 encoded length, followed by bytes[length].
	group_start = 3,    // Start of a group.
	group_end   = 4,    // End of a group.
	fixed32     = 5,    // The following value are 4 bytes.
	group_len   = 6     // Same as length_val but contains triplets.
};

// Combine the id and the wire type into a single int.
constexpr uint32_t maketag (uint32_t id, Wire_type wt)
{
	return (id << 3) | wt;
}


// The writer keeps a buffer in memory. All groups that fit in memory are
// written to the output in group_len or length_val format. Items that do
// not fit in memory are written to the file. If the file is seekable they
// will also be in group_len or length_val format. If the file is not
// seekable they will be in group_start/group_end format.

class EXPORTFN Protobuf_writer {
	struct Data;
	std::unique_ptr<Data> data; // pimpl idiom.

	void flush_buffer (size_t nbytes);
	void write_tag (unsigned id, Wire_type wt, bool keep_ptr=false);

public:
	// Groups may be written as length delimited triplets or as pairs of
	// group_start/group_end triplets. noseek tells the writer not to seek
	// backwards in the file. In this case whenever a group start is written
	// out to the file, it will stay there. In the case of seek when we
	// finish the group we will go back to the tag written initially and
	// will overwrite it with a group_len tag and the length. If nogroup is
	// selected it will not write group_start/group_end tags, only group_len
	// tags. If you select seek and the underlying stream does not allow
	// seeking then group_start/group_end tags will be output. If you select
	// nogroup and the underlying stream does not allow seeking then a
	// std::runtime_error exception will be thrown. seek is the most general
	// option: it creates length delimited triplets if possible but will
	// fall back to group_start/group_end tags if the stream is not
	// seekable. nogroup does not create group_start/group_end tags and may
	// simplify processing at the reader, but does not work in non-seekable
	// streams.

	enum Group { noseek, seek, nogroup };

	// The buffer size is the maximum size of the memory buffer that
	// keeps the stream before writing it to the file. As long as the
	// stream is in memory it will be compacted and optimized. Set gt as
	// stated above. If you want to keep everything in memory then pass os==0
	// and buffer_size == SIZE_MAX.
	Protobuf_writer (std::ostream *os, Group gt, size_t buffer_size = 0x4000);
	~Protobuf_writer();

	// Use the group_len wire type instead of the length_val.
	void use_group_len (bool flag);

	void set_ostream (std::ostream *os);

	// Write an ULEB128 with the field tag.
	void write_uint (unsigned id, uint64_t v);

	// Write an ULEB128 without a field tag. This must be part of a packed
	// array.
	void write_packed_uint (uint64_t v);

	// Write an array of ULEB128 packed values.
	template <class Uiter>
	void write_packed_uint (unsigned id, Uiter v, Uiter end) {
		start_group(id);
		while (v != end) {
			write_packed_uint (*v++);
		}
		if (end_group() != length_val) {
			throw_rte (_("Packed array is too long"));
		}
	}


	// Write a ZLEB128 together with the field tag.
	void write_int (unsigned id, int64_t v);

	// Write a ZLEB128 without a field tag. This must be part of a packed
	// array.
	void write_packed_int (int64_t v);

	// Write an array of ZLEB128 packed values.
	template <class Siter>
	void write_packed_int (unsigned id, Siter v, Siter end) {
		start_group(id);
		while (v != end) {
			write_packed_int (*v++);
		}
		if (end_group() != length_val) {
			throw_rte (_("Packed array is too long"));
		}
	}


	// Write a fixed length integer in little endian order together with the
	// field tag.
	void write_uint32 (unsigned id, uint32_t v);
	void write_uint64 (unsigned id, uint64_t v);

	// Write a fixed length integer without the field tag. This must be part
	// of a packed array.
	void write_packed_uint32 (uint32_t v);
	void write_packed_uint64 (uint64_t v);

	// Write a sequence of items as 4-byte quantities as a packed array.
	template <class Iter>
	void write_packed_uint32 (unsigned id, Iter v, Iter end) {
		start_group (id);
		while (v != end) {
			write_packed_uint32 (*v++);
		}
		if (end_group() != length_val) {
			throw_rte (_("Packed array is too long"));
		}
	}


	// Write a sequence of items as 8-byte quantities as a packed array.
	template <class Iter>
	void write_packed_uint64 (unsigned id, Iter v, Iter end) {
		start_group (id);
		while (v != end) {
			write_packed_uint64 (*v++);
		}
		if (end_group() != length_val) {
			throw_rte (_("Packed array is too long"));
		}
	}



	// Write a IEEE float or double in little endian order with the field
	// tag.
	void write_float  (unsigned id, float v);
	void write_double (unsigned id, double v);

	// Write a IEEE float or double in little endian order without the tag.
	void write_packed_float (float v);
	void write_packed_double (double v);

	// Write a sequence of floats or doubles as a packed array.
	template <class Iter>
	void write_packed_float (unsigned id, Iter v, Iter end) {
		start_group (id);
		while (v != end) {
			write_packed_float (*v++);
		}
		if (end_group() != length_val) {
			throw_rte (_("Packed array is too long"));
		}
	}
	template <class Iter>
	void write_packed_double (unsigned id, Iter v, Iter end) {
		start_group (id);
		while (v != end) {
			write_packed_double (*v++);
		}
		if (end_group() != length_val) {
			throw_rte (_("Packed array is too long"));
		}
	}


	// Write a string of bytes. If n == -1 then s is null terminated.
	void write_string (unsigned id, const char *s, ptrdiff_t n=-1);
	void write_bytes (unsigned id, const void *buf, size_t n);
	void add_bytes (const char *bytes, size_t n);


	// Start an embedded group of items with the given tag.
	void start_group (unsigned id);

	// Returns length_val if the group could be closed with a
	// length_val/group_len wire type. Otherwise it returns a group_end wire
	// type. If opaque is true then the group will be output as a length_val.
	Wire_type end_group (bool opaque=false);

	// End all pending groups.
	void end_all_groups();

	// Flush to stream.
	void flush ();

	// Get a reference to the buffer.
	const std::vector<char> & get_buffer() const;
};


// Note: when writing a packed triplet, start the block with
// start_group(id). Then write the contents as packed entities. When you
// are finished end the block with end_group() and make sure that it
// returns group_len. If group_end is returned it means that the packed array
// exceeded the size of the buffer and we are not writing to a seekable
// stream: this is an error because packed arrays must be delimited with a
// length. A practical way of avoiding such errors is to either: (1) output
// only to seekable streams or (2) limit the size of each packed array and if
// there are more items to be sent just add another packed array with the
// same id.




class EXPORTFN Protobuf_reader {
	struct Data;
	std::unique_ptr<Data> data;

	void check_requirements();

public:
	Protobuf_reader();
	Protobuf_reader (std::istream *isp);
	Protobuf_reader (const char *buf, size_t n);
	~Protobuf_reader();
	void set_input (std::istream *isp);
	void set_input (const char *buf, size_t n);
	uint64_t read_uleb();
	int64_t read_zleb();
	// Read the tag. If a group_len tag is found then we record the length
	// to be read. When we have read the group_len bytes the function will
	// return false. If top_level is true then on encountering the end of
	// the input stream it will check the requirements. If top level is not
	// true then encountering the end of input will throw an exception.
	bool read_tagval (uint32_t *tagwt, uint64_t *val, bool top_level=false);

	// Read the value and store it in buf in little endian order. Return the
	// value as an unsigned. You can use for int/uint/float/double.
	uint32_t read_le32 (void *buf=0);
	uint64_t read_le64 (void *buf=0);

	// Read an unsigned or signed value according to the wire type. Throw if
	// the value does not fit in the passed variable.
	template <class U> void read_uint (Wire_type wt, U *u);
	template <class I> void read_int (Wire_type wt, I *i);

	// Just get the bytes without endianness conversion.
	void get_bytes (void *buf, std::streamoff n);

	// Skip the current item.
	void skip (uint32_t tagwt, uint64_t val);

	// If you are using group_len tags then read_tagval will be automatically
	// work as described above: returning false when the group has been
	// read. When using length_val tags the program will also provide this
	// behaviour if after the first call to read_tagval (the one that
	// returned length_val) you immediately call again read_tagval()
	// without consuming any input.

	// If you use length_val like in the original Google Protocol Buffers
	// then you can still have this translation at the top level if you call
	// this function. At the start of a length delimited group push this. n
	// is the size of the data of the triplet. When we reach the end then
	// read_tagval will return false.
	void push_scope (std::streamoff n=std::numeric_limits<std::streamoff>::max());

	// At the start of a group you may set the requirements for some of the
	// tags. They will be checked at the end of the group. This must be used
	// only within groups, not at the top level. If you need checking at the
	// top level just push a scope without the length argument at the top
	// level.
	enum Requirement { optional_once, optional_many, needed_once, needed_many };
	void add_requirement (uint32_t tagwt, Requirement r);

	template <class ... Args>
	void add_requirement (uint32_t tagwt, Requirement r, Args ...args) {
		add_requirement (tagwt, r);
		add_requirement (args...);
	}
};

union Cont32 {
	uint32_t u;
	int32_t i;
	float x;
};
union Cont64 {
	uint64_t u;
	int64_t i;
	double x;
};

// Do not convert. Just read the underlying bytes. This uses type punning
// with unions, which is defined in C99 and C11 but is undefined behavior in
// C++. GCC explicitly allows it in C++. Linux uses it and the Windows API
// also has it. Therefore we just ignore the wording of the standard and use
// type punning with unions. See https://lkml.org/lkml/2018/6/5/769 for a
// strongly worded (but correct) opinion. The alternative is to use memcpy()
// and rely on the undefined promise that the compiler will optimize it
// away.

inline uint32_t float2int (float x)
{
	Cont32 c;
	c.x = x;
	return c.u;
}

inline float int2float (uint32_t x)
{
	Cont32 c;
	c.u = x;
	return c.x;
}

inline uint64_t double2int (double x)
{
	Cont64 c;
	c.x = x;
	return c.u;
}

inline double int2double (uint64_t x)
{
	Cont64 c;
	c.u = x;
	return c.x;
}




template <class U>
void Protobuf_reader::read_uint (Wire_type wt, U *u)
{
	uint64_t v;
	static_assert (std::is_unsigned<U>::value, "U must be an unsigned integral type.");

	switch (wt) {
	case varint:
		v = read_uleb();
		break;

	case fixed32:
		v = read_le32();
		break;

	case fixed64:
		v = read_le64();
		break;

	default:
		throw std::logic_error ("This wire type cannot be a uint");
	}

	if (v > std::numeric_limits<U>::max()) {
		throw std::out_of_range ("Read an unsigned that does not fit in the variable.");
	}
	*u = v;
}


template <class I>
void Protobuf_reader::read_int (Wire_type wt, I *i)
{
	int64_t v;
	int32_t tmp;
	static_assert (std::is_signed<I>::value, "I must be a signed integral type.");

	switch (wt) {
	case varint:
		v = read_zleb();
		break;

	case fixed32:
		read_le32 (&tmp);
		v = tmp;
		break;

	case fixed64:
		read_le64 (&v);
		break;

	default:
		throw std::logic_error ("This wire type cannot be a uint");
	}

	if (v > std::numeric_limits<I>::max() || v < std::numeric_limits<I>::min()) {
		throw std::out_of_range ("Read an signed that does not fit in the variable.");
	}
	*i = v;
}


}}

#endif


