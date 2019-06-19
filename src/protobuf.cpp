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

#include "protobuf.hpp"
#include <string.h>
#include <type_traits>
#include <map>
#include "hasopt.hpp"


namespace amber {   namespace AMBER_SONAME {


size_t write_uleb (uint64_t u, char *buf)
{
	uint8_t lb;
	char *wp = buf;

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

size_t write_zleb (int64_t i, char *buf)
{
	enum { scount = 64 - 1 };
	uint64_t u;
	u = (i << 1) ^ (i >> scount);
	return write_uleb (u, buf);
}


struct Protobuf_writer::Data {
	size_t max_size;    // Maximum size to keep in the buffer.

	// Number of bytes to write on each call to the underlying stream.
	enum { chunk_size = 5000 };

	struct Pending {
		std::streamoff pos;
		int            reserved_bytes;
		unsigned       id;
	};
	std::stack<Pending> pending;
	std::streamoff      current;       // Current position in logical stream.
	std::ostream        *os;
	std::vector<char>   buffer;
	std::streamoff      buffer_base;   // Position of the buffer in the logical stream.
	Group               gt;
	bool                use_group_len;

	Data (std::ostream *osp) : os(osp) {}
};


Protobuf_writer::Protobuf_writer (std::ostream *os, Group gt, size_t buffer_size)
	: data (new Data(os))
{
	data->max_size    = buffer_size;
	data->current     = 0;
	data->buffer_base = 0;
	data->gt          = gt;
	data->use_group_len = true;

	if (data->max_size < 2u * data->chunk_size) {
		data->max_size = 2 * data->chunk_size;
	}
}


Protobuf_writer::~Protobuf_writer()
{
	flush();
}

void Protobuf_writer::set_ostream (std::ostream *os)
{
	data->os = os;
}

void Protobuf_writer::use_group_len (bool flag)
{
	data->use_group_len = flag;
}

void Protobuf_writer::flush_buffer (size_t nbytes)  
{
	if (data->os) {
		data->os->write (&data->buffer[0], nbytes);
		data->buffer.erase (data->buffer.begin(), data->buffer.begin() + nbytes);
		data->buffer_base += nbytes;
	}
}


void Protobuf_writer::add_bytes (const char *bytes, size_t n)
{
	data->current += n;

	if (n > data->max_size) {
		flush_buffer (data->buffer.size());
		data->os->write (bytes, n);
		data->buffer_base = data->current;
		return;
	}

	size_t loc = data->buffer.size();
	data->buffer.resize (loc + n);
	memcpy (&data->buffer[0] + loc, bytes, n);

	if (data->buffer.size() > data->max_size) {
		flush_buffer (data->buffer.size() - data->max_size + data->chunk_size);
	}
}


void Protobuf_writer::write_tag (unsigned id, Wire_type wt, bool keep_ptr)
{
	char b[20];
	size_t nw = write_uleb ((id << 3) | wt, b);
	add_bytes (b, nw);
	if (keep_ptr) {
		data->current -=nw;
	}
}

// Maximum number of bytes to reserve for the length of a length_val or
// group_len triplet. For 64 bits we need 10 bytes of LEB128 encoding. For
// 63 bits we need 9 bytes of LEB128 encoding.
enum { max_res_space = 9 };

void Protobuf_writer::start_group (unsigned id)
{
	char tag[20];
	unsigned nw = write_uleb ((id << 3) | group_start, tag);

	// Encode it as a single tag field with space for the actual tag plus 10
	// bytes.
	tag[nw - 1] |= 0x80;
	for (unsigned i = nw; i < nw + max_res_space - 1; ++i) {
		tag[i] = 0x80;
	}
	tag[nw + max_res_space - 1] = 0;

	Data::Pending mark;
	mark.pos = data->current;
	mark.reserved_bytes = nw + max_res_space;
	mark.id = id;
	add_bytes (tag, nw + max_res_space);
	data->pending.push (mark);
}

Wire_type Protobuf_writer::end_group (bool opaque)
{
	Wire_type res;
	if (opaque) {
		res = length_val;
	} else if (data->use_group_len) {
		res = group_len;
	} else {
		res = length_val;
	}

	if (!data->pending.empty()) {
		Data::Pending top = data->pending.top();
		if (top.pos < data->buffer_base) {
			std::streampos pos = data->os->tellp();
			bool seek_ok = false;
			if (data->gt != noseek) {
				data->os->seekp (top.pos);
				if (data->os) {
					seek_ok = true;
				} else {
					data->os->clear();
				}
			}

			// Cancel if we can't seek.
			if (!seek_ok) {
				if (data->gt == nogroup || opaque) {
					throw_rte (_("Requested group_len tags only in non-seekable stream"));
				} else {
					write_tag (top.id, group_end, true);
				}
				res = group_end;
			} else {
				std::streamoff n = data->current - top.pos - top.reserved_bytes;
				char buf[30];
				memset (buf, 0, sizeof buf);
				ptrdiff_t first = write_uleb ((top.id << 3) | res, buf);
				if (write_uleb (n, buf + first) > max_res_space) {
					throw_rte (_("Trying to write a group_len bigger than the reserved space (%d)."),
					            max_res_space);
				}

				for (int i = first; i < top.reserved_bytes - 1; ++i) {
					buf[i] |= 0x80;
				}
				data->os->write (buf, top.reserved_bytes);
				if (top.pos + top.reserved_bytes > data->buffer_base) {
					size_t nerase = top.pos + top.reserved_bytes - data->buffer_base;
					data->buffer.erase (data->buffer.begin(), data->buffer.begin() + nerase);
					data->buffer_base += nerase;
				}
				data->os->seekp (pos);
			}
		} else {
			// The block header is still in the buffer.
			ptrdiff_t local_pos = top.pos - data->buffer_base;
			ptrdiff_t n = data->current - top.pos - top.reserved_bytes;
			char buf[20];
			int count = write_uleb ((top.id << 3) | (opaque ? length_val : group_len), buf);
			count += write_uleb (n, buf + count);
			memcpy (&data->buffer[0] + local_pos, buf, count);
			if (count < top.reserved_bytes) {
				data->buffer.erase (data->buffer.begin() + local_pos + count,
				                    data->buffer.begin() + local_pos + top.reserved_bytes);
				data->current -= top.reserved_bytes - count;
			}
		}

		data->pending.pop();
	}
	return res;
}




void Protobuf_writer::end_all_groups()
{
	while (!data->pending.empty()) {
		end_group();
	}
}


void Protobuf_writer::flush()
{
	if (data->os) {
		data->os->write (&data->buffer[0], data->buffer.size());
		data->buffer_base += data->buffer.size();
		data->buffer.clear();
	}
}


void Protobuf_writer::write_uint (unsigned id, uint64_t v)
{
	write_tag (id, varint);
	char b[20];
	size_t nw = write_uleb (v, b);
	add_bytes (b, nw);
}

// Write a signed integer in Zig Zag encoding together with the field tag.
void Protobuf_writer::write_int (unsigned id, int64_t v)
{
	write_tag (id, varint);
	char b[20];
	size_t nw = write_zleb (v, b);
	add_bytes (b, nw);
}

void Protobuf_writer::write_packed_uint (uint64_t v)
{
	char b[20];
	size_t nw = write_uleb (v, b);
	add_bytes (b, nw);
}

void Protobuf_writer::write_packed_int (int64_t v)
{
	char b[20];
	size_t nw = write_zleb (v, b);
	add_bytes (b, nw);
}



void Protobuf_writer::write_uint32 (unsigned id, uint32_t v)
{
	write_tag (id, fixed32);
	// Google's protocol buffers specifies that fixed length quantities will
	// be written in little endian order.
	char lebytes[4] = { char(v), char(v >> 8), char(v >> 16), char(v >> 24) };
	add_bytes (lebytes, 4);
}

void Protobuf_writer::write_packed_uint32 (uint32_t v)
{
	char lebytes[4] = { char(v), char(v >> 8), char(v >> 16), char(v >> 24) };
	add_bytes (lebytes, 4);
}



void Protobuf_writer::write_uint64 (unsigned id, uint64_t u)
{
	write_tag (id, fixed64);
	char lebytes[8] = { char(u), char(u >> 8), char(u >> 16), char(u >> 24),
	                    char(u >> 32), char(u >> 40), char(u >> 48), char(u >> 56) };
	add_bytes (lebytes, 8);
}

void Protobuf_writer::write_packed_uint64 (uint64_t u)
{
	char lebytes[8] = { char(u), char(u >> 8), char(u >> 16), char(u >> 24),
	                    char(u >> 32), char(u >> 40), char(u >> 48), char(u >> 56) };
	add_bytes (lebytes, 8);
}





// write_float and write_double assume that the doubles and floats use the
// IEEE representation in the cpu's native endianness. We use unions for
// type punning. See the comment in the header file.

void Protobuf_writer::write_float (unsigned id, float v)
{
	static_assert (sizeof(v) == sizeof(uint32_t) && std::numeric_limits<float>::is_iec559,
	               "A float must be in IEEE 32 bit format");
	union {
		float     f;
		uint32_t  u;
	} fu;

	fu.f = v;
	return write_uint32 (id, fu.u);
}

void Protobuf_writer::write_double (unsigned id, double v)
{
	static_assert(sizeof(v) == sizeof(uint64_t) && std::numeric_limits<double>::is_iec559,
	              "A double must be in IEEE 64 bit format");
	union {
		double   f;
		uint64_t u;
	} fu;

	fu.f = v;
	return write_uint64 (id, fu.u);
}

void Protobuf_writer::write_packed_float (float v)
{
	static_assert(sizeof(v) == sizeof(uint32_t) && std::numeric_limits<float>::is_iec559,
	              "A float must be in IEEE 32 bit format");
	union {
		float     f;
		uint32_t  u;
	} fu;

	fu.f = v;
	return write_packed_uint32 (fu.u);
}

void Protobuf_writer::write_packed_double (double v)
{
	static_assert(sizeof(v) == sizeof(uint64_t) && std::numeric_limits<double>::is_iec559,
	            "A double must be in IEEE 64 bit format");
	union {
		double   f;
		uint64_t u;
	} fu;

	fu.f = v;
	return write_packed_uint64 (fu.u);
}


void Protobuf_writer::write_string (unsigned id, const char *s, ptrdiff_t n)
{
	if (n == -1) {
		n = strlen (s);
	}
	write_tag (id, length_val);
	char b[20];
	size_t nw = write_uleb (n, b);
	add_bytes (b, nw);
	add_bytes (s, n);
}

void Protobuf_writer::write_bytes (unsigned id, const void *buf, size_t n)
{
	write_tag (id, length_val);
	char b[20];
	size_t nw = write_uleb (n, b);
	add_bytes (b, nw);
	add_bytes ((const char*)buf, n);
}


const std::vector<char> & Protobuf_writer::get_buffer() const
{
	return data->buffer;
}


struct Req {
	Protobuf_reader::Requirement r;
	int count;
	Req() : r(Protobuf_reader::optional_many), count(0) {}
};

struct Protobuf_reader::Data {
	std::istream    *is;
	const char      *pbuf, *plim;
	std::streamoff  current, limit, last_length, last_pos;
	struct Block {
		std::streamoff limit;
		std::map<uint32_t, Req> reqs;
	};
	std::stack<Block> scopes;
};



Protobuf_reader::Protobuf_reader()
	: data (new Data)
{
	data->is = 0;
	data->pbuf = data->plim = 0;
	data->current = 0;
	data->limit = std::numeric_limits<decltype(data->limit)>::max();
	data->last_length = data->last_pos = 0;
}

Protobuf_reader::Protobuf_reader (std::istream *isp)
	: data (new Data)
{
	data->is = isp;
	data->pbuf = data->plim = 0;
	data->current = 0;
	data->limit = std::numeric_limits<decltype(data->limit)>::max();
	data->last_length = data->last_pos = 0;
}


Protobuf_reader::Protobuf_reader (const char *buf, size_t n)
	: data (new Data)
{
	data->is = 0;
	data->pbuf = buf;
	data->plim = buf + n;
	data->current = 0;
	data->limit = std::numeric_limits<decltype(data->limit)>::max();
	data->last_length = data->last_pos = 0;
}


Protobuf_reader::~Protobuf_reader() {}

void Protobuf_reader::set_input (std::istream *is)
{
	data->is = is;
}

void Protobuf_reader::set_input (const char *buf, size_t n)
{
	data->is = 0;
	data->pbuf = buf;
	data->plim = buf + n;
	data->current = 0;
	data->limit = std::numeric_limits<decltype(data->limit)>::max();
}


uint64_t Protobuf_reader::read_uleb()
{
	uint64_t val = 0;
	unsigned shifts = 0;
	if (data->is) {
		while (data->current < data->limit) {
			int ch = data->is->get();
			if (ch == EOF) {
				throw std::length_error ("EOF while reading a LEB128 number");
			}
			data->current++;
			if (shifts >= 63) {
				if ((shifts == 63 && (ch & 0x7E)) || (shifts > 63 && (ch & 0x7F))) {
					throw std::out_of_range ("Reading a LEB128 that has more than 64 bits.");
				}
			}
			val |= uint64_t(ch & 0x7F) << shifts;
			shifts += 7;
			if ((ch & 0x80) == 0) {
				return val;
			}
		}
	} else {
		while (data->current < data->limit) {
			int ch;
			if (data->pbuf < data->plim) {
				ch = (unsigned char) *data->pbuf++;
			} else {
				throw std::length_error ("EOF while reading a LEB128 number");
			}
			data->current++;
			if (shifts >= 63) {
				if ((shifts == 63 && (ch & 0x7E)) || (shifts > 63 && (ch & 0x7F))) {
					throw std::out_of_range ("Reading a LEB128 that has more than 64 bits.");
				}
			}
			val |= uint64_t(ch & 0x7F) << shifts;
			shifts += 7;
			if ((ch & 0x80) == 0) {
				return val;
			}
		}
	}
	throw std::length_error (_("Attempting to read a LEB128 beyond a field limit"));
}


int64_t Protobuf_reader::read_zleb()
{
	int64_t u = read_uleb();
	int64_t sbit = u & 1;
	return int64_t(u >> 1) ^ (-sbit);
}


uint32_t Protobuf_reader::read_le32 (void *buf)
{
	uint32_t u;
	int ch, shifts = 0;

	u = 0;
	for (int i = 0; i < 4; ++i) {
		if (data->current > data->limit) {
			throw std::length_error ("Attempting to read a fixed32 beyond a field limit");
		}
		if (data->is) {
			ch = data->is->get();
		} else if (data->pbuf < data->plim) {
			ch = (unsigned char) *data->pbuf++;
		} else {
			ch = EOF;
		}
		if (ch == EOF) {
			throw std::length_error (_("EOF while reading a fixed32 number"));
		}
		data->current++;
		u |= ((uint32_t)(unsigned char)ch) << shifts;
		shifts += 8;
	}
	if (buf) {
		memcpy (buf, &u, 4);
	}
	return u;
}

uint64_t Protobuf_reader::read_le64 (void *buf)
{
	uint64_t u;
	int ch, shifts = 0;

	u = 0;
	for (int i = 0; i < 8; ++i) {
		if (data->current > data->limit) {
			throw std::length_error (_("Attempting to read a fixed64 beyond a field limit"));
		}
		if (data->is) {
			ch = data->is->get();
		} else if (data->pbuf < data->plim) {
			ch = (unsigned char) *data->pbuf++;
		} else {
			ch = EOF;
		}
		if (ch == EOF) {
			throw std::length_error (_("EOF while reading a fixed64 number"));
		}
		data->current++;
		u |= ((uint64_t)(unsigned char)ch) << shifts;
		shifts += 8;
	}
	if (buf) {
		memcpy (buf, &u, 8);
	}
	return u;
}



void Protobuf_reader::get_bytes (void *buf, std::streamoff n)
{
	if (data->current + n <= data->limit) {
		if (data->is) {
			data->is->read ((char*)buf, n);
			if (data->is->gcount() != n) {
				throw_rte (_("Cannot read the requested size"));
			}
		} else if (data->pbuf + n <= data->plim) {
			memcpy (buf, data->pbuf, n);
			data->pbuf += n;
		} else {
			throw_rte (_("Cannot read from the input"));
		}
		data->current += n;
	} else {
		throw std::length_error (_("Trying to read beyond the limit"));
	}
}


void Protobuf_reader::skip (uint32_t tagwt, uint64_t val)
{
	uint32_t t;
	uint64_t n;

	switch (tagwt & 7) {
	case varint:
	case fixed32:
	case fixed64:
	case group_end:
		// Nothing to consume.
		break;

	case length_val:
	case group_len:
		if (data->is) {
			data->is->seekg (val, data->is->cur);
		} else if (data->pbuf + val < data->plim) {
			data->pbuf += val;
		} else {
			throw_rte (_("Trying to skip beyond the input."));
		}
		data->current += val;
		break;

	case group_start:
		for (;;) {
			read_tagval (&t, &n);
			if ((t & 0x7) == group_end) {
				break;
			}
			skip (t, n);
		}
		break;
	}
}

void Protobuf_reader::push_scope (std::streamoff n)
{
	Data::Block b;
	b.limit = data->current + n;
	if (!data->scopes.empty() && data->scopes.top().limit < b.limit) {
		throw std::range_error (_("Protobuf_reader: Inner scope is bigger than outer scope."));
	}
	data->scopes.push (b);
	data->limit = b.limit;
}


bool Protobuf_reader::read_tagval (uint32_t *tagwt, uint64_t *val, bool top_level)
{
	// Calling read_tagval() immediately after having called read_tagval()
	// with a length_val wire type will push a new scope. With this you can
	// have automatic scope management with length val types.
	if (data->current == data->last_pos && data->last_length != 0) {
		push_scope (data->last_length);
		data->last_length = 0;
	}
	data->last_length = 0;

	if (data->current == data->limit && !data->scopes.empty()) {
		*tagwt = group_end;
		check_requirements();
		data->scopes.pop();
		if (!data->scopes.empty()) {
			data->limit = data->scopes.top().limit;
		} else {
			data->limit = std::numeric_limits<decltype(data->limit)>::max();
		}
		return false;
	}

	if (top_level) {
		if (data->is) {
			if (data->is->peek() == EOF) {
				check_requirements();
				return false;
			}
		} else if (data->pbuf == data->plim) {
			check_requirements();
			return false;
		}
	}

	uint64_t t = read_uleb();
	if (t > 0xFFFFFFFF) {
		throw std::out_of_range (_("Protobuf_reader: Read the type tag with a value that does not fit in 32 bits"));
	}
	*tagwt = t;
	switch (*tagwt & 0x7) {
	case group_end:
		if (!data->scopes.empty()) {
			data->scopes.pop();
		}
		if (!data->scopes.empty()) {
			data->limit = data->scopes.top().limit;
		} else {
			data->limit = std::numeric_limits<decltype(data->limit)>::max();
		}
		return false;
	case varint:
		*val = read_uleb();
		break;

	case length_val:
		*val = read_uleb();
		data->last_length = *val;
		data->last_pos = data->current;
		break;

	case group_len:
		*val = read_uleb();
		push_scope (*val);
		break;

	case fixed32:
		*val = read_le32();
		break;

	case fixed64:
		*val = read_le64();
		break;
	}

	if (!data->scopes.empty()) {
		auto req = data->scopes.top().reqs.find (*tagwt >> 3);
		if (req != data->scopes.top().reqs.end()) {
			req->second.count++;
		}
	}
	return true;
}


void Protobuf_reader::add_requirement (uint32_t tagwt, Requirement r)
{
	Req rq;
	rq.r = r;
	if (!data->scopes.empty()) {
		data->scopes.top().reqs[tagwt] = rq;
	}
}


void Protobuf_reader::check_requirements()
{
	if (data->scopes.empty()) return;

	for (const auto &i: data->scopes.top().reqs) {
		switch (i.second.r) {
		case needed_once:
			if (i.second.count != 1) {
				throw_rte (_("Field %d is required once, found %d."), i.first, i.second.count);
			}
			break;

		case needed_many:
			if (i.second.count < 1) {
				throw_rte (_("Field %d is required at least once."), i.first);
			}
			break;

		case optional_once:
			if (i.second.count > 1) {
				throw_rte (_("Field %d can be present only once."), i.first);
			}
			break;

		case optional_many:
			break;
		}
	}
}



}}



// Google protocol buffers wire types:

// The general format of a protocol buffer is a sequence of Tag-Length-Value
// triplets (TLV). Each triplet starts with a tag encoded in ULEB128 form and
// where the lower 3 bits encode the wire type. The wire type carries enough
// information to be able to skip the triplet and continue with the
// following triplet. The following wire types have been defined by Google:

// If the wire type is varint the value is a ULEB128/ZLEB128 encoded number
// that follows the tag. No length field is required.

// If the wire type is fixed32 the value are four bytes that follow the tag.
// No length field is required. If the four bytes are to be interpreted as a
// unit they should be in little endian format.

// If the wire type is fixed64 the value are eight bytes that follow the
// tag. No length field is required. If the eight bytes are to be
// interpreted as a unit they should be in little endian format.

// If the wire type is length_val the length is encoded after the tag as an
// ULEB128 which contains the number of bytes that follow after the length.
// The total size of the triplet is the encoded length value plus the number
// of bytes used to encode the length and the tag.

// If the wire type is group_start, it means that we start a group of
// triplets, which ends when we encounter another tag with the wire type
// group_end. Note that we may nest triplets in this way.

// It is possible to embed groups of triplets using either the group-start
// and group-end tags or by putting the whole group into a length_val
// triplet. If we use the group start and group end tags we do not need to
// know the length of the group and we can use the format in streaming mode,
// where we start transmitting the group immediately before we know all its
// contents. The encoding as a length_val object allows the reader to easily
// skip the whole group without any further processing, but requires that we
// either know the contents of the group before we start encoding or that we
// are using a file stream that can seek backwards.

// A special case is a length_val triplet containing a packed array. It can
// contain a sequence of other triplets, each of them written as above but
// without an id. For instance we could encode an array of 5 elements by
// writing a length_val block whose contents are 5 varints. The varints are
// written sequentially into the block without any tag or length between any
// two varints.

// Although the wire type provides enough information to skip unknown
// triplets you still need to know the structure of the protocol buffer (the
// protocol schema) in order to be able to interpret a protocol buffer.

// See https://tools.ietf.org/html/draft-rfernando-protocol-buffers-00 for a
// definition of the format.

// The wire types listed above are those defined by Google. We add an
// additional wire type, group_len. This is the same as length_val but
// explicitely states that it contains triplets inside. This allows
// debugging tools to dump the whole structure. It also simplifies the API
// of the reader. A tool that knows nothing about the protocol schema will
// treat a length_val type as a block of bytes, whereas a group_len type
// will be inspected for triplets inside it. This is similar to the bit used
// in BER for the same purpose.


// RATIONALE FOR PROTOCOL BUFFERS.

// A protocol buffer is similar to many encodings used for binary file
// formats or protocols which serialize to a binary encoding. As all
// variants of TLV it is a binary serialization format which is extensible,
// backwards and forwards compatible and compact. It is not suited for non
// serial access.

// For non serial access it may be better to use another format which would
// then be memory mapped into the program. In such an application the format
// would be designed to directly map to the memory layout used inside the
// program.

// The Tag-Length-Value encodings (also known as Type-Length-Value) have
// been used in ASN.1 based communication protocols. Using TLV you just
// write a sequence of Tag-Length-Value triplets to the stream. Each TLV
// triplet may in turn contain other triplets itself, allowing a
// hierarchical nesting of triplets. The tag field identifies the type of
// the value in the triplet. The length field allows a program to quickly
// skip the triplet even if it does not understand this triplet type. This
// is the key idea of the tag-length-value encoding: you can add new types
// of triplets and parsers which do not understand the triplet type can skip
// them. This provides the ability to extend the format by adding new
// triplet types without breaking existing parsers.

// ASN.1 even encodes some fields using variable length integers in its BER.
// MIDI uses a big endian variant of base 128 encoding called variable
// length quantity. Another influential format was the IFF, published just
// one year after ASN.1. The IFF has influenced many other formats like
// RIFF, AVI and even PNG. IFF has a general structure of ID-LENGTH-VALUE
// of triplets called chunks, which can also contain embedded chunks.

// The ID and LENGTH are encoded in IFF as fixed length items. This has two
// problems: typical implementations use 4 bytes for each of ID and LENGTH.
// This means that each VALUE chunk carries an overhead of 8 bytes.
// Therefore the value chunk is usually a fixed format structure containing
// many items of information in a given fixed order. This minimizes the
// impact of the 8 bytes of overhead. Although we can extend the format by
// adding new types of fixed format structures (a chunk type in RIFF or PNG
// parlance), once each structure is defined it can't be changed. Another
// problem of IFF-based formats using 4 bytes is that each chunk is limited
// to a length of 2³² bytes. You can have multiple chunks that in
// combination exceed that limit, but each must be less than 4 GiB. The
// MP4/QuickTime format gets around this limitation (relevant for video
// files, which can easily exceed 4 GiB) by defining an alternative length
// field for lengths which may grow beyond 4 GiB. In this way each chunk
// (called atom in QT) has two types of length field: a 32 bit one for
// normal atoms or a 32-bit field set to one and followed by a 64 bit field
// with the real length.

// The original ASN.1 BER uses variable length encodings for the tag and the
// length fields. The EBML format used in Matroska also does away with both
// limitations of IFF by using variable length encoding for the ID and
// LENGTH fields. In this way there is no limitation concerning the maximum
// length of each triplet. Small value lengths and low value IDs can be
// encoded in just one byte each. This encourages to use ID,LENGTH,VALUE
// chunks for each field, even for scalar fields. Thus we can freely add new
// fields to a chunk and existing parsers will be able to ignore them. This
// is an advantage for extensibility.

// The protocol buffers wire format is a refinement of ASN.1. Instead of
// using its own variable length encoding for integers as in ASN.1 or EBML,
// it uses the more known LEB128 format, which is already used in other
// areas (ELF, debugging information). ULEB128 is used for unsigned
// encoding. This is cleaner and easier to encode and decode than the EBML
// encoding. For signed integers zig zag encoding is used instead of the
// traditional SLEB128. Zig zag encoding is easier to encode and decode than
// SLEB128 and it also allows the signed encoding and decoding routines to
// reuse the unsigned ones.

// The protocol buffers encode in the lower 3 bits of the ID the format in
// which the length of the chunk is encoded. For varint, fixed32 and fixed64
// values there is no need to encode a separate length field. When used
// together with a low ID number (less than 32) this feature enables us to
// encode a value with an overhead of just a single byte. Thus you can just
// use TLV triplets to encode each piece of information separately, even each
// scalar value of information. The gain in extensibility costs just a single
// byte per field. For this overhead we gain the possibility to add and
// rearrange each of the fields in each chunk without affecting existing
// parsers. Note that the idea of encoding in the tag the number of bytes
// required for the length is already found in other formats, for instance 
// in the packet format of PGP.

// Google intended the protocol buffers to be used for the encoding of RPC
// There are three features that exist in PNG that are missing in protocol
// buffers.

// PNG files have a header which is designed to immediately catch common
// errors resulting from transmitting or manipulating files. Although such a
// header may not be needed if other mechanisms are present to ensure
// integrity of the data, it is a nice feature for a file format. The PNG
// header is 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A. The purpose of
// each byte is:

// 0x89 Is the first byte of the file and has the high bit set. It detects
// errors produced by systems which do not support 8-bit data. It also
// reduces the chance of interpreting the file as text.

// 0x50,0x4E,0x47 The ASCII values of PNG. This shows the file type when
// catting it to the terminal.

// 0x0D,0x0A CRLF. Detects errors caused by converting Windows line endings
// to unix.

// 0x1A The end of file character for DOS.

// 0x0A LF. Detects errors caused by converting Unix line endings to windows.


// Another feature of the PNG specification is that each chunk carries a CRC
// with it. You can be sure that the data has not been corrupted in a PNG
// file. This feature may not be necessary if there is another higher level
// mechanism that ensures that the data is not corrupted.

// The third feature of PNG that is missing in protocol buffers is the
// distinction made in PNG between critical and non-critical chunks and
// whether an unknown chunk can be copied if the file is modified. A program
// processing PNG files knowns that if it encounters an unknown chunk which
// is marked as critical it should stop processing the PNG because without
// the critical chunk the interpretation of the file would be wrong. A
// program that modifies PNG files must not copy unknown chunks if they
// depend on the data of some other chunks that are being modified (for
// instance an embedded thumbnail image will no longer be valid if we modify
// the main image). It seems that this functionality is better defined for
// each specific application of the format and should not be part of the
// general container format.

// You can define a file format for your application by defining a suitable
// header similar to the PNG header or just a 16-byte UUID, followed by TLV
// triplets as defined in the application with an optional CRC at the end of
// important chunks. If you decide to omit the CRC keep in mind that the
// lack of a CRC may lead to processing corrupted data and producing garbage
// by interpreting part of the file as a valid sequence of chunks.

// There are other formats that have been defined for general binary data
// encoding. IFF has been mentioned above. ASN.1 is more complex and has
// more options. This complexity argues against ASN.1. EBML is similar but
// its encoding is not as compact. It is also not used much beyond Matroska.
// Thrift is very similar to protocol buffers. It includes the distinction
// between field id (the tag) and the field type. This distinction is
// missing in protocol buffers but is present in ASN.1. The encoding of
// structs in Thrift is not a TLV but just a serialization of the fields
// finished by a zero byte. This means that if we want to skip a struct (or
// list or map) we must read its elements. Thrift does not support fast
// skipping of structs/lists/maps. Also in the compact form all integers are
// sent in the varint format.

