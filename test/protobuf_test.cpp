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
#include "hasopt.hpp"

using namespace amber;


void write1 (Protobuf_writer &pw)
{
	std::vector<char> vc;

	pw.write_uint (1, 42);
	pw.write_string (2, "hello");
	pw.start_group (3);
		pw.write_uint (1, 24);
		pw.write_uint (2, 25);
   //    pw.write_string (2, "world");
		vc.assign (20000, 'A');
		pw.write_bytes (3, &vc[0], vc.size());
		pw.start_group (9);
		static const char b1[] = "Big ", b2[] = "Bytes";
		pw.add_bytes (b1, sizeof b1 - 1);
		pw.add_bytes (b2, sizeof b2 - 1);
		pw.end_group (true);
	pw.end_group();
	pw.write_float (5, 3.14);
	pw.write_uint32 (6, -3);
	pw.write_string (4, "end of program");
	pw.flush();
}

void write1 (const char *name)
{
	std::ofstream os (name, os.binary);
	Protobuf_writer pw (&os, pw.nogroup, 1000);
	write1 (pw);
}


void read1 (Protobuf_reader &pr)
{
	uint32_t tagwt;
	uint64_t val;
	std::string s;


	while (pr.read_tagval (&tagwt, &val, true)) {
		switch (tagwt) {
		case maketag (1, varint):
			std::cout << "tag 1, v=" << val << std::endl;
			break;

		case maketag (2, length_val):
		case maketag (4, length_val):
			s.resize(val);
			pr.get_bytes (&s[0], val);
			std::cout << "tag " << (tagwt >> 3) << ", s=" << s << std::endl;
			break;

		case maketag (5, fixed32):
			std::cout << "tag 5, x=" << int2float(val) << '\n';
			break;

		case maketag (6, fixed32):
			std::cout << "tag 6, x=" << (int32_t) val << " as unsigned: " << val << '\n';
			break;

		case maketag (3, group_start):
			std::cout << "found a group 3 start\n";
		case maketag (3, group_len):
			pr.add_requirement (1, pr.needed_once, 2, pr.optional_once, 3, pr.optional_many);
			while (pr.read_tagval (&tagwt, &val)) {
				if (tagwt == maketag (3, group_end)) {
					std::cout << "found a group 3 end\n";
					break;
				}
				switch (tagwt) {
				case maketag (1, varint):
					std::cout << "   tag 3-1, v=" << val << '\n';
					break;

				case maketag (2, length_val):
					s.resize (val);
					pr.get_bytes (&s[0], val);
					std::cout << "   tag 3-2, s=" << s << '\n';
					break;

				case maketag (3, length_val):
					pr.skip (tagwt, val);
					std::cout << "   tag 3-3 byte block of size " << val << '\n';
					break;

				default:
					std::cout << "   skipping tagwt: " << std::showbase << std::hex
							<< tagwt << std::dec << "  val=" << val << '\n';
					pr.skip (tagwt, val);
				}
			}
			break;

		default:
			std::cout << "skipping tag=" << tagwt << '\n';
			pr.skip (tagwt, val);
		}
	}
}

void read1 (const char *name)
{
	std::ifstream is (name, is.binary);
	Protobuf_reader pr (&is);
	read1 (pr);
}


void combined()
{
	Protobuf_writer pw (NULL, pw.seek, -1);
	write1 (pw);
	const std::vector<char> &pwb (pw.get_buffer());
	Protobuf_reader pr (&pwb[0], pwb.size());
	read1 (pr);
}

void test_conv()
{
	float f = 2.5;
	uint32_t i = float2int (f);
	float r = int2float (i);
	std::cout << std::hex << "i=" << i << std::dec << '\n';
	std::cout << "r=" << r << '\n';
	double d = 3.14;
	uint64_t ii = double2int(d);
	double rr = int2double (ii);
	std::cout << std::hex << "ii=" << ii << std::dec << '\n';
	std::cout << "rr=" << rr << '\n';
	ii = float2int(f);
	r = int2float (ii);
	std::cout << "ii=" << std::hex << ii << std::dec << '\n';
	std::cout << "r=" << r << '\n';
}


void protohead()
{
	std::ofstream os ("kk.gpb", os.binary);
	Protobuf_writer pw (&os, pw.seek, 10000);
	static const char binh[42] = "Amber Key File\n";
	pw.write_bytes (5, binh, sizeof binh);
	for (int i = 0; i < 20; ++i) {
		char s[100];
		snprintf (s, sizeof s, "Longer This is i=%d\n", i);
		pw.write_string (i, s);
	}
}

int main()
{
	const char name[] = "foo.gpb";
	try {
		write1 (name);
		read1 (name);
	} catch (std::exception &e) {
		std::cout << "exception caught. what: " << e.what() << '\n';
	}
	protohead();
	test_conv();
	combined();
}



