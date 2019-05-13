/*
 * Copyright (c) 2016-2018 Pelayo Bernedo
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
#include "misc.hpp"
#include "hasopt.hpp"
#include <iostream>
#include <fstream>

using namespace amber;

struct How {
	std::string pass;
	Cu25519Pair tx, rx;
	Cu25519Mon rx2p;
	bool pub;
};


void test_random_read(int n, const How &how )
{
	static const char pos_name[] = "random_write_plain.dat";
	static const char cos_name[] = "random_write_crypt.dat";
	std::ofstream pos(pos_name, pos.binary);
	amber::ofstream cos;
	if (how.pub) {
		std::vector<amber::Cu25519Mon> rxv;
		rxv.push_back(how.rx.xp);
		rxv.push_back(how.rx2p);
		cos.open(cos_name, how.tx, rxv);
	} else {
		cos.open(cos_name, how.pass.c_str());
	}

	enum { bufsz = 20000 };
	char buf1[bufsz], buf2[bufsz];

	long long nwritten = 0, nread = 0;

	for (int i = 0; i < n; ++i) {
		amber::randombytes_buf(buf1, bufsz);
		pos.write(buf1, bufsz);
		cos.write(buf1, bufsz);
		nwritten += bufsz;
	}
	pos.close();
	cos.close();

	std::ifstream pis(pos_name, pis.binary);
	amber::ifstream cis;
	if (how.pub) {
		amber::Cu25519Mon txp;
		int nrx;
		cis.open(cos_name, how.rx, &txp, &nrx);
	} else {
		cis.open(cos_name, how.pass.c_str());
	}

	while (pis && cis) {
		pis.read(buf1, sizeof buf1);
		cis.read(buf2, sizeof buf2);
		if (pis.gcount() != cis.gcount()) {
			std::cout << "error: pis.gcount()=" << pis.gcount() << "  cis.gcount()=" << cis.gcount() << '\n';
			break;
		}
		if (pis.gcount() != 0) {
			if (crypto_neq (buf1, buf2, pis.gcount())) {
				std::cout << "error: memcmp failed\n";
				break;
			}
		}
		nread += pis.gcount();
	}
	if (nread != nwritten) {
		std::cout << "wrote " << nwritten << " bytes but read " << nread << " bytes\n";
	}

	nread = 0;
	for (int i = 0; i < n; ++i) {
		pis.clear();
		cis.clear();
		uint32_t x;
		amber::randombytes_buf(&x, 4);
		uint64_t pos = (nwritten * x) >> 32;
		pis.seekg(pos);
		cis.seekg(pos);
		uint32_t toread = bufsz * (x & 0xFFFF) / 0xFFFF;
		if (toread == 0) toread = 1;
		pis.read(buf1, toread);
		cis.read(buf2, toread);
		if (pis.gcount() != cis.gcount()) {
			std::cout << "error: pis.gcount()=" << pis.gcount() << "  cis.gcount()=" << cis.gcount() << " at " << toread << '\n';
			break;
		}
		if (pis.gcount() != 0) {
			if (crypto_neq (buf1, buf2, pis.gcount())) {
				std::cout << "error: memcmp failed\n";
				break;
			}
		}
		nread += pis.gcount();
	}


	std::cout << "pub=" << how.pub << " ";
	std::cout << "long random read finished with nwritten=" << nwritten << "  nread=" << nread << '\n';
}


void test_random_write(int n, const How &how)
{
	static const char pos_name[] = "random_write_plain.dat";
	static const char cos_name[] = "random_write_crypt.dat";
	std::ofstream pos(pos_name, pos.binary);
	amber::ofstream cos;

	if (how.pub) {
		std::vector<amber::Cu25519Mon> rxv;
		rxv.push_back (how.rx.xp);
		rxv.push_back (how.rx2p);
		cos.open (cos_name, how.tx, rxv);
	} else {
		cos.open(cos_name, how.pass.c_str());
	}

	std::streampos fmax = 0;
	char buf[0x10000];

	for (int i = 0; i < n; ++i) {
		uint32_t x;
		amber::randombytes_buf(&x, 4);
		uint64_t np = fmax;
		np = (np*x) >> 32;
		std::streamoff new_pos = np;
		unsigned count = x & 0xFFFF;
		amber::randombytes_buf(buf, count);
		pos.seekp(new_pos);
		cos.seekp(new_pos);
		pos.write(buf, count);
		cos.write(buf, count);
		new_pos += count;
		if (new_pos > fmax) {
			fmax = new_pos;
		}
	}
	pos.close();
	cos.close();

	std::ifstream pis(pos_name, pis.binary);
	amber::ifstream cis;
	if (how.pub) {
		amber::Cu25519Mon txp;
		int nrx;
		cis.open(cos_name, how.rx, &txp, &nrx);
	} else {
		cis.open(cos_name, how.pass.c_str());
	}

	long long nread = 0;
	char buf2[sizeof buf];
	while (pis && cis) {
		pis.read(buf, sizeof buf);
		cis.read(buf2, sizeof buf2);
		if (pis.gcount() != cis.gcount()) {
			std::cout << "error: pis.gcount()=" << pis.gcount() << "  cis.gcount()=" << cis.gcount()
				<< " at block starting at " << nread << '\n';
			std::cout << cis.get_error_info() << '\n';
			break;
		}
		if (pis.gcount() != 0) {
			if (crypto_neq (buf, buf2, pis.gcount())) {
				std::cout << "error: memcmp failed at block starting at " << nread << " length=" << pis.gcount() << "\n";
				for (int i = 0; i < pis.gcount(); ++i) {
					if (buf[i] != buf2[i]) {
						std::cout << "first difference at " << nread + i << '\n';
						std::cout << "good=" << unsigned(buf[i]&0xFF) << "  bad=" << unsigned(buf2[i]&0xFF) << '\n';
						long bu = cis.get_block_size() - cis.get_block_filler();
						long bn = (nread + i)/bu;
						std::cout << "this is block_number=" << bn << ", offset=" << nread + i - bu*bn << '\n';
						std::cout << "block_size=" << cis.get_block_size() << "  block_filler=" << cis.get_block_filler()
							<< "  payload=" << bu << '\n';
						long first_pos = bu * bn;
						if (first_pos >= nread && first_pos < nread + pis.gcount()) {
							std::cout << "first: good=" << unsigned(buf[first_pos - nread]&0xFF) << " bad=" << unsigned(buf2[first_pos - nread]&0xFF) << '\n';
							std::cout << "first pos at " << first_pos << '\n';
						}
						long last_pos = first_pos + bu - 1;
						if (last_pos >= nread && last_pos < nread + pis.gcount()) {
							std::cout << "last: good=" << unsigned(buf[last_pos - nread]&0xFF) << " bad=" << unsigned(buf2[last_pos - nread]&0xFF) << '\n';
							std::cout << "last_pos at " << last_pos << '\n';
						}
						long mid_pos = first_pos + bu/2;
						if (mid_pos >= nread && mid_pos < nread + pis.gcount()) {
							std::cout << "mid: good=" << unsigned(buf[mid_pos - nread]&0xFF) << " bad=" << unsigned(buf2[mid_pos - nread]&0xFF) << '\n';
							std::cout << "mid_pos at " << mid_pos << '\n';
						}
						std::cerr << "failed\n";
						break;
					}
				}
				std::cout << cis.get_error_info() << '\n';
				break;
			}
		}
		nread += pis.gcount();
	}
	std::cout << "pub=" << how.pub << " ";
	std::cout << "long random write finished with fmax=" << fmax << "  n=" << n << '\n';
}


void test_blockbuf(int n)
{
	static const char name[] = "test.dat";
	std::fstream fos(name, fos.binary | fos.in | fos.out | fos.trunc);
	if (!fos) {
		format(std::cerr, _("Cannot open the file %s for writing\n"), name);
		return;
	}
	Blockbuf bb;
	bb.init_write(fos.rdbuf(), "kkti");
	ocryptwrap os(&bb);
	for (int i = 0; i < n; ++i) {
		os << i << '\n';
	}
	os.close();
	fos.close();

	std::ifstream fis(name, fis.binary);
	if (!fis) {
		format(std::cerr, _("Cannot open the file %s for reading\n"), name);
		return;
	}
	bb.init_read(fis.rdbuf(), "kkti");
	insert_icryptbuf(fis, &bb);
	for (int i = 0; i < n; ++i) {
		int x;
		fis >> x;
		if (i != x) {
			format(std::cerr, _("Error while reading from the encrypted file\n"));
			break;
		}
	}
	if (fis.eof()) {
		format(std::cout, _("EOF reached in test_blockbuf, point 1\n"));
	}
	int x;
	fis >> x;
	if (!fis.eof()) {
		format(std::cout, _("EOF not reached in test_blockbuf, point 2\n"));
	}
}

void test_bad_bit()
{
	static const char fn[] = "foo.cha";
	static const char pwd[] = "kkti";
	amber::ofstream os(fn, pwd);
	os << "hello world\n";
	os.close();

	std::fstream tmp(fn, tmp.in | tmp.out);
	tmp.seekp(-1, std::ios_base::end);
	tmp << 'a';
	tmp.close();

	amber::ifstream is(fn, pwd);
	is.exceptions(std::ios_base::badbit);
	std::string ln;
	while (getline(is, ln)) {
		std::cout << "ln=" << ln << '\n';
	}
	std::cout << "is.rdstate()=" << is.rdstate() << "  badbit=" << std::ios_base::badbit << '\n';
	std::cout << "eof=" << std::ios_base::eofbit << "  failbit=" << std::ios_base::failbit << '\n';
}


void real_main()
{
	How how;
	how.pass = "foo";
	how.pub = false;
	test_random_read(500, how);
	test_random_write(500, how);

	amber::randombytes_buf (how.rx.xs.b, 32);
	amber::cu25519_generate(&how.rx.xs, &how.rx2p);
	amber::randombytes_buf(how.rx.xs.b, 32);
	amber::cu25519_generate(&how.rx.xs, &how.rx.xp);
	amber::randombytes_buf(how.tx.xs.b, 32);
	amber::cu25519_generate(&how.tx.xs, &how.tx.xp);
	how.pub = true;

	test_random_read(500, how);
	test_random_write(500, how);
	test_blockbuf(10000);
//  test_bad_bit();
}



int main()
{
	return amber::run_main(real_main);
}
