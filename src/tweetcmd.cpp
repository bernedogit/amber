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

#include "tweetamber.hpp"
#include <unistd.h>
#include <string.h>
#include <vector>
#include <iostream>
#include <fstream>
#include <time.h>

#include "misc.hpp"

#ifdef __unix__
	#define USE_UNISTD_GETPASS
#endif

using namespace twamber;

static
void remove_arg(int *argc, char **argv, int i)
{
	for (int j = i + 1; j < *argc; ++j) {
		argv[j - 1] = argv[j];
	}
	--*argc;
}

static
int hasopt(int *argcp, char **argv, const char *opts, const char **val)
{
	for (int i = 1; i < *argcp; ++i) {
		if (argv[i][0] != '-' || argv[i][1] == '-') continue;
		char *cp = argv[i] + 1;
		while (*cp) {
			for (const char *op = opts; *op; ++op) {
				if (*op == ':') continue;
				if (*op == *cp) {
					if (op[1] == ':') {
						if (cp[1]) {
							*val = cp + 1;
							*cp = 0;
							if (cp == argv[i] + 1) {
								remove_arg(argcp, argv, i);
							}
							return *op;
						} else if (i + 1 < *argcp) {
							*val = argv[i + 1];
							remove_arg(argcp, argv, i + 1);
							if (cp == argv[i] + 1) {
								remove_arg(argcp, argv, i);
							}
							return *op;
						} else {
							return -1;
						}
					} else {
						int res = *cp;
						do {
							*cp = cp[1];
							++cp;
						} while (*cp);
						if (argv[i][1] == 0) {
							remove_arg(argcp, argv, i);
						}
						return res;
					}
				}
			}
			return -1;
			++cp;
		}
	}
	return 0;
}

static void encrypt (std::istream &is, std::ostream &os, const Chakey &key,
                     uint64_t n64, int bs, int bf, const Chakey *ka,
                     size_t nka)
{
	std::vector<char> bufi (bs);
	std::vector<char> bufo (bs + 16*nka);
	unsigned payload = bs - bf;

	uint8_t adflag = 1;
	unsigned nread;
	do {
		randombytes_buf (&bufi[0], bf);
		is.read (&bufi[bf], payload);
		nread = is.gcount();
		if (nread != payload) {
			adflag = 3;
			n64 += UINT64_C(1) << 63;
		}

		encrypt_multi ((uint8_t*)&bufo[0], (uint8_t*)&bufi[0], nread + bf, &adflag, 1, key, ka, nka, n64++);
		adflag = 2;
		os.write (&bufo[0], nread + bf + 16*nka);
	} while (nread == payload);
}

static void encrypt (const char *iname, const char *oname, const char *pass, int shifts, int bs, int bf)
{
	std::ifstream is (iname, is.binary);
	std::ofstream os (oname, os.binary);
	if (!is) {
		std::cerr << "Cannot open the file " << iname << " for reading.\n";
		return;
	}
	if (!os) {
		std::cerr << "Cannot open the file " << oname << " for writing.\n";
		return;
	}

	uint8_t salt[32];
	randombytes_buf (salt, sizeof salt);
	uint8_t key[32];
	scrypt_blake2b (key, sizeof key, pass, strlen(pass), salt, sizeof salt, shifts);
	Chakey kw;
	load (&kw, key);

	os.write ((char*)salt, sizeof salt);

	uint8_t blocks[8], enc[24];
	leput32 (blocks, bs);
	leput32 (blocks + 4, bf);
	encrypt_multi (enc, blocks, sizeof blocks, NULL, 0, kw, &kw, 1, 0);
	os.write ((char*)enc, sizeof enc);
	encrypt (is, os, kw, 1, bs, bf, &kw, 1);
}


static void decrypt (std::istream &is, std::ostream &os, const Chakey &key,
                     uint64_t n64, int bs, int bf, const Chakey &ka,
                     size_t nka, size_t ika)
{
	std::vector<char> bufi (bs + 16*nka);
	std::vector<char> bufo (bs);

	uint8_t adflag = 1;
	size_t nread;
	do {
		is.read (&bufi[0], bufi.size());
		nread = is.gcount();
		if (nread != bufi.size()) {
			adflag = 3;
			n64 += UINT64_C(1) << 63;
		}
		if (decrypt_multi ((uint8_t*)&bufo[0], (uint8_t*)&bufi[0], nread,
		                &adflag, 1, key, ka, nka, ika, n64++) != 0) {
			std::cerr << "Tampered packet. The file has been tampered.\n";
			return;
		}
		adflag = 2;
		os.write (&bufo[bf], nread - 16*nka - bf);
	} while (nread == bufi.size());
}


static void decrypt (const char *iname, const char *oname, const char *pass)
{
	std::ifstream is (iname, is.binary);
	std::ofstream os (oname, os.binary);
	if (!is) {
		std::cerr << "Cannot open the file " << iname << " for reading.\n";
		return;
	}
	if (!os) {
		std::cerr << "Cannot open the file " << oname << " for writing.\n";
		return;
	}

	uint8_t salt[32];
	is.read ((char*)salt, sizeof salt);
	if (is.gcount() != sizeof salt) {
		std::cerr << "Could not read the salt value.\n";
		return;
	}

	uint8_t enc[24], dec[8];
	uint8_t key[32];
	Chakey kw;

	is.read ((char*)enc, sizeof enc);
	if (is.gcount() != sizeof enc) {
		std::cerr << "Could not read the encoded block sizes.\n";
		return;
	}

	int err = -1;
	for (int i = 1; i < 20; ++i) {
		scrypt_blake2b (key, sizeof key, pass, strlen(pass), salt, sizeof salt, i);
		load (&kw, key);
		err = decrypt_multi (dec, enc, sizeof enc, NULL, 0, kw, kw, 1, 0, 0);
		if (err == 0) break;
	}
	if (err) {
		std::cerr << "Could not decrypt the first block. Wrong password?\n";
		return;
	}
	int bs = leget32 (dec);
	int bf = leget32 (dec + 4);

	decrypt (is, os, kw, 1, bs, bf, kw, 1, 0);
}




static uint_fast32_t crc_table[] = {
			 0, 0x77073096, 0xee0e612c, 0x990951ba,  0x76dc419, 0x706af48f,
	0xe963a535, 0x9e6495a3,  0xedb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	 0x9b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
	0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
	0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
	0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
	0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190,  0x1db7106,
	0x98d220bc, 0xefd5102a, 0x71b18589,  0x6b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2,  0xf00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb,  0x86d3d2d,
	0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
	0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
	0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
	0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
	0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6,  0x3b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af,  0x4db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
	 0xd6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d,  0xa00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
	0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
	0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
	0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
	0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c,  0x26d930a, 0x9c0906a9, 0xeb0e363f,
	0x72076785,  0x5005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae,  0xcb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7,  0xbdbdf21, 0x86d3d2d4, 0xf1d4e242,
	0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
	0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
	0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
	0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};


uint_fast32_t update_crc32 (const void *buf, size_t nbytes, uint_fast32_t crc=0)
{
	crc ^= 0xffffffffL;
	const uint_least8_t *bytes = static_cast<const uint_least8_t*>(buf);
	while (nbytes-- > 0) {
		crc = crc_table[(crc ^ *bytes++) & 0xff] ^ (crc >> 8);
	}
	return crc ^ 0xffffffffL;
}

template <class It>
static uint8_t divmod58(It beg, It end)
{
	unsigned rem = 0;
	while (beg != end) {
		unsigned tmp = rem * 256 + *beg;
		*beg = tmp / 58;
		rem = tmp % 58;
		++beg;
	}
	return rem;
}

static uint8_t divmod256(uint8_t *num, size_t len)
{
	unsigned rem = 0;
	for (unsigned i = 0; i < len; ++i) {
		unsigned tmp = rem * 58 + num[i];
		num[i] = tmp / 256;
		rem = tmp % 256;
	}
	return rem;
}

static const unsigned char symbols[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static unsigned char values[256];

struct Init_values {
	Init_values();
};

Init_values::Init_values()
{
	memset(values, 255, sizeof values);
	for (unsigned i = 0; i < sizeof symbols; ++i) {
		values[symbols[i]] = i;
	}
}
static Init_values init_values;

// Encode in base 58 with a CRC byte.
void base58enc (const uint8_t *num, size_t nsize, std::string &res)
{
	std::vector<uint8_t> copy(nsize + 1);
	memcpy(&copy[0], num, nsize);
	copy[nsize] = update_crc32 (num, nsize) & 0xFF;
	res.clear();

	int leading_zeros = 0;
	std::vector<uint8_t>::iterator beg = copy.begin();
	std::vector<uint8_t>::iterator lim = copy.end();
	std::string tmp;
	while (beg < lim && *beg == 0) {
		leading_zeros++;
		res.push_back('1');
		++beg;
	}
	while (beg < lim) {
		uint8_t val = divmod58(beg, lim);
		tmp.push_back(symbols[val]);
		if (*beg == 0) ++beg;
	}
	res.append(tmp.rbegin(), tmp.rend());
}

void base58dec(const char *s, std::vector<uint8_t> &res, size_t n)
{
	std::vector<uint8_t> input;
	const unsigned char *us = (const unsigned char*)s;
	while (n > 0 && *us) {
		if (values[*us] <= 58) {
			input.push_back(values[*us]);
		}
		++us;
		--n;
	}

	res.clear();
	int leading_zeros = 0;
	uint8_t *beg = &input[0];
	uint8_t *lim = &input[input.size()];
	std::vector<uint8_t> tmp;
	while (beg < lim && *beg == 0) {
		leading_zeros++;
		res.push_back(0);
		++beg;
	}
	while (beg < lim) {
		unsigned u = divmod256(beg, lim - beg);
		tmp.push_back(u);
		if (*beg == 0) ++beg;
	}
	auto i = tmp.rbegin();
	auto e = tmp.rend();
	while (i != e && *i == 0) ++i;
	while (i != e) res.push_back(*i++);

	if (!res.empty()) {
		uint32_t crc = update_crc32 (&res[0], res.size() - 1);
		if (res[res.size() - 1] != (crc & 0xFF)) {
			throw std::runtime_error ("Bad CRC while reading public key");
		}
		res.resize (res.size() - 1);
	}
}


void compute_key (const char *pass, Cu25519Sec *xs, Cu25519Ris *xp)
{
	blake2b (xs->b, 32, NULL, 0, pass, strlen(pass));
	cu25519_generate (xs, xp);
}



// Write in buf the noise message for a X handshake. The payload is symk. It
// returns the filled buffer and the symmetric key ka.
void create_noise_x (const Cu25519Sec &txs, const Cu25519Ris &txp,
                     const Cu25519Ris &rx, uint8_t ran[32],
                     const uint8_t symk[33], uint8_t buf[129], Chakey *ka)
{
	uint8_t ck[32], h[32], k[32];
	mix_hash_init (ck, h, "Noise_X_25519_ChaChaPoly_BLAKE2s", NULL, 0);

	mix_hash (h, rx.b, 32);  // rs

	// e
	Cu25519Sec es;
	Cu25519Mon ep;
	Cu25519Ell er;
	memcpy (es.b, ran, 32);
	cu25519_elligator2_gen (&es, &ep, &er);
	memcpy (buf, er.b, 32);
	mix_hash (h, er.b, 32);

	// es
	uint8_t sh[32];
	cu25519_shared_secret (sh, rx, es);
	mix_key (ck, k, sh, 32);

	// s
	Chakey kw;
	load (&kw, k);
	encrypt_multi (buf + 32, txp.b, 32, h, 32, kw, &kw, 1, 0);
	mix_hash (h, buf + 32, 48);

	// ss
	cu25519_shared_secret (sh, rx, txs);
	mix_key (ck, k, sh, 32);

	// Payload
	load (&kw, k);
	encrypt_multi (buf + 32 + 48, symk, 33, h, 32, kw, &kw, 1, 0);

	// split
	mix_key (ck, NULL, 0);
	load (ka, ck);
}


// Parse the noise X message in buf and retrieve the payload to symk, the
// session key to ka and the sender to tx.
int parse_noise_x (const uint8_t buf[129], const Cu25519Sec &xs,
                   const Cu25519Ris &xp, Cu25519Ris *tx, uint8_t symk[33],
                   Chakey *ka)
{
	uint8_t ck[32], h[32], k[32];
	mix_hash_init (ck, h, "Noise_X_25519_ChaChaPoly_BLAKE2s", NULL, 0);

	mix_hash (h, xp.b, 32);  // rs

	// e
	Cu25519Mon ep;
	Cu25519Ell er;
	memcpy (er.b, buf, 32);
	cu25519_elligator2_rev (&ep, er);
	mix_hash (h, er.b, 32);

	// es
	uint8_t sh[32];
	cu25519_shared_secret (sh, ep, xs);
	mix_key (ck, k, sh, 32);

	// s
	Chakey kw;
	load (&kw, k);
	if (decrypt_multi (tx->b, buf + 32, 48, h, 32, kw, kw, 1, 0, 0) != 0) {
		return -1;
	}
	mix_hash (h, buf + 32, 48);

	// ss
	cu25519_shared_secret (sh, *tx, xs);
	mix_key (ck, k, sh, 32);

	// Payload
	load (&kw, k);
	if (decrypt_multi (symk, buf + 32 + 48, 33 + 16, h, 32, kw, kw, 1, 0, 0) != 0) {
		return -1;
	}

	// split
	mix_key (ck, NULL, 0);
	load (ka, ck);
	return 0;
}


void encrypt (const char *iname, const char *oname, const Cu25519Sec &sendxs, const Cu25519Ris &sendxp,
              const Cu25519Ris *vrx, size_t nrx, int block_size, int block_filler)
{
	std::ifstream is (iname, is.binary);
	std::ofstream os (oname, os.binary);
	if (!is) {
		std::cerr << "Cannot open the file " << iname << " for reading.\n";
		return;
	}
	if (!os) {
		std::cerr << "Cannot open the file " << oname << " for writing.\n";
		return;
	}

	uint8_t tmpsym[33];
	tmpsym[32] = nrx;
	randombytes_buf (tmpsym, 32);

	// Authentication keys for each recipient.
	std::vector<Chakey> kav (nrx);

	for (unsigned i = 0; i < nrx; ++i) {
		uint8_t ran[32], buf[129];
		randombytes_buf (ran, 32);
		create_noise_x (sendxs, sendxp, vrx[i], ran, tmpsym, buf, &kav[i]);
		os.write ((char*)buf, sizeof buf);
	}

	uint8_t pt[12];
	leput32(pt, block_size);
	leput32(pt + 4, block_filler);
	memset (pt + 8, 0, 4);
	std::vector<uint8_t> tmpv (12 + nrx * 16);

	// Encryption key.
	Chakey ke;
	load (&ke, tmpsym);
	encrypt_multi (&tmpv[0], pt, 12, NULL, 0, ke, &kav[0], kav.size(), 0);
	os.write ((char*) &tmpv[0], tmpv.size());

	encrypt (is, os, ke, 1, block_size, block_filler, &kav[0], nrx);
}


void decrypt (const char *iname, const char *oname, const Cu25519Sec &xs,
              const Cu25519Ris &xp, Cu25519Ris *sender)
{
	std::ifstream is (iname, is.binary);
	std::ofstream os (oname, os.binary);
	if (!is) {
		std::cerr << "Cannot open the file " << iname << " for reading.\n";
		return;
	}
	if (!os) {
		std::cerr << "Cannot open the file " << oname << " for writing.\n";
		return;
	}

	unsigned i;
	uint8_t buf[129];
	// Encryption key and number of receivers.
	uint8_t symk[33];
	// Authentication key.
	Chakey ka;

	for (i = 0; i < 256; ++i) {
		is.read ((char*)buf, sizeof buf);
		if (is.gcount() != sizeof buf) {
			std::cerr << "This file is not encrypted for this key\n";
			return;
		}
		if (parse_noise_x (buf, xs, xp, sender, symk, &ka) == 0) {
			break;
		}
	}
	if (i == 256) {
		std::cerr << "This file is not encrypted for this key\n";
		return;
	}
	int keypos = i;
	unsigned nrx = symk[32];
	for (i = keypos + 1; i < nrx; ++i) {
		is.read ((char*)buf, sizeof buf);
		if (is.gcount() != sizeof buf) {
			std::cerr << "Wrong format in header.\n";
			return;
		}
	}

	// Decryption key
	Chakey ke;
	load (&ke, symk);

	std::vector<uint8_t> ctv (12 + nrx * 16);
	is.read ((char*) &ctv[0], ctv.size());
	if (is.gcount() != (ptrdiff_t)ctv.size()) {
		std::cerr << "Unexpected end of file while reading the header.\n";
		return;
	}
	uint8_t pt[12];

	if (decrypt_multi (pt, &ctv[0], ctv.size(), NULL, 0, ke, ka, nrx, keypos, 0) != 0) {
		std::cerr << "Error decrypting the header information.\n";
		return;
	}
	int bs = leget32 (pt);
	int bf = leget32 (pt + 4);
	uint32_t info_size = leget32 (pt + 8);

	uint64_t nonce = 1;
	if (info_size != 0) {
		ctv.resize (info_size + nrx * 16);
		is.read ((char*)&ctv[0], ctv.size());
		if (is.gcount() != (ptrdiff_t)ctv.size()) {
			std::cerr << "Unexpected end of file while reading the header.\n";
			return;
		}
		if (decrypt_multi (&ctv[0], &ctv[0], ctv.size(), NULL, 0, ke, ka, nrx, keypos, nonce++) != 0) {
			std::cerr << "Error decrypting the header information.\n";
			return;
		}
	}

	decrypt (is, os, ke, nonce, bs, bf, ka, nrx, keypos);
}


inline void leput64 (unsigned char *x, uint64_t u)
{
	x[0] = u & 0xFF;
	x[1] = (u >> 8) & 0xFF;
	x[2] = (u >> 16) & 0xFF;
	x[3] = (u >> 24) & 0xFF;
	x[4] = (u >> 32) & 0xFF;
	x[5] = (u >> 40) & 0xFF;
	x[6] = (u >> 48) & 0xFF;
	x[7] = (u >> 56) & 0xFF;
}

inline uint64_t leget64 (const unsigned char *x)
{
	uint64_t res = 0;
	for (int i = 0; i < 8; ++i) {
		res |= uint64_t(x[i]) << (i*8);
	}
	return res;
}

static const char sig_prefix[] = "Amber signature prefix";
static const char sig_h1[] = { 0x06, 0x6D, 0x0A, 0x20 };
static const char sig_h2[] = { 0x12, 0x40 };
static const char sig_h3[] = { 0x41 };

void sign (const char *iname, const char *oname, const Cu25519Sec &xs, const Cu25519Ris &xp)
{
	std::ifstream is (iname, is.binary);
	std::ofstream os (oname, os.binary);
	if (!is) {
		std::cerr << "Cannot open the file " << iname << " for reading.\n";
		return;
	}
	if (!os) {
		std::cerr << "Cannot open the file " << oname << " for writing.\n";
		return;
	}

	char buf[10000];
	blake2b_ctx bl;
	blake2b_init (&bl, 64, NULL, 0);
	int nread;
	long long hcount = 0;
	do {
		is.read (buf, sizeof buf);
		nread = is.gcount();
		hcount += nread;
		blake2b_update (&bl, buf, nread);
	} while (nread == sizeof buf);

	blake2b_update (&bl, hcount);
	blake2b_update (&bl, 0);
	time_t now = time(NULL);
	blake2b_update (&bl, now);
	blake2b_final (&bl, buf);

	uint8_t sig[64];
	cu25519_sign (sig_prefix, (uint8_t*)buf, 64, xp, xs, sig);

	os.write (sig_h1, sizeof sig_h1);    os.write ((char*)xp.b, 32);
	os.write (sig_h2, sizeof sig_h2);    os.write ((char*)sig, 64);
	os.write (sig_h3, sizeof sig_h3);
	leput64 ((unsigned char*)buf, now);
	os.write (buf, 8);
}

void verify (const char *iname, const char *sname)
{
	std::ifstream is (iname, is.binary);
	std::ifstream ss (sname, ss.binary);
	if (!is) {
		std::cerr << "Cannot open the file " << iname << " for reading.\n";
		return;
	}
	if (!ss) {
		std::cerr << "Cannot open the file " << sname << " for reading.\n";
		return;
	}

	char buf[10000];
	blake2b_ctx bl;
	blake2b_init (&bl, 64, NULL, 0);
	int nread;
	long long hcount = 0;
	do {
		is.read (buf, sizeof buf);
		nread = is.gcount();
		hcount += nread;
		blake2b_update (&bl, buf, nread);
	} while (nread == sizeof buf);

	blake2b_update (&bl, hcount);
	blake2b_update (&bl, 0);

	uint8_t sigbuf[111];
	ss.read ((char*)sigbuf, sizeof sigbuf);
	if (ss.gcount() != sizeof sigbuf) {
		std::cerr << "Could not read the signature.\n";
		return;
	}
	if (memcmp (sigbuf, sig_h1, sizeof sig_h1) != 0) {
		std::cerr << "Wrong format in signature header.\n";
		return;
	}

	Cu25519Ris xp;
	memcpy (xp.b, sigbuf + sizeof sig_h1, 32);

	if (memcmp (sigbuf + sizeof sig_h1 + 32, sig_h2, sizeof sig_h2) != 0) {
		std::cerr << "Wrong format in signature header.\n";
		return;
	}
	uint8_t sig[64];
	memcpy (sig, sigbuf + sizeof sig_h1 + 32 + sizeof sig_h2, 64);

	if (memcmp (sigbuf + sizeof sig_h1 + 32 + sizeof sig_h2 + 64, sig_h3, sizeof sig_h3) != 0) {
		std::cerr << "Wrong format in signature header.\n";
		return;
	}
	const uint8_t *tb = sigbuf + sizeof sig_h1 + 32 + sizeof sig_h2 + 64 + sizeof sig_h3;
	blake2b_update (&bl, tb, 8);

	blake2b_final (&bl, buf);

	if (cu25519_verify (sig_prefix, (uint8_t*)buf, 64, sig, xp) == 0) {
		std::string id;
		base58enc (xp.b, 32, id);
		std::cout << "Signed by " << id << '\n';
		time_t ts = leget64 (tb);
		tm *tp = gmtime (&ts);
		strftime (buf, sizeof buf, "Signed on %F %T UTC", tp);
		std::cout << buf;
		tp = localtime (&ts);
		strftime (buf, sizeof buf, " =  %F %T %z\n", tp);
		std::cout << buf;
	} else {
		std::cerr << "Wrong signature.\n";
	}
}

#ifndef USE_UNISTD_GETPASS
const char * getpass (const char *prompt)
{
	static std::string pass;
	std::cout << prompt << " ";
	getline (std::cin, pass);
	return pass.c_str();
}
#endif

void usage()
{
	std::cout << "Usage is twcmd [options] infile outfile\n";
	std::cout << "  -c encrypt with a password\n";
	std::cout << "  -C decrypt with a password\n";
	std::cout << "  -e encrypt with keys\n";
	std::cout << "  -E decrypt with keys\n";
	std::cout << "  -n <val> shifts parameter for Scrypt\n";
	std::cout << "  -b <val> block size\n";
	std::cout << "  -f <val> block filler size\n";
	std::cout << "  -r <rx> recipient\n";
	std::cout << "  -p show my padlock\n";
	std::cout << "  -s sign\n";
	std::cout << "  -v verify\n";
}

int real_main (int argc, char **argv)
{
	enum { symenc, symdec, pubenc, pubdec, showid, pubsig, pubver, nothing } op = nothing;
	int shifts = 14;
	int block_size = -1, block_filler = -1;
	std::vector<Cu25519Ris> vrx;
	std::vector<uint8_t> decn;

	int opt;
	const char *val;
	while ((opt = hasopt (&argc, argv, "cCeEpsvn:b:f:r:", &val)) > 0) {
		switch (opt) {
		case 'c':
			op = symenc;
			break;

		case 'C':
			op = symdec;
			break;

		case 'e':
			op = pubenc;
			break;

		case 'E':
			op = pubdec;
			break;

		case 's':
			op = pubsig;
			break;

		case 'v':
			op = pubver;
			break;

		case 'n':
			shifts = atoi (val);
			if (shifts == 0) shifts = 14;
			break;

		case 'b':
			block_size = atoi (val);
			break;

		case 'f':
			block_filler = atoi (val);
			break;

		case 'p':
			op = showid;
			break;

		case 'r':
			base58dec (val, decn, 1000);
			if (decn.size() == 32) {
				Cu25519Ris tmp;
				memcpy (tmp.b, &decn[0], 32);
				vrx.push_back (tmp);
			} else {
				std::cout << "Wrong argument passed to option r: " << val << '\n';
			}
			break;
		}
	}

	if (argc != 3 && op != showid) {
		usage();
		return -1;
	}

	uint16_t rn[2];
	randombytes_buf (&rn, sizeof rn);

	if (block_size <= 0) {
		block_size = rn[0] + 1000;
	}
	if (block_filler < 0 || block_filler >= block_size) {
		block_filler = rn[1] * block_size / 0x10000;
	}

	const char *pass;
	if (op != pubver) {
		pass = getpass ("Enter the password: ");
	}

	Cu25519Sec xs;
	Cu25519Ris xp, txp;
	std::string id;

	switch (op) {
	case symenc:
		encrypt (argv[1], argv[2], pass, shifts, block_size, block_filler);
		break;

	case symdec:
		decrypt (argv[1], argv[2], pass);
		break;

	case pubenc:
		compute_key (pass, &xs, &xp);
		encrypt (argv[1], argv[2], xs, xp, &vrx[0], vrx.size(), block_size, block_filler);
		break;

	case pubdec:
		compute_key (pass, &xs, &xp);
		decrypt (argv[1], argv[2], xs, xp, &txp);
		base58enc (txp.b, 32, id);
		std::cout << "Sender is " << id << '\n';
		break;

	case pubsig:
		compute_key (pass, &xs, &xp);
		sign (argv[1], argv[2], xs, xp);
		break;

	case pubver:
		verify (argv[1], argv[2]);
		break;

	case showid:
		compute_key (pass, &xs, &xp);
		base58enc (xp.b, 32, id);
		std::cout << "id: " << id << '\n';
		break;

	case nothing:
	default:
		std::cout << "No command given. Nothing done.\n";
	}

	return 0;
}


int main (int argc, char **argv)
{
	try {
		return real_main (argc, argv);
	} catch (std::exception &e) {
		std::cerr << "An error has happened. " << e.what() << '\n';
		return -1;
	} catch (...) {
		std::cerr << "An error has happened.\n";
		return -1;
	}
}


