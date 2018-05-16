#include "group25519.hpp"
#include "misc.hpp"
#include "hasopt.hpp"
#include <iostream>
#include <string.h>
#include <fstream>
#include <iomanip>

using namespace amber;

// Vectors from https://tools.ietf.org/html/draft-irtf-cfrg-curves-05
void test_x25519()
{
	std::cout << "Testing X25519 vectors.\n";
	// Alice's private key, f:
	const char asec[] = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
	// Alice's public key, X25519(f, 9):
	const char apub[] = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
	// Bob's private key, g:
	const char bsec[] = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
	// Bob's public key, X25519(g, 9):
	const char bpub[] = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
	// Their shared secret, K:
	const char shared[] = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

	Cu25519Sec as, bs;
	Cu25519Pub ap, bp, rap, rbp;
	std::vector<uint8_t> tmp;
	const char *last;

	read_block (asec, &last, tmp);
	if (*last || tmp.size() != 32) {
		std::cout << "error reading key\n";
		return;
	}
	memcpy (as.b, &tmp[0], 32);

	read_block (bsec, &last, tmp);
	if (*last || tmp.size() != 32) {
		std::cout << "error reading key\n";
		return;
	}
	memcpy (bs.b, &tmp[0], 32);

	read_block (apub, &last, tmp);
	if (*last || tmp.size() != 32) {
		std::cout << "error reading key\n";
		return;
	}
	memcpy (rap.b, &tmp[0], 32);

	read_block (bpub, &last, tmp);
	if (*last || tmp.size() != 32) {
		std::cout << "error reading key\n";
		return;
	}
	memcpy (rbp.b, &tmp[0], 32);

	read_block (shared, &last, tmp);
	if (*last || tmp.size() != 32) {
		std::cout << "error reading key\n";
		return;
	}

	cu25519_generate (&as, &ap);
	ap.b[31] &= 0x7F;
	if (crypto_neq (ap.b, rap.b, 32)) {
		std::cout << "Error in generating the public key 1\n";
		show_block (std::cout, "scalar  ", as.b, 32);
		show_block (std::cout, "computed", ap.b, 32);
		show_block (std::cout, "expected", rap.b, 32);
		return;
	}
	cu25519_generate (&bs, &bp);
	bp.b[31] &= 0x7F;
	if (crypto_neq (bp.b, rbp.b, 32)) {
		std::cout << "Error in generating the public key 2\n";
		show_block (std::cout, "scalar  ", bs.b, 32);
		show_block (std::cout, "computed", bp.b, 32);
		show_block (std::cout, "expected", rbp.b, 32);
		return;
	}
	uint8_t sh[32];
	cu25519_shared_secret (sh, ap, bs);
	if (crypto_neq (sh, &tmp[0], 32)) {
		std::cout << "error in shared key\n";
		show_block (std::cout, "computed", sh, 32);
		show_block (std::cout, "expected", &tmp[0], 32);
		return;
	}
	cu25519_shared_secret (sh, bp, as);
	if (crypto_neq (sh, &tmp[0], 32)) {
		std::cout << "error in shared key\n";
		show_block (std::cout, "computed", sh, 32);
		show_block (std::cout, "expected", &tmp[0], 32);
		return;
	}
	std::cout << "X25519 vectors tested.\n";
}



struct Test_case {
	const char *sec, *pub, *msg, *sig;
};


static const Test_case ietf[] = {

{   // SECRET KEY:
	"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
	// PUBLIC KEY:
	"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
	// MESSAGE (length 0 bytes):
	"",
	// SIGNATURE:
	"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
	"5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
},
{
	// SECRET KEY:
	"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
	// PUBLIC KEY:
	"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
	// MESSAGE (length 1 byte):
	"72",
	// SIGNATURE:
	"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
	"085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
},
{
	// SECRET KEY:
	"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
	// PUBLIC KEY:
	"fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
	// MESSAGE (length 2 bytes):
	"af82",
	// SIGNATURE:
	"6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
	"18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
}

};

void test_ed25519 (const Test_case *tc, size_t n)
{
	std::vector<uint8_t> tmp, msg;
	const char *next;

	std::cout << "Testing " << n << " IETF Ed25519 test vectors.\n";

	while (n > 0) {
		uint8_t seed[32], ey[32], eygood[32];
		read_block (tc->sec, &next, tmp);
		if (*next) {
			std::cout << "Error reading the secret key.\n";
			return;
		}
		if (tmp.size() != 32) {
			std::cout << "The key must be 32 bytes long. Got " << tmp.size() << ".\n";
			return;
		}
		memcpy (seed, &tmp[0], tmp.size());

		read_block (tc->pub, &next, tmp);
		if (*next) {
			std::cout << "Error reading the public key.\n";
			return;
		}
		if (tmp.size() != 32) {
			std::cout << "The key must be 32 bytes long. Got " << tmp.size() << ".\n";
			return;
		}
		memcpy (eygood, &tmp[0], tmp.size());

		ed25519_seed_to_ey (ey, seed);

		if (crypto_neq (ey, eygood, 32)) {
			std::cout << "Error in the computed public Ed25519 key.\n";
			show_block (std::cout, "computed", ey, 32);
			show_block (std::cout, "good    ", eygood, 32);
			return;
		}

		read_block (tc->msg, &next, tmp);
		if (*next) {
			std::cout << "Error reading the message.\n";
			return;
		}
		msg = std::move (tmp);

		read_block (tc->sig, &next, tmp);
		if (*next) {
			std::cout << "Error reading the signature.\n";
			return;
		}
		if (tmp.size() != 64) {
			std::cout << "The signature must be 64 bytes long. Got " << tmp.size() << ".\n";;
			return;
		}

		uint8_t mysig[64];
		sign_sey (&msg[0], msg.size(), ey, seed, mysig);

		if (crypto_neq (mysig, &tmp[0], 64)) {
			std::cout << "The signature is wrong.\n";
			return;
		}
		if (0 != verify_sey (&msg[0], msg.size(), mysig, ey)) {
			std::cout << "The verication with ey failed.\n";
			return;
		}

		uint8_t mx[32];
		ey_to_mx (mx, ey);

		if (0 != verify_sey (&msg[0], msg.size(), mysig, mx, false)) {
			std::cout << "The verification with mx failed.\n";
			return;
		}

		--n;
		++tc;
	}
	std::cout << "All Ed25519 tests finished.\n";
}


void show_const()
{
	std::cout << "\nConstants used in the program\n";
	Fe x, y, z;
	memset (x.v, 0, sizeof x);
	x.v[0] = 2;
	raise_253_5 (y, x);
	std::cout << "sqrt(-1) = 2^(2²⁵³ - 5) =" << y << '\n';
	show_raw ("sqrt(-1) raw", y);
	x.v[0] = 486664;
	if (sqrt(z, x) == 0) {
		std::cout << "C = sqrt(A+2): " << z << '\n';
		show_raw ("C = sqrt(A+2), raw", z);
		negate (z,z);
		show_raw ("C = sqrt(A+2), raw", z);

		mul (z, z, y);
		std::cout << "sqrt(-1)*sqrt(A+2): " << z << '\n';
		negate (z, z);
		std::cout << "sqrt(-1)*sqrt(A+2): " << z << '\n';
		show_raw ("sqrt(-1)*sqrt(A+2) raw", z);
	}

	// d = -121665/121666
	x.v[0] = 121665;
	negate (y, x);
	x.v[0] = 121666;
	invert (z, x);
	mul (y, y, z);
	std::cout << "d: " << y << '\n';
	show_raw ("d raw", y);
	add (y, y, y);
	show_raw ("2d raw", y);

	uint8_t bu[32] = { 9 };
	Edwards e;
	mx_to_edwards (e, bu, false);
	std::cout << "basepoint in Edwards:\n";
	// Normalize to z = 1.
	invert (y, e.z);
	mul (e.x, e.x, y);
	mul (e.y, e.y, y);
	memset (e.z.v, 0, sizeof(Fe));
	e.z.v[0] = 1;
	mul (e.t, e.x, e.y);
	show_raw ("b.x", e.x);
	show_raw ("b.y", e.y);
	show_raw ("b.z", e.z);
	show_raw ("b.t", e.t);
}



void test_scalarmult()
{
	Cu25519Sec xs;
	Cu25519Pub xp;
	randombytes_buf (xs.b, 32);
	cu25519_generate (&xs, &xp);

	Edwards e1;
	uint8_t mx[32];

	scalarbase (e1, xs.b);
	edwards_to_mx (mx, e1);
	if (memcmp (xp.b, mx, 32) != 0) {
		format (std::cout, "Error in scalarbase().\n");
	}
	scalarmult (e1, edwards_base_point, xs.b);
	edwards_to_mx (mx, e1);
	if (memcmp (xp.b, mx, 32) != 0) {
		format (std::cout, "Error in scalarmult().\n");
	}
	scalarmult_fw (e1, edwards_base_point, xs.b);
	edwards_to_mx (mx, e1);
	if (memcmp (xp.b, mx, 32) != 0) {
		format (std::cout, "Error in scalarmult_fw().\n");
	}

	montgomery_base (e1, xs.b);
	edwards_to_mx (mx, e1);
	if (memcmp (xp.b, mx, 32) != 0) {
		format (std::cout, "Error in montgomery_base(Edwards).\n");
	}
	montgomery_base (mx, xs.b);
	if (memcmp (xp.b, mx, 32) != 0) {
		format (std::cout, "Error in montgomery_base(mx).\n");
	}
	montgomery_ladder (e1, edwards_base_point, xs.b);
	edwards_to_mx (mx, e1);
	if (memcmp (xp.b, mx, 32) != 0) {
		format (std::cout, "Error in montgomery_ladder(Edwards).\n");
	}

	format (std::cout, "Scalar multiplication tested.\n");
}


void test_conv()
{
	uint8_t sc[32];
	Edwards e1, e2;

	randombytes_buf (sc, 32);
	mask_scalar(sc);
	scalarbase (e1, sc);

	Fe u, v;
	static const Fe feone = { 1 };
	edwards_to_mont (u, v, e1);
	mont_to_edwards (e2, u, v, feone);

	uint8_t ey1[32], ey2[32];
	edwards_to_ey (ey1, e1);
	edwards_to_ey (ey2, e2);
	if (memcmp (ey1, ey2, 32) != 0) {
		format (std::cout, "Error in edwards/mont conversions.\n");
	}
}


int main()
{
	test_x25519();
	test_ed25519 (ietf, sizeof(ietf)/sizeof(ietf[0]));
	show_const();
	write_summands ("summands.txt");
	test_conv();
	test_scalarmult();
}


