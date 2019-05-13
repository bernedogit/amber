#include "group25519.hpp"
#include "hasopt.hpp"

using namespace amber;

void test_altsig()
{
	Edwards es1, es2, eres;
	uint8_t sc1[32], sc2[32];

	randombytes_buf (sc1, 32);
	randombytes_buf (sc2, 32);

	mask_scalar (sc1);
	mask_scalar (sc2);

	scalarbase (es1, sc1);
	scalarbase (es2, sc2);
	add (eres, es1, es2);

	uint8_t mx1[32], mx2[32], mres[32];
	edwards_to_mx (mx1, es1);
	edwards_to_mx (mx2, es2);
	mx1[31] &= 0x7F;
	mx2[31] &= 0x7F;
	edwards_to_mx (mres, eres);

	static const uint8_t mbase[32] = { 9 };
	uint8_t ml1[32], ml2[32];
	montgomery_ladder (ml1, mbase, sc1);
	montgomery_ladder (ml2, mbase, sc2);

	if (memcmp (mx1, ml1, 32) != 0) {
		show_block (std::cout, "mx1", mx1, 32);
		show_block (std::cout, "ml1", ml1, 32);
	}
	if (memcmp (mx2, ml2, 32) != 0) {
		show_block (std::cout, "mx2", mx2, 32);
		show_block (std::cout, "ml2", ml2, 32);
	}

	Fe u1, u2, u3;
	load (u1, mres);
	load (u2, mx1);
	load (u3, mx2);

	// 4(u1 + u2 + u3 + A)(u1u2u3) = (1 - u1u2 - u2u3 - u3u1)²
	Fe s1, s2, tmp;
	add (s1, u1, u2);
	add (s1, s1, u3);
	s1.v[0] += 486662;
	mul_small (s1, s1, 4);
	mul (s1, s1, u1);
	mul (s1, s1, u2);
	mul (s1, s1, u3);

	static const Fe feone = { 1 };
	mul (s2, u1, u2);
	mul (tmp, u2, u3);
	add (s2, s2, tmp);
	mul (tmp, u3, u1);
	add (s2, s2, tmp);
	sub (s2, feone, s2);
	square (s2, s2);

	uint8_t lh[32], rh[32];
	reduce_store (lh, s1);
	reduce_store (rh, s2);

	if (memcmp (lh, rh, 32) != 0) {
		show_block (std::cout, "lh", lh, 32);
		show_block (std::cout, "rh", rh, 32);
	} else {
		format (std::cout, "Normal coordinates match.\n");
	}

	Fe tmp1, tmp2, res;

	// qDSA method. It seems that the projective formulae by Hamburg are
	// better than projective qDSA.
	sub (tmp1, u2, u3);
	mul (tmp1, tmp1, u1);
	square (res, tmp1);

	mul (tmp1, u2, u3);
	tmp1.v[0]++;
	add (tmp2, u2, u3);
	mul (tmp1, tmp1, tmp2);
	mul (tmp1, tmp1, u1);
	sub (res, res, tmp1);
	sub (res, res, tmp1);

	mul (tmp1, u1, u2);
	mul (tmp1, tmp1, u3);
	mul_small (tmp1, tmp1, 4*486662);
	sub (res, res, tmp1);

	mul (tmp1, u2, u3);
	sub (tmp1, tmp1, feone);
	square (tmp1, tmp1);
	add (res, res, tmp1);

	std::cout << "qDSA residual=" << res << '\n';

	Fe fu1, fu2, fu3, fz2, fz3;
	static const Fe fbase = { 9 };
	montgomery_ladder (fu2, fz2, fbase, sc1);
	montgomery_ladder (fu3, fz3, fbase, sc2);
	invert (tmp1, fz2);     mul (tmp1, tmp1, fu2);
	invert (tmp2, fz3);     mul (tmp2, tmp2, fu3);
	uint8_t mm1[32], mm2[32];
	reduce_store (mm1, tmp1);
	reduce_store (mm2, tmp2);
	if (memcmp (mm1, mx1, 32) != 0 || memcmp (mm2, mx2, 32) != 0) {
		format (std::cout, "Wrong montgomery ladder\n");
	}

	/*
	4(u1 + u2 + u3 + A)(u1u2u3) = (1 - u1u2 - u2u3 - u3u1)²
	4 (U1.Z2.Z3 + U2.Z1.Z3 + U3.Z1.Z2 + A.Z1.Z2.Z3) (U1.U2.U3) = (Z1.Z2.Z3 - U1.U2.Z3 - U2.U3.Z1 - U3.U1.Z2)²
	4 (U1.Z2.Z3 + U2.Z3 + U3.Z2 + A.Z2.Z3) (U1.U2.U3) = (Z2.Z3 - U1.U2.Z3 - U2.U3 - U3.U1.Z2)²

	if u2 == u3
		v = u2 = u3
		4 (u1 + 2v + A)uv² = (1 - 2u1v - v²)²
	*/

	Fe ss1, ss2;
	memcpy (&fu1, &u1, sizeof u1);
	mul (ss1, fu1, fz2);     mul (ss1, ss1, fz3);
	mul (tmp1, fu2, fz3);
	add (ss1, ss1, tmp1);
	mul (tmp1, fu3, fz2);
	add (ss1, ss1, tmp1);
	mul (tmp1, fz2, fz3);
	mul_small (tmp1, tmp1, 486662);
	add (ss1, ss1, tmp1);
	mul_small (ss1, ss1, 4);
	mul (ss1, ss1, fu1);
	mul (ss1, ss1, fu2);
	mul (ss1, ss1, fu3);

	mul (ss2, fu1, fu2);
	mul (ss2, ss2, fz3);
	mul (tmp1, fu2, fu3);
	add (ss2, ss2, tmp1);
	mul (tmp1, fu3, fu1);
	mul (tmp1, tmp1, fz2);
	add (ss2, ss2, tmp1);
	mul (tmp1, fz2, fz3);
	sub (ss2, tmp1, ss2);
	square (ss2, ss2);

	uint8_t flh[32], frh[32];
	reduce_store (flh, ss1);
	reduce_store (frh, ss2);

	if (memcmp (flh, frh, 32) != 0) {
		show_block (std::cout, "flh", flh, 32);
		show_block (std::cout, "frh", frh, 32);
	} else {
		format (std::cout, "Projective coordinates match.\n");
	}

	/*
	4 (U1.Z2.Z3 + U2.Z3 + U3.Z2 + A.Z2.Z3) (U1.U2.U3) = (Z2.Z3 - U1.U2.Z3 - U2.U3 - U3.U1.Z2)²
	*/
	Fe z2z3, u3z2, u1u2;
	mul (z2z3, fz2, fz3);
	mul (s1, z2z3, fu1);
	mul (tmp1, fu2, fz3);           add (s1, s1, tmp1);
	mul (u3z2, fu3, fz2);           add (s1, s1, u3z2);
	mul_small (tmp1, z2z3, 486662); add (s1, s1, tmp1);
	mul (u1u2, fu1, fu2);
	mul (s1, s1, u1u2);
	mul (s1, s1, fu3);
	mul_small (s1, s1, 4);

	mul (s2, u1u2, fz3);
	mul (tmp1, fu2, fu3);
	add (s2, s2, tmp1);
	mul (tmp1, u3z2, fu1);
	add (s2, s2, tmp1);
	sub (s2, z2z3, s2);
	square (s2, s2);

	reduce_store (lh, s1);
	reduce_store (rh, s2);

	if (memcmp (lh, rh, 32) != 0) {
		show_block (std::cout, "lh", lh, 32);
		show_block (std::cout, "rh", rh, 32);
	} else {
		format (std::cout, "Projective coordinates opt match.\n");
	}

	sub (s1, s1, s2);
	std::cout << "s1=" << s1 << '\n';
}

int main()
{
	test_altsig();
}

