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

#include "blake2.hpp"
#include "hasopt.hpp"
#include <string.h>

using namespace amber;

void compare (const char *p1, size_t n1, const char *p2, size_t n2, const char *p3, size_t n3)
{
	blake2b_ctx ctx;
	blake2b_init (&ctx, 64);
	blake2b_update (&ctx, p1, n1);
	blake2b_update (&ctx, p2, n2);
	blake2b_update (&ctx, p3, n3);
	char h1[64];
	blake2b_final (&ctx, h1);

	blake2b_init (&ctx, 64);
	blake2b_update (&ctx, p1, n1, p2, n2, p3, n3);
	char h2[64];
	blake2b_final (&ctx, h2);

	if (memcmp (h1, h2, 64) != 0) {
		format (std::cout, "the hashes differ\n");
	} else {
		format (std::cout, "the hashes are equal\n");
	}
}


int main()
{
	const char s1[] = "foo";
	const char s2[] = "bar";
	const char s3[] = "foobar";
	compare (s1, sizeof s1, s2, sizeof s2, s3, sizeof s3);
}

