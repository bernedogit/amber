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

