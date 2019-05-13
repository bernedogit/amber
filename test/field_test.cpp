#include "hasopt.hpp"
#include "field25519.hpp"
#include <string.h>

using namespace amber;

int main()
{
	Fe x, res;
	memset (&x, 0, sizeof x);
	invert (res, x);         // inv(0) produces zero.
	format (std::cout, "inverting %s yields %s\n", x, res);

	int errc;
	for (int i = 0; i < 5; ++i) {
		x.v[0] = i;
		errc  = sqrt (res, x);
		format (std::cout, "sqrt %s yields %s, errc=%d\n", x, res, errc);
		errc = invsqrt (res, x);
		format (std::cout, "invsqrt %s yields %s, errc=%d\n", x, res, errc);
	}
}

