#include <iostream>
#include <fstream>
#include <stdlib.h>
#include "symmetric.hpp"
#include "hasopt.hpp"

using namespace amber;

void usage()
{
	format(std::cout, _("wipe -n <size> -m <size> files...\n"));
	format(std::cout, _("Wipe or create files by filling them with random bytes.\n"));
	format(std::cout, _("The -n option gives the size of the file after wiping.\n"));
	format(std::cout, _("If the -n option is not given the current size of the file will be used.\n"));
	format(std::cout, _("If no -n option is given then the -m option specifies the maximum size\n"
						"for files which do not exist. The actual size will be a random value up\n"
						"to this maximum.\n"));
}

int main(int argc, char **argv)
{
	const char *val;
	size_t sz = 0, maxsz = 0;

	if (hasopt_long(&argc, argv, "--help")) {
		usage();
		return 0;
	}

	switch (hasopt(&argc, argv, "hn:m:", &val)) {
	case 'n':
		sz = atoll(val);
		break;

	case 'm':
		maxsz = atoll(val);
		break;

	case 'h':
		usage();
		break;
	}

	Keyed_random kr;

	for (int i = 1; i < argc; ++i) {
		size_t nwrite = sz;
		if (sz == 0) {
			std::ifstream is(argv[i], is.binary);
			if (maxsz != 0) {
				uint32_t rnd;
				kr.get_bytes((uint8_t*)&rnd, sizeof rnd);
				nwrite = ((uint64_t(maxsz) * rnd) >> 32) + 1;
			} else if (!is) {
				format(std::cerr, _("No size was given and the file %s does not exist. Skipping it.\n"), argv[i]);
				continue;
			} else {
				is.seekg(0, is.end);
				nwrite = is.tellg();
			}
		}
		std::ofstream os(argv[i], os.binary);
		if (!os) {
			format(std::cerr, _("Could not create the file %s\n"), argv[i]);
			continue;
		}
		static const size_t bufsz = 10000u;
		char buf[bufsz];
		size_t pending = nwrite;
		while (pending > 0) {
			size_t n = pending > bufsz ? bufsz : pending;
			kr.get_bytes(buf, n);
			os.write(buf, n);
			pending -= n;
		}
	}
}

