// Ask for a master password and generate passwords for each command line
// argument. The only secret is the master password. Then for each argument
// a keyed blake2b hash is generated using the master password as key. You
// only need to remember the master password and keep for each service a word
// that does not need to remain secret, because it will be hashed with the
// master password as key.

#include "symmetric.hpp"
#include "misc.hpp"
#include "hasopt.hpp"
#include <iostream>
#include <iomanip>
#include <string>
#include <string.h>
#include <vector>


using namespace amber;

void process_key(const std::string &s, const std::string &pass)
{
	uint8_t key[32];
#if 0
	// We use shifts==17. This requires 128 MiB of memory.
	scrypt_blake2b (key, sizeof key, pass.c_str(),  pass.size(),
	                (const uint8_t*)s.c_str(), s.size(), 17);
	// It used to be just a wrapper around blake. But it seems better to use
	// Scrypt to provide a better resistance to cracking.
#else
	blake2s (key, sizeof key, pass.c_str(), pass.size(), s.c_str(), s.size());
#endif

	std::string enc;
	amber::base32enc (key + 8, 20, enc, true, false, true);
	format(std::cout, "%09d  %s\n\n", leget64(key) % 1000000000, enc);
}

int main()
{
	std::string pass, id;

	get_password(_("Password: "), pass);

	for (;;) {
		format(std::cout, _("Identifier: "));
		if (!getline(std::cin, id) || id.empty()) break;
		process_key(id, pass);
	}
}


