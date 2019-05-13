#include "misc.hpp"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <string>

int main (int argc, char **argv)
{
	for (int i = 1; i < argc; ++i) {
		std::ifstream is (argv[i]);
		if (!is) continue;
		std::string ln;
		std::vector<unsigned char> v;
		const char *next;
		while (getline (is, ln)) {
			v.clear();
			amber::read_block (&ln[0], &next, v);
			if (!v.empty()) {
				std::cout << std::hex << std::setfill('0');
				std::cout << "   { ";
				for (unsigned i = 0; i < v.size(); ++i) {
					std::cout << "0x" << std::setw(2) << unsigned(v[i]) << ", ";
				}
				std::cout << "\n";
			}
		}
	}
}

