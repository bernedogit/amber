#include <iostream>
#include <fstream>
#include <stdlib.h>

int main(int argc, char **argv)
{
	if (argc != 3) {
		std::cerr << "usage is tamper file pos\n";
		return -1;
	}

	std::fstream fs(argv[1], fs.binary | fs.in | fs.out);
	if (!fs) {
		std::cout << "can't open the file " << argv[1] << '\n';
		return -1;
	}

	std::streamoff pos = atoll(argv[2]);
	std::cout << "modifying byte at position " << pos << '\n';
	fs.seekg(pos);
	char ch = fs.get();
	fs.seekp(pos);
	if (!fs) {
		std::cout << "error while seeking\n";
	}
	++ch;
	fs << ch;
}
