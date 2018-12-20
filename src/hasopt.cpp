/* Copyright (c) 2015-2017 Pelayo Bernedo.
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




#include "hasopt.hpp"
#include <string.h>
#include <exception>
#include <iostream>
#include <stdlib.h>



namespace amber {   namespace AMBER_SONAME {

static
void remove_arg(int *argc, char **argv, int i)
{
	for (int j = i + 1; j < *argc; ++j) {
		argv[j - 1] = argv[j];
	}
	--*argc;
}


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


// Check if a flag was passed in the command line and remove it from the
// arguments.

bool hasopt_long (int *argc, char **argv, const char *longopt)
{
	for (int i = 1; i < *argc; ++i) {
		if (strcmp(argv[i], longopt) == 0) {
			for (int j = i + 1; j < *argc; ++j) {
				argv[j - 1] = argv[j];
			}
			--*argc;
			return true;
		}
	}
	return false;
}


// Check if an option with a value was passed in the command line and remove
// it from the arguments.

bool hasopt_long(int *argc, char **argv, const char *longopt,
                 const char **val)
{
	size_t olen = strlen(longopt);

	for (int i = 1; i < *argc; ++i) {
		if (strncmp(argv[i], longopt, olen) == 0) {
			if (argv[i][olen] == '=' || argv[i][olen] == ':') {
				*val = argv[i] + olen + 1;
				for (int j = i + 1; j < *argc; ++j) {
					argv[j - 1] = argv[j];
				}
				--*argc;
				return true;
			} else if (argv[i][olen] == 0) {
				if (i + 1 < *argc) {
					*val = argv[i + 1];
					for (int j = i + 2; j < *argc; ++j) {
						argv[j - 2] = argv[j];
					}
					*argc -= 2;
					return true;
				}
			}
		}
	}
	return false;
}



std::string describe(const std::exception &e)
{
	std::string res("Reason: ");
	res += e.what();
	res += '\n';

	try {
		std::rethrow_if_nested(e);
	} catch (std::exception &e) {
		res += describe(e);
	} catch (...) {
		res += "Unknown exception class\n";
	}
	return res;
}

static void show_exception(std::exception &e, bool first=true)
{
	if (first) {
		std::cerr << _("The program was interrupted\n");
	}
	format(std::cerr, _("Reason: %s\n"), e.what());

	try {
		std::rethrow_if_nested(e);
	} catch (std::exception &ne) {
		show_exception(ne, false);
	} catch (...) {
		std::cerr << _("Unknown exception has been caught.\n");
	}
}


int run_main(int (*real_main)())
{
	try {
		return real_main();
	} catch (std::exception &e) {
		show_exception(e);
		return EXIT_FAILURE;
	} catch (...) {
		std::cerr << _("Some unknown exception was caught.\n");
		return EXIT_FAILURE;
	}
}


int run_main(void (*real_main)())
{
	try {
		real_main();
		return EXIT_SUCCESS;
	} catch (std::exception &e) {
		show_exception(e);
		return EXIT_FAILURE;
	} catch (...) {
		std::cerr << _("Some unknown exception was caught.\n");
		return EXIT_FAILURE;
	}
}


int run_main(int argc, char **argv, int (*real_main)(int,char**))
{
	try {
		return real_main(argc, argv);
	} catch (std::exception &e) {
		show_exception(e);
		return EXIT_FAILURE;
	} catch (...) {
		std::cerr << _("Some unknown exception was caught.\n");
		return EXIT_FAILURE;
	}
}


void process_format_stream (std::ostream &os, const char **fmt,
                            int *argnum, int *saved_prec, int *wa, int *pa)
{
	const char *sow = *fmt;
	const char *eow = sow;
	bool argument_found = false;

	*saved_prec = os.precision ();

	for (;;) {
		while (*eow && *eow != '%') ++eow;
		if (eow != sow) {
			os.write (sow, eow - sow);
		}
		if (*eow == '%' && eow[1] == '%') {
			os << '%';
			eow += 2;
			sow = eow;
		} else {
			break;
		}
	}

	if (*eow == '%') {
		if (isdigit(eow[1])) {
			char *endstr;
			int val = strtol (eow + 1, &endstr, 10);
			if (*endstr == '%') {
				*fmt = endstr + 1;
				*argnum = val;
				return;
			} else if (*endstr == '$') {
				*argnum = val;
				 eow = endstr + 1;
			} else {
				++eow;
				++*argnum;
			}
		} else {
			++eow;
			++*argnum;
		}
		argument_found = true;

		bool align_left = false;
		bool show_base = false;
		bool show_pos = false;

		std::ios_base::fmtflags mask = (std::ios_base::fmtflags) (
				std::ios_base::left | std::ios_base::right | std::ios_base::internal |
				std::ios_base::showbase | std::ios_base::uppercase | std::ios_base::showpos |
				std::ios_base::showpoint |
				std::ios_base::oct | std::ios_base::hex | std::ios_base::dec |
				std::ios_base::fixed | std::ios_base::scientific );

		std::ios_base::fmtflags how = (std::ios_base::fmtflags) (os.flags() & (std::ios_base::fmtflags)(~mask));

		while (*eow == '-' || *eow == '#' || *eow == '+') {
			if (*eow == '-') {
				align_left = true;
				++eow;
			}
			if (*eow == '#') {
				show_base = true;
				++eow;
			}
			if (*eow == '+') {
				show_pos = true;
				++eow;
			}
		}

		if (align_left) {
			how |= std::ios_base::left;
		} else {
			how |= std::ios_base::right;
		}
		if (show_base) {
			how |= std::ios_base::showbase | std::ios_base::showpoint;
		}
		if (show_pos) {
			how |= std::ios_base::showpos;
		}

		if (*eow == '0') {
			os.fill('0');
			++eow;
		} else {
			os.fill(' ');
		}

		// Collect the width.
		if (*eow == '*') {
			const char *ar = eow + 1;
			if (isdigit (*ar)) {
				while (isdigit(*ar)) ++ar;
				*wa = atoi (eow + 1);
				if (*ar != '$') {
					throw std::runtime_error ("Wrong format in width specification *m$");
				}
				eow = ar + 1;
			} else {
				*wa = *argnum;
				++*argnum;
				eow++;
			}
		} else {
			*wa = -1;
			const char *wp = eow;
			while (isdigit(*eow)) ++eow;
			if (wp != eow) {
				std::streamsize width = atoi (wp);
				os.width (width);
			}
		}

		// Collect the precision.
		if (*eow == '.') {
			++eow;
			if (*eow == '*') {
				const char *ar = eow + 1;
				if (isdigit (*ar)) {
					while (isdigit(*ar)) ++ar;
					*pa = atoi (eow + 1);
					if (*ar != '$') {
						throw std::runtime_error ("Wrong format in width specification *m$");
					}
					eow = ar + 1;
				} else {
					*pa = *argnum;
					++*argnum;
					eow++;
				}
			} else {
				*pa = -1;
				const char *wp = eow;
				while (isdigit(*eow)) ++eow;
				if (wp != eow) {
					int prec = atoi (wp);
					os.precision (prec);
				}
			}
		}

		// Just ignore any size specifiers.
		if (*eow == 'h') {
			if (eow[1] == 'h') {
				eow += 2;
			} else {
				eow++;
			}
		} else if (*eow == 'l') {
			if (eow[1] == 'l') {
				eow += 2;
			} else {
				eow++;
			}
		} else if (*eow == 'j' || *eow == 'z' || *eow == 't' || *eow == 'L') {
			++eow;
		}

		// Now the format itself.
		switch (*eow) {
		case 'o':
			os.flags (how | std::ios_base::oct);
			break;

		case 'X':
			os.flags (how | std::ios_base::uppercase | std::ios_base::hex);
			break;

		case 'x':
			os.flags (how | std::ios_base::hex);
			break;

		case 'G':
			os.flags (how | std::ios_base::uppercase);
			break;

		case 'g':
			os.flags (how);
			break;

		case 'E':
			os.flags (how | std::ios_base::uppercase | std::ios_base::scientific);
			break;

		case 'e':
			os.flags (how | std::ios_base::scientific);
			break;

		case 'F':
			os.flags (how | std::ios_base::uppercase | std::ios_base::fixed);
			break;

		case 'f':
			os.flags (how | std::ios_base::fixed | std::ios_base::internal);
			break;

		case 'd':
			os.flags (how & ~std::ios_base::boolalpha);
			break;

		case 's':
			os.flags (how | std::ios_base::boolalpha);
			break;

		default:
			os.flags (how);
		}

		++eow;
	}
	*fmt = eow;
	if (!argument_found) {
		*argnum = 0;
	}
}


}}

