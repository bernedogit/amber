#ifndef AMBER_HASOPT_HPP
#define AMBER_HASOPT_HPP

/* Copyright (c) 2015-2017, Pelayo Bernedo.
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


// Command line options and error handling.


#include "soname.hpp"
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace amber {   inline  namespace AMBER_SONAME {

// Similar to getopt. The opts string is the same as the one for getopt: a
// sequence of single letter options. If the option takes an argument then it
// is followed by a colon. The function returns the option that was found. If
// the option takes an argument then *val is set to point to it. If there is
// an error then -1 is returned. It returns 0 when there are no more
// arguments to process. The argc and argv are modified to remove the option
// arguments.
EXPORTFN int hasopt (int *argcp, char **argv, const char *opts, const char **val);


// Check if a long string flag was passed in the command line and remove it
// from the arguments. The longopt must include the hyphen or the double
// hyphen.
EXPORTFN bool hasopt_long (int *argc, char **argv, const char *longopt);


// Check if a long string option with a value was passed in the command line
// and remove it from the arguments. The longopt argument must include the
// hyphen or the double hyphen.
EXPORTFN bool hasopt_long (int *argc, char **argv, const char *longopt,
                           const char **val);


// Return a string which contains the error description, including any nested
// exceptions.
EXPORTFN std::string describe (const std::exception &e);


// Run the real_main. Catch and show any exceptions.
EXPORTFN int run_main (int (*real_main)());
EXPORTFN int run_main (void (*real_main)());
EXPORTFN int run_main (int argc, char **argv, int (*real_main)(int,char**));


// Placeholder for internationalization. When the program is adapted for
// gettext the _() strings are already there.
inline const char * _(const char *s) { return s; }


// format (stream,fmt,args...) works as fprintf with the following properties:
//
// 1) it outputs to a std::ostream;
//
// 2) it is type safe. The underlying operator << is used and the formatting
// flags are used to set the state of the ostream;

// 3) it allows the use of positional arguments as required for
// internationalization.

// The positional arguments are given using the syntax %1% or %2% or %3%...
// for arguments that will use the default formatting rules or using the
// posix syntax: %4$3d This will print the 4th argument as a decimal integer
// with a width of 3 positions. Note that the d only sets the output base to
// decimal. If it turns out that the 4th argument is not an integer it will
// be printed using the operator<< corresponding to the argument.

// The format specifications of printf will be used to set the corresponding
// fmtflags of the output stream. They do not otherwise change the way things
// are output. For instance %8e will just select scientific output and the
// field width of 8. If the corresponding argument happens to be a string,
// the std::ios_base::scientific flag will have no effect on it but the
// string will be written with a minimum width of 8 characters. There is one
// case where the format specifications differ from printf: if the value to
// be written is a bool, a %d format will write it as an integer (1 or 0). If
// the format is %s the bool will be written as a string.

// Auxiliary function.
EXPORTFN
void process_format_stream (std::ostream &os, const char **fmt,
                            int *argnum, int *saved_prec, int *wa, int *pa);

// Output to a ostream
inline void format (std::ostream &os, const char *s) {
	os << s;
}

template <class T>
inline void format_insert_single (std::ostream &os, const T &t) {
	os << t;
}

inline void format_helper (std::ostream&, int) {}


template <class T1, class ... Args>
inline void format_helper (std::ostream &os, int n, const T1 &t1,
                           const Args &... args)
{
	if (n == 1) {
		format_insert_single (os, t1);
	} else {
		format_helper (os, n - 1, args...);
	}
}

// We expect the width and precision to be available as integers. For
// everything else interpret it as no precision.
template <class T>
inline int evalint (T) { return 0; }

// Items convertible to integer. Should cover ptrdiff_t and size_t.
template <> inline int evalint<int>      (int i) { return i; }
template <> inline int evalint<unsigned> (unsigned i) { return i; }
template <> inline int evalint<long> (long i) { return i; }
template <> inline int evalint<unsigned long> (unsigned long i) { return i; }
template <> inline int evalint<long long> (long long i) { return i; }
template <> inline int evalint<unsigned long long> (unsigned long long i) { return i; }


template <class T>
inline int getint (int an, const T &t) {  return an == 1 ? evalint(t) : 0;   }

template <class T1, class ... Args>
inline int getint (int an, const T1 &t1, const Args & ... args)
{
	if (an == 1) return evalint(t1);
	else return getint (an - 1, args...);
}


template <class ... Args>
void format (std::ostream &os, const char *fmt, const Args &... args)
{
	const char *sow = fmt;
	int argnum = 0;
	int saved_prec, wa, pa;
	auto sf = os.flags();

	while (*sow) {
		process_format_stream (os, &sow, &argnum, &saved_prec, &wa, &pa);
		if (wa != -1) {
			os.width (getint(wa, args...));
		}
		if (pa != -1) {
			os.precision (getint(pa, args...));
		}

		format_helper (os, argnum, args...);
		os.precision (saved_prec);
	}
	os.flags (sf);
}

// Return a string with the proper formatting.
template <class ... Args>
std::string sformat (const char *fmt, const Args &... args)
{
	std::ostringstream os;
	format (os, fmt, args...);
	return os.str();
}


// Throw a std::runtime_error exception with the given information.
template <class ...Args>
void throw_rte (const char *fmt, const Args &... args)
{
	std::ostringstream os;
	format (os, fmt, args...);
	throw std::runtime_error (os.str());
}

// Throw with nested using the given information.
template <class ...Args>
void throw_nrte (const char *fmt, const Args &... args)
{
	std::ostringstream os;
	format(os, fmt, args...);
	std::throw_with_nested (std::runtime_error(os.str()));
}


template <class F>
class Scoped_guard {
	F f;
public:
	bool forget;
	Scoped_guard(F &&ff) : f(ff), forget(false) {}
	~Scoped_guard() {
		if (!forget) {
			try {
				f();
			} catch (...) {
				// Do not allow any exceptions to leave the destructor!
			}
		}
	}
};

template <class F>
inline Scoped_guard<F> make_guard(F f)
{
	return Scoped_guard<F>(std::move(f));
}


}}

#endif

