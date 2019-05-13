#ifndef AMBER_SONAME_HPP
#define AMBER_SONAME_HPP

// Update the SONAME of the library whenever the ABI is changed in an incompatible way.
// This allows the coexistence of several versions of the library within the same
// executable program. Change it here and in the makefile.
#define AMBER_SONAME v6

#if defined(_WIN32) || defined(__CYGWIN__)
	#define EXPORTFN __declspec(dllexport)
#elif defined(__GNUC__)
	#define EXPORTFN __attribute__((visibility("default")))
#else
	#define EXPORTFN
#endif


namespace amber {
	inline namespace AMBER_SONAME {}
}


#endif

