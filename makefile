SONAME=5

ifeq ($(OS),Windows_NT)
	SO=dll
	SOV=-$(SONAME).$(SO)
	CPL2B=-ln -f $(PREFIX)/lib/libamber$(SOV) $(PREFIX)/bin
else
	SO=so
	SOV=.$(SO).$(SONAME)
	CPL2B=
endif

CCFLAGS=-Wall -Wextra -std=gnu++11
CCDEBUG=-ftrapv -g
CCOPTIMIZED=-O2
LIBS=-lz -lpthread
BIN=bin
INCLUDE=src
VPATH=src:test:experimental

$(BIN)/%.o: %.cpp
	g++ $(CCFLAGS) -c -I$(INCLUDE) $(CCOPTIMIZED) -o$@ $<

$(BIN)/%-pic.o: %.cpp
	g++ $(CCFLAGS) -c -I$(INCLUDE) -fpic -o$@ $<

$(BIN)/%-dbg.o: %.cpp
	g++ $(CCFLAGS) -c -I$(INCLUDE) $(CCDEBUG) -o$@ $<

$(BIN)/%: $(BIN)/%.o
	g++ $(CCFLAGS) -o$@ $^ $(LIBS)

$(BIN)/%-dbg: $(BIN)/%-dbg.o

lib%$(SOEXT):
	g++ $(CFLAGS) -shared -Wl,--soname=lib$(*F)$(SOEXT) -o $@ $^ $(LIBS)

lib%.a:
	ar -cru -o $@ $^


all: $(BIN)/amber $(BIN)/libamber$(SOV) $(BIN)/genpass $(BIN)/wipe $(BIN)/blakerng $(BIN)/tweetcmd

PREFIX=/usr/local
INSTALLBIN=$(PREFIX)/bin
INSTALLLIB=$(PREFIX)/lib
INSTALLINCLUDE=$(PREFIX)/include

install: all
	install $(BIN)/amber $(BIN)/genpass $(BIN)/wipe $(BIN)/blakerng $(BIN)/tweetcmd $(INSTALLBIN)
	install $(BIN)/libamber$(SOV) $(INSTALLLIB)
	-rm $(INSTALLLIB)/libamber.$(SO)
	ln $(INSTALLLIB)/libamber$(SOV) $(INSTALLLIB)/libamber.$(SO)
	install -d $(INSTALLINCLUDE)/amber
	install $(FULL_LIB_HEADERS) $(INSTALLINCLUDE)/amber
	$(CPL2B)





# Generated automatically. Do not edit beyond here.

# Object dependencies.
bin/amber.o bin/amber-pic.o : src/amber.cpp src/group25519.hpp  src/misc.hpp  \
    src/inplace.hpp  src/blake2.hpp  src/combined.hpp  src/field25519.hpp  \
    src/symmetric.hpp  src/pack.hpp  src/keys.hpp  src/soname.hpp  \
    src/hasopt.hpp  src/blockbuf.hpp  

bin/blake2.o bin/blake2-pic.o : src/blake2.cpp src/soname.hpp  src/hasopt.hpp  \
    src/misc.hpp  src/blake2.hpp  

bin/blake2_test.o bin/blake2_test-pic.o : test/blake2_test.cpp src/blake2.hpp  \
    src/soname.hpp  src/hasopt.hpp  

bin/blakerng.o bin/blakerng-pic.o : src/blakerng.cpp src/soname.hpp  \
    src/hasopt.hpp  src/symmetric.hpp  src/misc.hpp  src/blake2.hpp  

bin/blockbuf.o bin/blockbuf-pic.o : src/blockbuf.cpp src/group25519.hpp  \
    src/misc.hpp  src/soname.hpp  src/field25519.hpp  src/noise.hpp  \
    src/symmetric.hpp  src/hasopt.hpp  src/blockbuf.hpp  src/blake2.hpp  \
    src/hkdf.hpp  

bin/blockbuf_test.o bin/blockbuf_test-pic.o : test/blockbuf_test.cpp \
    src/group25519.hpp  src/misc.hpp  src/symmetric.hpp  src/field25519.hpp  \
    src/soname.hpp  src/hasopt.hpp  src/blockbuf.hpp  src/blake2.hpp  

bin/combined.o bin/combined-pic.o : src/combined.cpp src/symmetric.hpp  \
    src/soname.hpp  src/field25519.hpp  src/group25519.hpp  src/misc.hpp  \
    src/protobuf.hpp  src/blockbuf.hpp  src/hasopt.hpp  src/keys.hpp  \
    src/blake2.hpp  src/combined.hpp  

bin/field25519.o bin/field25519-pic.o : src/field25519.cpp src/soname.hpp  \
    src/hasopt.hpp  src/field25519.hpp  src/symmetric.hpp  src/misc.hpp  \
    src/blake2.hpp  

bin/genpass.o bin/genpass-pic.o : src/genpass.cpp src/soname.hpp  src/hasopt.hpp  \
    src/symmetric.hpp  src/misc.hpp  src/blake2.hpp  

bin/group25519.o bin/group25519-pic.o : src/group25519.cpp src/misc.hpp  \
    src/group25519.hpp  src/blake2.hpp  src/hasopt.hpp  \
    src/group25519_basemult_32.hpp  src/sha2.hpp  src/soname.hpp  \
    src/field25519.hpp  src/symmetric.hpp  src/group25519_basemult_64.hpp  

bin/group25519_speed.o bin/group25519_speed-pic.o : test/group25519_speed.cpp \
    src/misc.hpp  src/group25519.hpp  src/field25519.hpp  src/hasopt.hpp  \
    src/soname.hpp  src/symmetric.hpp  src/tweetamber.hpp  src/blake2.hpp  

bin/group25519_test.o bin/group25519_test-pic.o : test/group25519_test.cpp \
    src/field25519.hpp  src/hasopt.hpp  src/soname.hpp  src/symmetric.hpp  \
    src/blake2.hpp  src/misc.hpp  src/group25519.hpp  

bin/hasopt.o bin/hasopt-pic.o : src/hasopt.cpp src/hasopt.hpp  src/soname.hpp  

bin/hkdf.o bin/hkdf-pic.o : src/hkdf.cpp src/soname.hpp  src/blake2.hpp  

bin/hkdf_test.o bin/hkdf_test-pic.o : test/hkdf_test.cpp src/soname.hpp  \
    src/sha2.hpp  src/misc.hpp  src/hkdf.hpp  

bin/inplace.o bin/inplace-pic.o : src/inplace.cpp src/symmetric.hpp  \
    src/field25519.hpp  src/blockbuf.hpp  src/blake2.hpp  src/group25519.hpp  \
    src/misc.hpp  src/soname.hpp  

bin/keys.o bin/keys-pic.o : src/keys.cpp src/blake2.hpp  src/symmetric.hpp  \
    src/soname.hpp  src/field25519.hpp  src/protobuf.hpp  src/hasopt.hpp  \
    src/blockbuf.hpp  src/misc.hpp  src/group25519.hpp  src/keys.hpp  

bin/libamber.o bin/libamber-pic.o : src/libamber.cpp src/noise.hpp  src/pack.hpp  \
    src/symmetric.hpp  src/misc.hpp  src/group25519.hpp  src/poly1305.hpp  \
    src/protobuf.hpp  src/zwrap.hpp  src/siphash24.hpp  src/inplace.hpp  \
    src/blockbuf.hpp  src/buffer.hpp  src/hasopt.hpp  src/blake2.hpp  \
    src/combined.hpp  src/hkdf.hpp  src/soname.hpp  src/field25519.hpp  \
    src/keys.hpp  

DEPS_libamber = src/noise.hpp  src/pack.hpp  src/symmetric.hpp  src/misc.hpp  src/group25519.hpp  \
    src/poly1305.hpp  src/protobuf.hpp  src/zwrap.hpp  src/siphash24.hpp  \
    src/inplace.hpp  src/blockbuf.hpp  src/buffer.hpp  src/hasopt.hpp  \
    src/blake2.hpp  src/combined.hpp  src/hkdf.hpp  src/soname.hpp  \
    src/field25519.hpp  src/keys.hpp  

bin/misc.o bin/misc-pic.o : src/misc.cpp src/soname.hpp  src/blake2.hpp  \
    src/misc.hpp  

bin/noise.o bin/noise-pic.o : src/noise.cpp src/group25519.hpp  src/misc.hpp  \
    src/blake2.hpp  src/hkdf.hpp  src/field25519.hpp  src/hasopt.hpp  \
    src/soname.hpp  src/poly1305.hpp  src/symmetric.hpp  src/noise.hpp  

bin/noise_test.o bin/noise_test-pic.o : test/noise_test.cpp src/group25519.hpp  \
    src/misc.hpp  src/field25519.hpp  src/hasopt.hpp  src/soname.hpp  \
    src/symmetric.hpp  src/noise.hpp  src/blake2.hpp  src/hkdf.hpp  

bin/noisestream.o bin/noisestream-pic.o : test/noisestream.cpp \
    src/group25519.hpp  src/misc.hpp  src/field25519.hpp  src/hasopt.hpp  \
    src/soname.hpp  src/symmetric.hpp  src/noise.hpp  src/blake2.hpp  \
    src/hkdf.hpp  

bin/pack.o bin/pack-pic.o : src/pack.cpp src/group25519.hpp  src/misc.hpp  \
    src/symmetric.hpp  src/soname.hpp  src/blake2.hpp  src/protobuf.hpp  \
    src/zwrap.hpp  src/field25519.hpp  src/keys.hpp  src/blockbuf.hpp  \
    src/buffer.hpp  src/hasopt.hpp  

bin/passstrength.o bin/passstrength-pic.o : test/passstrength.cpp 

bin/poly1305.o bin/poly1305-pic.o : src/poly1305.cpp src/soname.hpp  \
    src/misc.hpp  src/poly1305.hpp  

bin/protobuf.o bin/protobuf-pic.o : src/protobuf.cpp src/protobuf.hpp  \
    src/soname.hpp  src/hasopt.hpp  

bin/protobuf_test.o bin/protobuf_test-pic.o : test/protobuf_test.cpp \
    src/protobuf.hpp  src/soname.hpp  src/hasopt.hpp  

bin/protodump.o bin/protodump-pic.o : src/protodump.cpp src/protobuf.hpp  \
    src/soname.hpp  src/hasopt.hpp  

bin/sha2.o bin/sha2-pic.o : src/sha2.cpp src/sha2.hpp  src/soname.hpp  

bin/show_randdev.o bin/show_randdev-pic.o : test/show_randdev.cpp src/soname.hpp  \
    src/symmetric.hpp  src/misc.hpp  src/blake2.hpp  

bin/siphash24.o bin/siphash24-pic.o : src/siphash24.cpp src/soname.hpp  \
    src/siphash24.hpp  src/symmetric.hpp  src/misc.hpp  src/blake2.hpp  

bin/speed_test.o bin/speed_test-pic.o : test/speed_test.cpp src/misc.hpp  \
    src/group25519.hpp  src/blake2.hpp  src/hasopt.hpp  src/soname.hpp  \
    src/siphash24.hpp  src/field25519.hpp  src/poly1305.hpp  src/symmetric.hpp  

bin/symmetric.o bin/symmetric-pic.o : src/symmetric.cpp src/soname.hpp  \
    src/hasopt.hpp  src/symmetric.hpp  src/poly1305.hpp  src/misc.hpp  \
    src/blake2.hpp  

bin/symmetric_test.o bin/symmetric_test-pic.o : test/symmetric_test.cpp \
    src/soname.hpp  src/hasopt.hpp  src/symmetric.hpp  src/misc.hpp  \
    src/blake2.hpp  

bin/tamper.o bin/tamper-pic.o : test/tamper.cpp 

bin/twcmp.o bin/twcmp-pic.o : src/twcmp.cpp src/soname.hpp  src/misc.hpp  \
    src/group25519.hpp  src/blake2.hpp  src/tweetamber.hpp  src/field25519.hpp  \
    src/symmetric.hpp  

bin/tweetamber.o bin/tweetamber-pic.o : src/tweetamber.cpp src/tweetamber.hpp  \
    src/soname.hpp  

bin/tweetamber32.o bin/tweetamber32-pic.o : src/tweetamber32.cpp \
    src/tweetamber.hpp  src/soname.hpp  

bin/tweetamber64.o bin/tweetamber64-pic.o : src/tweetamber64.cpp \
    src/tweetamber.hpp  src/soname.hpp  

bin/tweetcmd.o bin/tweetcmd-pic.o : src/tweetcmd.cpp src/soname.hpp  \
    src/misc.hpp  src/tweetamber.hpp  

bin/wipe.o bin/wipe-pic.o : src/wipe.cpp src/soname.hpp  src/hasopt.hpp  \
    src/symmetric.hpp  src/misc.hpp  src/blake2.hpp  

bin/zwrap.o bin/zwrap-pic.o : src/zwrap.cpp src/soname.hpp  src/buffer.hpp  \
    src/zwrap.hpp  

# Main programs
bin/amber: \
    bin/zwrap.o bin/combined.o bin/blake2.o bin/symmetric.o bin/group25519.o  \
    bin/sha2.o bin/protobuf.o bin/inplace.o bin/field25519.o bin/misc.o  \
    bin/pack.o bin/keys.o bin/hasopt.o bin/blockbuf.o bin/amber.o  \
    bin/hkdf.o bin/noise.o bin/poly1305.o

bin/amber-pic: \
    bin/zwrap-pic.o bin/combined-pic.o bin/blake2-pic.o bin/symmetric-pic.o  \
    bin/group25519-pic.o bin/sha2-pic.o bin/protobuf-pic.o  \
    bin/inplace-pic.o bin/field25519-pic.o bin/misc-pic.o bin/pack-pic.o  \
    bin/keys-pic.o bin/hasopt-pic.o bin/blockbuf-pic.o bin/amber-pic.o  \
    bin/hkdf-pic.o bin/noise-pic.o bin/poly1305-pic.o

bin/blake2_test: \
    bin/misc.o bin/blake2_test.o bin/blake2.o bin/hasopt.o

bin/blake2_test-pic: \
    bin/misc-pic.o bin/blake2_test-pic.o bin/blake2-pic.o bin/hasopt-pic.o

bin/blakerng: \
    bin/blakerng.o bin/blake2.o bin/misc.o bin/hasopt.o bin/poly1305.o  \
    bin/symmetric.o

bin/blakerng-pic: \
    bin/blakerng-pic.o bin/blake2-pic.o bin/misc-pic.o bin/hasopt-pic.o  \
    bin/poly1305-pic.o bin/symmetric-pic.o

bin/blockbuf_test: \
    bin/sha2.o bin/poly1305.o bin/noise.o bin/hkdf.o bin/blockbuf_test.o  \
    bin/misc.o bin/blockbuf.o bin/group25519.o bin/field25519.o  \
    bin/symmetric.o bin/blake2.o bin/hasopt.o

bin/blockbuf_test-pic: \
    bin/sha2-pic.o bin/poly1305-pic.o bin/noise-pic.o bin/hkdf-pic.o  \
    bin/blockbuf_test-pic.o bin/misc-pic.o bin/blockbuf-pic.o  \
    bin/group25519-pic.o bin/field25519-pic.o bin/symmetric-pic.o  \
    bin/blake2-pic.o bin/hasopt-pic.o

bin/genpass: \
    bin/genpass.o bin/blake2.o bin/misc.o bin/hasopt.o bin/poly1305.o  \
    bin/symmetric.o

bin/genpass-pic: \
    bin/genpass-pic.o bin/blake2-pic.o bin/misc-pic.o bin/hasopt-pic.o  \
    bin/poly1305-pic.o bin/symmetric-pic.o

bin/group25519_speed: \
    bin/poly1305.o bin/sha2.o bin/group25519.o bin/tweetamber.o bin/misc.o  \
    bin/blake2.o bin/hasopt.o bin/group25519_speed.o bin/field25519.o  \
    bin/symmetric.o

bin/group25519_speed-pic: \
    bin/poly1305-pic.o bin/sha2-pic.o bin/group25519-pic.o  \
    bin/tweetamber-pic.o bin/misc-pic.o bin/blake2-pic.o  \
    bin/hasopt-pic.o bin/group25519_speed-pic.o bin/field25519-pic.o  \
    bin/symmetric-pic.o

bin/group25519_test: \
    bin/poly1305.o bin/sha2.o bin/group25519_test.o bin/group25519.o  \
    bin/field25519.o bin/symmetric.o bin/hasopt.o bin/blake2.o  \
    bin/misc.o

bin/group25519_test-pic: \
    bin/poly1305-pic.o bin/sha2-pic.o bin/group25519_test-pic.o  \
    bin/group25519-pic.o bin/field25519-pic.o bin/symmetric-pic.o  \
    bin/hasopt-pic.o bin/blake2-pic.o bin/misc-pic.o

bin/hkdf_test: \
    bin/hasopt.o bin/blake2.o bin/hkdf_test.o bin/hkdf.o bin/sha2.o  \
    bin/misc.o

bin/hkdf_test-pic: \
    bin/hasopt-pic.o bin/blake2-pic.o bin/hkdf_test-pic.o bin/hkdf-pic.o  \
    bin/sha2-pic.o bin/misc-pic.o

bin/libamber.a: \
    bin/keys.o bin/group25519.o bin/sha2.o bin/protobuf.o bin/pack.o  \
    bin/symmetric.o bin/siphash24.o bin/misc.o bin/field25519.o  \
    bin/poly1305.o bin/noise.o bin/zwrap.o bin/hkdf.o bin/inplace.o  \
    bin/blockbuf.o bin/hasopt.o bin/blake2.o bin/combined.o

bin/libamber$(SOV): \
    bin/keys-pic.o bin/group25519-pic.o bin/sha2-pic.o bin/protobuf-pic.o  \
    bin/pack-pic.o bin/symmetric-pic.o bin/siphash24-pic.o  \
    bin/misc-pic.o bin/field25519-pic.o bin/poly1305-pic.o  \
    bin/noise-pic.o bin/zwrap-pic.o bin/hkdf-pic.o bin/inplace-pic.o  \
    bin/blockbuf-pic.o bin/hasopt-pic.o bin/blake2-pic.o  \
    bin/combined-pic.o

bin/noise_test: \
    bin/poly1305.o bin/sha2.o bin/noise_test.o bin/hkdf.o bin/misc.o  \
    bin/group25519.o bin/blake2.o bin/hasopt.o bin/field25519.o  \
    bin/symmetric.o bin/noise.o

bin/noise_test-pic: \
    bin/poly1305-pic.o bin/sha2-pic.o bin/noise_test-pic.o bin/hkdf-pic.o  \
    bin/misc-pic.o bin/group25519-pic.o bin/blake2-pic.o  \
    bin/hasopt-pic.o bin/field25519-pic.o bin/symmetric-pic.o  \
    bin/noise-pic.o

bin/noisestream: \
    bin/poly1305.o bin/sha2.o bin/hkdf.o bin/noisestream.o bin/misc.o  \
    bin/group25519.o bin/blake2.o bin/hasopt.o bin/field25519.o  \
    bin/symmetric.o bin/noise.o

bin/noisestream-pic: \
    bin/poly1305-pic.o bin/sha2-pic.o bin/hkdf-pic.o bin/noisestream-pic.o  \
    bin/misc-pic.o bin/group25519-pic.o bin/blake2-pic.o  \
    bin/hasopt-pic.o bin/field25519-pic.o bin/symmetric-pic.o  \
    bin/noise-pic.o

bin/passstrength: \
    bin/passstrength.o

bin/passstrength-pic: \
    bin/passstrength-pic.o

bin/protobuf_test: \
    bin/protobuf_test.o bin/protobuf.o bin/hasopt.o

bin/protobuf_test-pic: \
    bin/protobuf_test-pic.o bin/protobuf-pic.o bin/hasopt-pic.o

bin/protodump: \
    bin/protodump.o bin/protobuf.o bin/hasopt.o

bin/protodump-pic: \
    bin/protodump-pic.o bin/protobuf-pic.o bin/hasopt-pic.o

bin/show_randdev: \
    bin/hasopt.o bin/show_randdev.o bin/blake2.o bin/poly1305.o  \
    bin/symmetric.o bin/misc.o

bin/show_randdev-pic: \
    bin/hasopt-pic.o bin/show_randdev-pic.o bin/blake2-pic.o  \
    bin/poly1305-pic.o bin/symmetric-pic.o bin/misc-pic.o

bin/speed_test: \
    bin/sha2.o bin/speed_test.o bin/poly1305.o bin/group25519.o bin/misc.o  \
    bin/blake2.o bin/hasopt.o bin/symmetric.o bin/field25519.o  \
    bin/siphash24.o

bin/speed_test-pic: \
    bin/sha2-pic.o bin/speed_test-pic.o bin/poly1305-pic.o  \
    bin/group25519-pic.o bin/misc-pic.o bin/blake2-pic.o  \
    bin/hasopt-pic.o bin/symmetric-pic.o bin/field25519-pic.o  \
    bin/siphash24-pic.o

bin/symmetric_test: \
    bin/blake2.o bin/misc.o bin/symmetric_test.o bin/hasopt.o bin/poly1305.o  \
    bin/symmetric.o

bin/symmetric_test-pic: \
    bin/blake2-pic.o bin/misc-pic.o bin/symmetric_test-pic.o  \
    bin/hasopt-pic.o bin/poly1305-pic.o bin/symmetric-pic.o

bin/tamper: \
    bin/tamper.o

bin/tamper-pic: \
    bin/tamper-pic.o

bin/twcmp: \
    bin/poly1305.o bin/sha2.o bin/twcmp.o bin/group25519.o bin/tweetamber.o  \
    bin/misc.o bin/hasopt.o bin/blake2.o bin/field25519.o  \
    bin/symmetric.o

bin/twcmp-pic: \
    bin/poly1305-pic.o bin/sha2-pic.o bin/twcmp-pic.o bin/group25519-pic.o  \
    bin/tweetamber-pic.o bin/misc-pic.o bin/hasopt-pic.o  \
    bin/blake2-pic.o bin/field25519-pic.o bin/symmetric-pic.o

bin/tweetcmd: \
    bin/hasopt.o bin/blake2.o bin/tweetcmd.o bin/misc.o bin/tweetamber.o

bin/tweetcmd-pic: \
    bin/hasopt-pic.o bin/blake2-pic.o bin/tweetcmd-pic.o bin/misc-pic.o  \
    bin/tweetamber-pic.o

bin/wipe: \
    bin/wipe.o bin/blake2.o bin/misc.o bin/hasopt.o bin/poly1305.o  \
    bin/symmetric.o

bin/wipe-pic: \
    bin/wipe-pic.o bin/blake2-pic.o bin/misc-pic.o bin/hasopt-pic.o  \
    bin/poly1305-pic.o bin/symmetric-pic.o

FULL_TARGETS =  bin/amber bin/blake2_test bin/blakerng bin/blockbuf_test bin/genpass  \
    bin/group25519_speed bin/group25519_test bin/hkdf_test  \
    bin/libamber.a bin/libamber$(SOV) bin/noise_test bin/noisestream  \
    bin/passstrength bin/protobuf_test bin/protodump bin/show_randdev  \
    bin/speed_test bin/symmetric_test bin/tamper bin/twcmp bin/tweetcmd  \
    bin/wipe
full_targets: $(FULL_TARGETS)
FULL_LIB_HEADERS = $(DEPS_libamber) 
