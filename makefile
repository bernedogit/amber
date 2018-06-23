SONAME=4

ifeq ($(OS),Windows_NT)
	SO=dll
	SOV=-$(SONAME).$(SO)
	CPL2B=-ln -f $(PREFIX)/lib/libamber$(SOV) $(PREFIX)/bin
else
	SO=so
	SOV=.$(SO).$(SONAME)
	CPL2B=
endif

CCFLAGS=-O2 -Wall -Wextra -std=gnu++0x
LIBS=-lz -lpthread
BIN=bin
INCLUDE=src
VPATH=src:test:experimental

$(BIN)/%.o: %.cpp
	g++ $(CCFLAGS) -c -I$(INCLUDE) -o$@ $<

$(BIN)/%-pic.o: %.cpp
	g++ $(CCFLAGS) -c -I$(INCLUDE) -fpic -o$@ $<

$(BIN)/%: $(BIN)/%.o
	g++ $(CCFLAGS) -o$@ $^ $(LIBS)

lib%$(SOEXT):
	g++ $(CFLAGS) -shared -Wl,--soname=lib$(*F)$(SOEXT) -o $@ $^ $(LIBS)


all: $(BIN)/amber $(BIN)/libamber$(SOV) $(BIN)/genpass $(BIN)/wipe $(BIN)/blakerng $(BIN)/tweetcmd

PREFIX=/usr/local
INSTALLBIN=$(PREFIX)/bin
INSTALLLIB=$(PREFIX)/lib
INSTALLINCLUDE=$(PREFIX)/include

install: all
	install $(BIN)/amber $(BIN)/genpass $(BIN)/wipe $(BIN)/blakerng $(BIN)/tweetcmd $(INSTALLBIN)
	install $(BIN)/libamber$(SOV) $(INSTALLLIB)
	-rm $(INSTALLLIB)/libamber.$(SO)
	ln -s $(INSTALLLIB)/libamber$(SOV) $(INSTALLLIB)/libamber.$(SO)
	install -d $(INSTALLINCLUDE)/amber
	install $(FULL_LIB_HEADERS) $(INSTALLINCLUDE)/amber
	$(CPL2B)





# Generated automatically. Do not edit beyond here.

# Object dependencies.
bin/amber.o bin/amber-pic.o : src/amber.cpp src/symmetric.hpp  src/inplace.hpp  \
    src/group25519.hpp  src/pack.hpp  src/field25519.hpp  src/keys.hpp  \
    src/hasopt.hpp  src/blockbuf.hpp  src/combined.hpp  src/misc.hpp  \
    src/blake2.hpp  src/soname.hpp  

bin/blake2.o bin/blake2-pic.o : src/blake2.cpp src/blake2.hpp  src/soname.hpp  \
    src/hasopt.hpp  

bin/blake2_test.o bin/blake2_test-pic.o : src/blake2_test.cpp src/blake2.hpp  \
    src/soname.hpp  src/hasopt.hpp  

bin/blakerng.o bin/blakerng-pic.o : src/blakerng.cpp src/misc.hpp  \
    src/hasopt.hpp  src/symmetric.hpp  src/blake2.hpp  src/soname.hpp  

bin/blockbuf.o bin/blockbuf-pic.o : src/blockbuf.cpp src/soname.hpp  \
    src/blake2.hpp  src/group25519.hpp  src/symmetric.hpp  src/blockbuf.hpp  \
    src/misc.hpp  src/noise.hpp  src/hkdf.hpp  src/hasopt.hpp  \
    src/field25519.hpp  

bin/blockbuf_test.o bin/blockbuf_test-pic.o : test/blockbuf_test.cpp \
    src/soname.hpp  src/blake2.hpp  src/group25519.hpp  src/symmetric.hpp  \
    src/hasopt.hpp  src/field25519.hpp  src/blockbuf.hpp  src/misc.hpp  

bin/combined.o bin/combined-pic.o : src/combined.cpp src/blockbuf.hpp  \
    src/field25519.hpp  src/group25519.hpp  src/protobuf.hpp  src/hasopt.hpp  \
    src/keys.hpp  src/symmetric.hpp  src/blake2.hpp  src/combined.hpp  \
    src/soname.hpp  src/misc.hpp  

bin/field25519.o bin/field25519-pic.o : src/field25519.cpp src/misc.hpp  \
    src/blake2.hpp  src/symmetric.hpp  src/hasopt.hpp  src/field25519.hpp  \
    src/soname.hpp  

bin/genpass.o bin/genpass-pic.o : src/genpass.cpp src/misc.hpp  src/hasopt.hpp  \
    src/symmetric.hpp  src/blake2.hpp  src/soname.hpp  

bin/group25519.o bin/group25519-pic.o : src/group25519.cpp src/soname.hpp  \
    src/symmetric.hpp  src/field25519.hpp  src/hasopt.hpp  src/group25519.hpp  \
    src/blake2.hpp  src/group25519_basemult_64.hpp  src/misc.hpp  \
    src/group25519_basemult_32.hpp  src/sha2.hpp  

bin/group25519_speed.o bin/group25519_speed-pic.o : test/group25519_speed.cpp \
    src/soname.hpp  src/symmetric.hpp  src/misc.hpp  src/blake2.hpp  \
    src/group25519.hpp  src/field25519.hpp  src/hasopt.hpp  src/tweetamber.hpp  

bin/group25519_test.o bin/group25519_test-pic.o : test/group25519_test.cpp \
    src/soname.hpp  src/symmetric.hpp  src/misc.hpp  src/blake2.hpp  \
    src/group25519.hpp  src/field25519.hpp  src/hasopt.hpp  

bin/hasopt.o bin/hasopt-pic.o : src/hasopt.cpp src/hasopt.hpp  src/soname.hpp  

bin/hkdf.o bin/hkdf-pic.o : src/hkdf.cpp src/soname.hpp  src/blake2.hpp  

bin/hkdf_test.o bin/hkdf_test-pic.o : test/hkdf_test.cpp src/hkdf.hpp  \
    src/soname.hpp  src/sha2.hpp  src/misc.hpp  

bin/inplace.o bin/inplace-pic.o : src/inplace.cpp 

bin/keys.o bin/keys-pic.o : src/keys.cpp src/soname.hpp  src/field25519.hpp  \
    src/hasopt.hpp  src/group25519.hpp  src/blake2.hpp  src/keys.hpp  \
    src/protobuf.hpp  src/symmetric.hpp  src/blockbuf.hpp  src/misc.hpp  

bin/libamber.o bin/libamber-pic.o : src/libamber.cpp src/keys.hpp  \
    src/hasopt.hpp  src/combined.hpp  src/buffer.hpp  src/blake2.hpp  \
    src/misc.hpp  src/soname.hpp  src/field25519.hpp  src/group25519.hpp  \
    src/poly1305.hpp  src/siphash24.hpp  src/protobuf.hpp  src/zwrap.hpp  \
    src/pack.hpp  src/noise.hpp  src/hkdf.hpp  src/inplace.hpp  \
    src/symmetric.hpp  src/blockbuf.hpp  

DEPS_libamber = src/keys.hpp  src/hasopt.hpp  src/combined.hpp  src/buffer.hpp  src/blake2.hpp  \
    src/misc.hpp  src/soname.hpp  src/field25519.hpp  src/group25519.hpp  \
    src/poly1305.hpp  src/siphash24.hpp  src/protobuf.hpp  src/zwrap.hpp  \
    src/pack.hpp  src/noise.hpp  src/hkdf.hpp  src/inplace.hpp  \
    src/symmetric.hpp  src/blockbuf.hpp  

bin/misc.o bin/misc-pic.o : src/misc.cpp src/misc.hpp  src/soname.hpp  \
    src/blake2.hpp  

bin/noise.o bin/noise-pic.o : src/noise.cpp src/soname.hpp  src/blake2.hpp  \
    src/group25519.hpp  src/symmetric.hpp  src/noise.hpp  src/hkdf.hpp  \
    src/poly1305.hpp  src/hasopt.hpp  src/field25519.hpp  src/misc.hpp  

bin/noise_test.o bin/noise_test-pic.o : test/noise_test.cpp src/soname.hpp  \
    src/blake2.hpp  src/group25519.hpp  src/symmetric.hpp  src/hasopt.hpp  \
    src/field25519.hpp  src/misc.hpp  src/noise.hpp  src/hkdf.hpp  

bin/noisestream.o bin/noisestream-pic.o : test/noisestream.cpp src/soname.hpp  \
    src/blake2.hpp  src/group25519.hpp  src/symmetric.hpp  src/hasopt.hpp  \
    src/field25519.hpp  src/misc.hpp  src/noise.hpp  src/hkdf.hpp  

bin/pack.o bin/pack-pic.o : src/pack.cpp src/protobuf.hpp  src/field25519.hpp  \
    src/keys.hpp  src/hasopt.hpp  src/blockbuf.hpp  src/symmetric.hpp  \
    src/zwrap.hpp  src/buffer.hpp  src/misc.hpp  src/soname.hpp  src/blake2.hpp  \
    src/group25519.hpp  

bin/passstrength.o bin/passstrength-pic.o : test/passstrength.cpp 

bin/poly1305.o bin/poly1305-pic.o : src/poly1305.cpp src/poly1305.hpp  \
    src/soname.hpp  src/misc.hpp  

bin/protobuf.o bin/protobuf-pic.o : src/protobuf.cpp src/protobuf.hpp  \
    src/soname.hpp  src/hasopt.hpp  

bin/protobuf_test.o bin/protobuf_test-pic.o : test/protobuf_test.cpp \
    src/protobuf.hpp  src/soname.hpp  src/hasopt.hpp  

bin/protodump.o bin/protodump-pic.o : src/protodump.cpp src/protobuf.hpp  \
    src/soname.hpp  src/hasopt.hpp  

bin/sha2.o bin/sha2-pic.o : src/sha2.cpp src/sha2.hpp  src/soname.hpp  

bin/show_randdev.o bin/show_randdev-pic.o : test/show_randdev.cpp \
    src/symmetric.hpp  src/blake2.hpp  src/soname.hpp  src/misc.hpp  

bin/siphash24.o bin/siphash24-pic.o : src/siphash24.cpp src/soname.hpp  \
    src/misc.hpp  src/siphash24.hpp  src/symmetric.hpp  src/blake2.hpp  

bin/speed_test.o bin/speed_test-pic.o : test/speed_test.cpp src/soname.hpp  \
    src/symmetric.hpp  src/misc.hpp  src/blake2.hpp  src/group25519.hpp  \
    src/field25519.hpp  src/hasopt.hpp  src/siphash24.hpp  src/poly1305.hpp  

bin/symmetric.o bin/symmetric-pic.o : src/symmetric.cpp src/misc.hpp  \
    src/soname.hpp  src/hasopt.hpp  src/poly1305.hpp  src/symmetric.hpp  \
    src/blake2.hpp  

bin/symmetric_test.o bin/symmetric_test-pic.o : test/symmetric_test.cpp \
    src/misc.hpp  src/hasopt.hpp  src/symmetric.hpp  src/blake2.hpp  \
    src/soname.hpp  

bin/tamper.o bin/tamper-pic.o : test/tamper.cpp 

bin/twcmp.o bin/twcmp-pic.o : src/twcmp.cpp src/field25519.hpp  \
    src/tweetamber.hpp  src/misc.hpp  src/symmetric.hpp  src/group25519.hpp  \
    src/blake2.hpp  src/soname.hpp  

bin/tweetamber.o bin/tweetamber-pic.o : src/tweetamber.cpp src/tweetamber.hpp  \
    src/soname.hpp  

bin/tweetamber32.o bin/tweetamber32-pic.o : src/tweetamber32.cpp \
    src/tweetamber.hpp  src/soname.hpp  

bin/tweetamber64.o bin/tweetamber64-pic.o : src/tweetamber64.cpp \
    src/tweetamber.hpp  src/soname.hpp  

bin/tweetcmd.o bin/tweetcmd-pic.o : src/tweetcmd.cpp src/tweetamber.hpp  \
    src/soname.hpp  src/misc.hpp  

bin/wipe.o bin/wipe-pic.o : src/wipe.cpp src/misc.hpp  src/hasopt.hpp  \
    src/symmetric.hpp  src/blake2.hpp  src/soname.hpp  

bin/zwrap.o bin/zwrap-pic.o : src/zwrap.cpp src/zwrap.hpp  src/soname.hpp  \
    src/buffer.hpp  

# Main programs
bin/amber: \
    bin/zwrap.o bin/noise.o bin/poly1305.o bin/protobuf.o bin/sha2.o  \
    bin/hkdf.o bin/blake2.o bin/inplace.o bin/group25519.o  \
    bin/combined.o bin/symmetric.o bin/blockbuf.o bin/pack.o  \
    bin/field25519.o bin/keys.o bin/amber.o bin/hasopt.o bin/misc.o

bin/amber-pic: \
    bin/zwrap-pic.o bin/noise-pic.o bin/poly1305-pic.o bin/protobuf-pic.o  \
    bin/sha2-pic.o bin/hkdf-pic.o bin/blake2-pic.o bin/inplace-pic.o  \
    bin/group25519-pic.o bin/combined-pic.o bin/symmetric-pic.o  \
    bin/blockbuf-pic.o bin/pack-pic.o bin/field25519-pic.o  \
    bin/keys-pic.o bin/amber-pic.o bin/hasopt-pic.o bin/misc-pic.o

bin/blake2_test: \
    bin/blake2_test.o bin/hasopt.o bin/blake2.o

bin/blake2_test-pic: \
    bin/blake2_test-pic.o bin/hasopt-pic.o bin/blake2-pic.o

bin/blakerng: \
    bin/poly1305.o bin/symmetric.o bin/blakerng.o bin/misc.o bin/hasopt.o  \
    bin/blake2.o

bin/blakerng-pic: \
    bin/poly1305-pic.o bin/symmetric-pic.o bin/blakerng-pic.o bin/misc-pic.o  \
    bin/hasopt-pic.o bin/blake2-pic.o

bin/blockbuf_test: \
    bin/poly1305.o bin/hasopt.o bin/misc.o bin/symmetric.o bin/blockbuf.o  \
    bin/blockbuf_test.o bin/group25519.o bin/hkdf.o bin/blake2.o  \
    bin/noise.o bin/field25519.o bin/sha2.o

bin/blockbuf_test-pic: \
    bin/poly1305-pic.o bin/hasopt-pic.o bin/misc-pic.o bin/symmetric-pic.o  \
    bin/blockbuf-pic.o bin/blockbuf_test-pic.o bin/group25519-pic.o  \
    bin/hkdf-pic.o bin/blake2-pic.o bin/noise-pic.o bin/field25519-pic.o  \
    bin/sha2-pic.o

bin/genpass: \
    bin/poly1305.o bin/genpass.o bin/symmetric.o bin/misc.o bin/hasopt.o  \
    bin/blake2.o

bin/genpass-pic: \
    bin/poly1305-pic.o bin/genpass-pic.o bin/symmetric-pic.o bin/misc-pic.o  \
    bin/hasopt-pic.o bin/blake2-pic.o

bin/group25519_speed: \
    bin/sha2.o bin/poly1305.o bin/tweetamber.o bin/field25519.o  \
    bin/symmetric.o bin/hasopt.o bin/misc.o bin/group25519.o  \
    bin/group25519_speed.o bin/blake2.o

bin/group25519_speed-pic: \
    bin/sha2-pic.o bin/poly1305-pic.o bin/tweetamber-pic.o  \
    bin/field25519-pic.o bin/symmetric-pic.o bin/hasopt-pic.o  \
    bin/misc-pic.o bin/group25519-pic.o bin/group25519_speed-pic.o  \
    bin/blake2-pic.o

bin/group25519_test: \
    bin/sha2.o bin/poly1305.o bin/group25519_test.o bin/field25519.o  \
    bin/symmetric.o bin/hasopt.o bin/misc.o bin/group25519.o  \
    bin/blake2.o

bin/group25519_test-pic: \
    bin/sha2-pic.o bin/poly1305-pic.o bin/group25519_test-pic.o  \
    bin/field25519-pic.o bin/symmetric-pic.o bin/hasopt-pic.o  \
    bin/misc-pic.o bin/group25519-pic.o bin/blake2-pic.o

bin/hkdf_test: \
    bin/blake2.o bin/hkdf.o bin/sha2.o bin/hkdf_test.o bin/hasopt.o  \
    bin/misc.o

bin/hkdf_test-pic: \
    bin/blake2-pic.o bin/hkdf-pic.o bin/sha2-pic.o bin/hkdf_test-pic.o  \
    bin/hasopt-pic.o bin/misc-pic.o

bin/libamber.a: \
    bin/sha2.o bin/blockbuf.o bin/symmetric.o bin/inplace.o bin/noise.o  \
    bin/zwrap.o bin/hkdf.o bin/blake2.o bin/combined.o bin/hasopt.o  \
    bin/misc.o bin/keys.o bin/pack.o bin/field25519.o bin/group25519.o  \
    bin/poly1305.o bin/protobuf.o bin/siphash24.o

bin/libamber$(SOV): \
    bin/sha2-pic.o bin/blockbuf-pic.o bin/symmetric-pic.o bin/inplace-pic.o  \
    bin/noise-pic.o bin/zwrap-pic.o bin/hkdf-pic.o bin/blake2-pic.o  \
    bin/combined-pic.o bin/hasopt-pic.o bin/misc-pic.o bin/keys-pic.o  \
    bin/pack-pic.o bin/field25519-pic.o bin/group25519-pic.o  \
    bin/poly1305-pic.o bin/protobuf-pic.o bin/siphash24-pic.o

bin/noise_test: \
    bin/sha2.o bin/hasopt.o bin/misc.o bin/symmetric.o bin/group25519.o  \
    bin/noise.o bin/field25519.o bin/blake2.o bin/hkdf.o  \
    bin/noise_test.o bin/poly1305.o

bin/noise_test-pic: \
    bin/sha2-pic.o bin/hasopt-pic.o bin/misc-pic.o bin/symmetric-pic.o  \
    bin/group25519-pic.o bin/noise-pic.o bin/field25519-pic.o  \
    bin/blake2-pic.o bin/hkdf-pic.o bin/noise_test-pic.o  \
    bin/poly1305-pic.o

bin/noisestream: \
    bin/sha2.o bin/hasopt.o bin/misc.o bin/symmetric.o bin/group25519.o  \
    bin/noise.o bin/field25519.o bin/blake2.o bin/noisestream.o  \
    bin/hkdf.o bin/poly1305.o

bin/noisestream-pic: \
    bin/sha2-pic.o bin/hasopt-pic.o bin/misc-pic.o bin/symmetric-pic.o  \
    bin/group25519-pic.o bin/noise-pic.o bin/field25519-pic.o  \
    bin/blake2-pic.o bin/noisestream-pic.o bin/hkdf-pic.o  \
    bin/poly1305-pic.o

bin/passstrength: \
    bin/passstrength.o

bin/passstrength-pic: \
    bin/passstrength-pic.o

bin/protobuf_test: \
    bin/protobuf_test.o bin/hasopt.o bin/protobuf.o

bin/protobuf_test-pic: \
    bin/protobuf_test-pic.o bin/hasopt-pic.o bin/protobuf-pic.o

bin/protodump: \
    bin/protodump.o bin/hasopt.o bin/protobuf.o

bin/protodump-pic: \
    bin/protodump-pic.o bin/hasopt-pic.o bin/protobuf-pic.o

bin/show_randdev: \
    bin/poly1305.o bin/symmetric.o bin/hasopt.o bin/misc.o  \
    bin/show_randdev.o bin/blake2.o

bin/show_randdev-pic: \
    bin/poly1305-pic.o bin/symmetric-pic.o bin/hasopt-pic.o bin/misc-pic.o  \
    bin/show_randdev-pic.o bin/blake2-pic.o

bin/speed_test: \
    bin/sha2.o bin/speed_test.o bin/poly1305.o bin/field25519.o  \
    bin/siphash24.o bin/symmetric.o bin/hasopt.o bin/misc.o  \
    bin/group25519.o bin/blake2.o

bin/speed_test-pic: \
    bin/sha2-pic.o bin/speed_test-pic.o bin/poly1305-pic.o  \
    bin/field25519-pic.o bin/siphash24-pic.o bin/symmetric-pic.o  \
    bin/hasopt-pic.o bin/misc-pic.o bin/group25519-pic.o  \
    bin/blake2-pic.o

bin/symmetric_test: \
    bin/poly1305.o bin/symmetric_test.o bin/symmetric.o bin/misc.o  \
    bin/hasopt.o bin/blake2.o

bin/symmetric_test-pic: \
    bin/poly1305-pic.o bin/symmetric_test-pic.o bin/symmetric-pic.o  \
    bin/misc-pic.o bin/hasopt-pic.o bin/blake2-pic.o

bin/tamper: \
    bin/tamper.o

bin/tamper-pic: \
    bin/tamper-pic.o

bin/twcmp: \
    bin/poly1305.o bin/sha2.o bin/twcmp.o bin/blake2.o bin/group25519.o  \
    bin/field25519.o bin/hasopt.o bin/misc.o bin/symmetric.o  \
    bin/tweetamber.o

bin/twcmp-pic: \
    bin/poly1305-pic.o bin/sha2-pic.o bin/twcmp-pic.o bin/blake2-pic.o  \
    bin/group25519-pic.o bin/field25519-pic.o bin/hasopt-pic.o  \
    bin/misc-pic.o bin/symmetric-pic.o bin/tweetamber-pic.o

bin/tweetcmd: \
    bin/tweetamber.o bin/hasopt.o bin/misc.o bin/tweetcmd.o bin/blake2.o

bin/tweetcmd-pic: \
    bin/tweetamber-pic.o bin/hasopt-pic.o bin/misc-pic.o bin/tweetcmd-pic.o  \
    bin/blake2-pic.o

bin/wipe: \
    bin/poly1305.o bin/symmetric.o bin/misc.o bin/hasopt.o bin/wipe.o  \
    bin/blake2.o

bin/wipe-pic: \
    bin/poly1305-pic.o bin/symmetric-pic.o bin/misc-pic.o bin/hasopt-pic.o  \
    bin/wipe-pic.o bin/blake2-pic.o

FULL_TARGETS =  bin/amber bin/blake2_test bin/blakerng bin/blockbuf_test bin/genpass  \
    bin/group25519_speed bin/group25519_test bin/hkdf_test  \
    bin/libamber.a bin/libamber$(SOV) bin/noise_test bin/noisestream  \
    bin/passstrength bin/protobuf_test bin/protodump bin/show_randdev  \
    bin/speed_test bin/symmetric_test bin/tamper bin/twcmp bin/tweetcmd  \
    bin/wipe
full_targets: $(FULL_TARGETS)
FULL_LIB_HEADERS = $(DEPS_libamber) 
