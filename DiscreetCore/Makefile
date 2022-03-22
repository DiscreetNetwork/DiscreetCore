# this makefile is for compiling on windows. 
# remember to set the BOOST_LIB and BOOST on your machine.

CC=gcc
DIR_BUILD=build
DIR_CORE=src/core
DIR_UTIL=src/util
DIR_CRYPTO=src/crypto
DIR_INC=.
CPP=g++

BOOST=/home/brandon/Desktop/boost_tmp/include
BOOST_LIB=/home/brandon/Desktop/boost_1_77_0/stage/lib

CFLAGS=-c -O2 -Wall -fPIC

# core
bulletproof.o: $(DIR_CORE)/bulletproof.cpp $(DIR_INC)/bulletproof.h $(DIR_INC)/multiexp.h $(DIR_INC)/ops.h $(DIR_INC)/util/span.h $(DIR_INC)/util/varint.h $(DIR_INC)/crypto_curve.h $(DIR_INC)/crypto.h $(DIR_INC)/types.h
	$(CPP) $(CFLAGS) -I$(BOOST) -I$(DIR_INC) $(DIR_CORE)/bulletproof.cpp

bulletproof_plus.o: $(DIR_CORE)/bulletproof_plus.cpp $(DIR_INC)/bulletproof.h $(DIR_INC)/multiexp.h $(DIR_INC)/ops.h $(DIR_INC)/util/span.h $(DIR_INC)/util/varint.h $(DIR_INC)/crypto_curve.h $(DIR_INC)/crypto.h $(DIR_INC)/types.h
	$(CPP) $(CFLAGS) -I$(BOOST) -I$(DIR_INC) $(DIR_CORE)/bulletproof_plus.cpp

multiexp.o: $(DIR_CORE)/multiexp.cpp $(DIR_INC)/multiexp.h $(DIR_INC)/ops.h $(DIR_INC)/util/aligned.h $(DIR_INC)/types.h $(DIR_INC)/crypto_curve.h $(DIR_INC)/crypto.h
	$(CPP) $(CFLAGS) -I$(DIR_INC) $(DIR_CORE)/multiexp.cpp

ops.o: $(DIR_CORE)/ops.cpp $(DIR_INC)/sc_reduce32copy.h $(DIR_INC)/ops.h $(DIR_INC)/crypto_curve.h $(DIR_INC)/crypto.h $(DIR_INC)/types.h
	$(CPP) $(CFLAGS) -I$(DIR_INC) $(DIR_CORE)/ops.cpp

proofs.o: $(DIR_CORE)/proofs.cpp $(DIR_INC)/proofs.h $(DIR_INC)/bulletproof.h $(DIR_INC)/multiexp.h $(DIR_INC)/ops.h $(DIR_INC)/util/memwipe.h $(DIR_INC)/util/varint.h $(DIR_INC)/crypto_curve.h $(DIR_INC)/crypto.h $(DIR_INC)/types.h
	$(CPP) $(CFLAGS) -I$(BOOST) -I$(DIR_INC) $(DIR_CORE)/proofs.cpp

sc_reduce32copy.o: $(DIR_CORE)/sc_reduce32copy.c $(DIR_INC)/sc_reduce32copy.h $(DIR_INC)/crypto_curve.h
	$(CC) $(CFLAGS) -I$(DIR_INC) $(DIR_CORE)/sc_reduce32copy.c

transaction.o: $(DIR_CORE)/transaction.cpp $(DIR_INC)/transaction.h $(DIR_INC)/proofs.h $(DIR_INC)/bulletproof.h $(DIR_INC)/multiexp.h $(DIR_INC)/ops.h $(DIR_INC)/crypto_curve.h $(DIR_INC)/crypto.h $(DIR_INC)/types.h $(DIR_INC)/sc_reduce32copy.h $(DIR_INC)/sha/sha256.h $(DIR_INC)/export.h
	$(CPP) $(CFLAGS) -I$(DIR_INC) $(DIR_CORE)/transaction.cpp

types.o: $(DIR_CORE)/types.cpp $(DIR_INC)/types.h $(DIR_INC)/crypto_curve.h $(DIR_INC)/util.h
	$(CPP) $(CFLAGS) -I$(DIR_INC) $(DIR_CORE)/types.cpp

# util
memwipe.o: $(DIR_UTIL)/memwipe.c $(DIR_INC)/util/memwipe.h
	$(CC) $(CFLAGS) -I$(DIR_INC) $(DIR_UTIL)/memwipe.c

aligned.o: $(DIR_UTIL)/aligned.c $(DIR_INC)/util/aligned.h
	$(CC) $(CFLAGS) -I$(DIR_INC) $(DIR_UTIL)/aligned.c

# crypto/sha
sha256.o: $(DIR_CRYPTO)/sha/sha256.c $(DIR_INC)/sha/sha256.h $(DIR_INC)/util.h
	$(CC) $(CFLAGS) -I$(DIR_INC) $(DIR_CRYPTO)/sha/sha256.c

sha512.o: $(DIR_CRYPTO)/sha/sha512.c $(DIR_INC)/sha/sha512.h $(DIR_INC)/util.h
	$(CC) $(CFLAGS) -I$(DIR_INC) $(DIR_CRYPTO)/sha/sha512.c

# crypto/ripemd160
ripemd160.o: $(DIR_CRYPTO)/ripemd160/ripemd160.c $(DIR_INC)/ripemd160/ripemd160.h
	$(CC) $(CFLAGS) -I$(DIR_INC) $(DIR_CRYPTO)/ripemd160/ripemd160.c

# crypto/keccak
keccak.o: $(DIR_CRYPTO)/keccak/keccak.c $(DIR_INC)/keccak/keccak.h $(DIR_INC)/util.h
	$(CC) $(CFLAGS) -I$(DIR_INC) $(DIR_CRYPTO)/keccak/keccak.c

# crypto/random
random.o: $(DIR_CRYPTO)/random/random.c $(DIR_INC)/random/random.h $(DIR_INC)/sha/sha512.h $(DIR_INC)/initializer.h 
	$(CC) $(CFLAGS) -I$(DIR_INC) $(DIR_CRYPTO)/random/random.c

chacha20.o: $(DIR_CRYPTO)/random/chacha20.c $(DIR_INC)/random/chacha20.h $(DIR_INC)/util.h
	$(CC) $(CFLAGS) -I$(DIR_INC) $(DIR_CRYPTO)/random/chacha20.c

# crypto/hmac
hmacsha256.o: $(DIR_CRYPTO)/hmac/hmacsha256.c $(DIR_INC)/hmac/hmacsha256.h $(DIR_INC)/sha/sha256.h $(DIR_INC)/verify.h $(DIR_INC)/random/random.h $(DIR_INC)/util.h
	$(CC) $(CFLAGS) -I$(DIR_INC) $(DIR_CRYPTO)/hmac/hmacsha256.c

hmacsha512.o: $(DIR_CRYPTO)/hmac/hmacsha512.c $(DIR_INC)/hmac/hmacsha512.h $(DIR_INC)/sha/sha512.h $(DIR_INC)/verify.h $(DIR_INC)/random/random.h $(DIR_INC)/util.h
	$(CC) $(CFLAGS) -I$(DIR_INC) $(DIR_CRYPTO)/hmac/hmacsha512.c

# crypto/pbkdf2
pbkdf2.o: $(DIR_CRYPTO)/pbkdf2/pbkdf2.c $(DIR_INC)/pbkdf2/pbkdf2.h $(DIR_INC)/util.h $(DIR_INC)/hmac/hmacsha256.h
	$(CC) $(CFLAGS) -I$(DIR_INC) $(DIR_CRYPTO)/pbkdf2/pbkdf2.c

# crypto
verify.o: $(DIR_CRYPTO)/verify.c $(DIR_INC)/verify.h
	$(CC) $(CFLAGS) -I$(DIR_INC) $(DIR_CRYPTO)/verify.c

crypto_curve.o: $(DIR_CRYPTO)/crypto_curve.c $(DIR_INC)/crypto_curve.h
	$(CC) $(CFLAGS) -I$(DIR_INC) $(DIR_CRYPTO)/crypto_curve.c

crypto_data.o: $(DIR_CRYPTO)/crypto_data.c $(DIR_INC)/crypto_curve.h
	$(CC) $(CFLAGS) -I$(DIR_INC) $(DIR_CRYPTO)/crypto_data.c

crypto.o: $(DIR_CRYPTO)/crypto.cpp $(DIR_INC)/crypto.h $(DIR_INC)/random/random.h $(DIR_INC)/sha/sha256.h $(DIR_INC)/crypto_curve.h
	$(CPP) $(CFLAGS) -I$(BOOST) -I$(DIR_INC) $(DIR_CRYPTO)/crypto.cpp


all: bulletproof.o bulletproof_plus.o multiexp.o ops.o proofs.o sc_reduce32copy.o transaction.o types.o memwipe.o aligned.o sha256.o sha512.o ripemd160.o random.o chacha20.o hmacsha256.o hmacsha512.o pbkdf2.o keccak.o verify.o crypto_curve.o crypto_data.o crypto.o

clean:
	rm -f *.o *.so *.dll

core: all
	$(CPP) -L$(BOOST_LIB) -lboost_thread -shared -o ../linux/DiscreetCore.so bulletproof.o bulletproof_plus.o multiexp.o ops.o proofs.o sc_reduce32copy.o transaction.o types.o memwipe.o aligned.o sha256.o sha512.o ripemd160.o random.o chacha20.o hmacsha256.o hmacsha512.o pbkdf2.o keccak.o verify.o crypto_curve.o crypto_data.o crypto.o

