CXX=clang++
CFLAGS=-I/usr/include/nspr4 -I/usr/include/nss3 -Wall -g
LDFLAGS=-lnss3 -lnspr4 -lsmime3

default: import-client-cert

import-client-cert: import-client-cert.cpp Makefile
	$(CXX) -o import-client-cert import-client-cert.cpp $(CFLAGS) $(LDFLAGS)

clean:
	rm -f import-client-cert cert9.db key4.db
