CXX=clang++
CFLAGS=-I/usr/include/nspr4 -I/usr/include/nss3 -I/usr/local/opt/nss/include/nss -I/usr/local/opt/nspr/include/nspr -Wall -g --std=c++11
LDFLAGS=-lnss3 -lnspr4 -lsmime3 -L/usr/local/opt/nss/lib

default: import-client-cert

import-client-cert: import-client-cert.cpp Makefile
	$(CXX) -o import-client-cert import-client-cert.cpp $(CFLAGS) $(LDFLAGS)

clean:
	rm -f import-client-cert cert9.db key4.db pkcs11.txt
