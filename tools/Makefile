CFLAGS = -std=c99 -O3 -g -ggdb -pedantic -Wall -Wextra
LDLIBS = -lssl -lcrypto

# Specify the OpenSSL revision/commit to build with.
# 3.1.7
#OPENSSL_REV = 3c6a7a1
# 3.2.3
#OPENSSL_REV = 45fda76
# 3.3.2
#OPENSSL_REV = fb7fab9
# 3.4.0
OPENSSL_REV = 98acb6b

# Use an own built OpenSSL that is installed in ~/tmp/, via:
# REV=98acb6b for openssl-3.4.0
# ./Configure --prefix=$HOME/tmp/openssl-$REV --openssldir=$HOME/tmp/openssl-$REV -Wl,-rpath=$HOME/tmp/openssl-$REV/lib64
INCLUDES    = -I$(HOME)/tmp/openssl-$(OPENSSL_REV)/include
LDFLAGS     = -L$(HOME)/tmp/openssl-$(OPENSSL_REV)/lib64 -Wl,-rpath,$(HOME)/tmp/openssl-$(OPENSSL_REV)/lib64
# alternatively use system installed:
# INCLUDES    = -I/usr/local/include
# LDFLAGS     = -L/usr/local/lib

all: dtls-server dtls-client

clean:
	rm -f dtls-server dtls-client

dtls-server: dtls-server.c
	$(CC) $(CFLAGS) $(INCLUDES) $(LDFLAGS) -o $@ $< $(LDLIBS)

dtls-client: dtls-client.c
	$(CC) $(CFLAGS) $(INCLUDES) $(LDFLAGS) -o $@ $< $(LDLIBS)
