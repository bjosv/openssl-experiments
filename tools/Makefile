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

CFLAGS = -std=c99 -O3 -g -ggdb -pedantic -Wall -Wextra
LDLIBS = -lssl -lcrypto

all: dtls-server dtls-client

clean:
	rm -f dtls-server dtls-client

dtls-server: dtls-server.c
	$(CC) $(CFLAGS) $(INCLUDES) $(LDFLAGS) -o $@ $< $(LDLIBS)

dtls-client: dtls-client.c
	$(CC) $(CFLAGS) $(INCLUDES) $(LDFLAGS) -o $@ $< $(LDLIBS)

.PHONY: certs
certs:
	mkdir -p dtls
	openssl genrsa -out dtls/ca.key 4096
	openssl req -x509 -new -nodes -sha256 -key dtls/ca.key -days 3650 -subj '/O=Test/CN=Certificate Authority' -out dtls/ca.crt
	openssl genrsa -out dtls/server.key 2048
	openssl req -new -sha256 -key dtls/server.key -subj '/O=Test/CN=Server' | openssl x509 -req -sha256 -CA dtls/ca.crt -CAkey dtls/ca.key -CAserial dtls/ca.txt -CAcreateserial -days 1 -out dtls/server.crt
	openssl genrsa -out dtls/client.key 2048
	openssl req -new -sha256 -key dtls/client.key -subj '/O=Test/CN=Client' | openssl x509 -req -sha256 -CA dtls/ca.crt -CAkey dtls/ca.key -CAserial dtls/ca.txt -CAcreateserial -days 1 -out dtls/client.crt
