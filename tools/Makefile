CFLAGS = -std=c99 -pedantic -Wall -g -Wextra
LDLIBS = -lssl -lcrypto

# INCLUDES    = -I/usr/local/include
# LDFLAGS     = -L/usr/local/lib

# Use a sanitizer
#CFLAGS += -fno-omit-frame-pointer -fsanitize=address
#CFLAGS += -fno-omit-frame-pointer -fsanitize=leak
#CFLAGS += -fno-omit-frame-pointer -fsanitize=undefined

all: dtls-server dtls-client

clean:
	rm dtls-server dtls-client

dtls-server: dtls-server.c
	$(CC) $(CFLAGS) $(INCLUDES) $(LDFLAGS) -o $@ $< $(LDLIBS)

dtls-client: dtls-client.c
	$(CC) $(CFLAGS) $(INCLUDES) $(LDFLAGS) -o $@ $< $(LDLIBS)
