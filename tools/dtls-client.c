#include <assert.h>
#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <unistd.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 4433
#define CLIENT_PORT 4434
#define UNUSED __attribute__((unused))

#define openssl_abort(msg)                      \
    {                                           \
        perror(msg);                            \
        ERR_print_errors_fp(stderr);            \
        abort();                                \
    }

#define openssl_assert(e, msg)                  \
    {                                           \
        if (!e) {                               \
            openssl_abort(msg);                 \
        }                                       \
    }

int main(int argc UNUSED, char **argv UNUSED)
{
    printf("Using %s\n", OPENSSL_VERSION_TEXT);

    SSL_CTX *ctx = SSL_CTX_new(DTLS_client_method());
    openssl_assert(ctx, "Failed to create context");

    if (SSL_CTX_use_certificate_file(ctx, "dtls/client.crt", SSL_FILETYPE_PEM) != 1)
        openssl_abort("Failed to load certificate file");

    if (SSL_CTX_use_PrivateKey_file(ctx, "dtls/client.key", SSL_FILETYPE_PEM) != 1)
        openssl_abort("Failed to load private key file");

    if (SSL_CTX_check_private_key(ctx) != 1)
        openssl_abort("Invalid private key");

    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(CLIENT_PORT);
    local_addr.sin_addr.s_addr = INADDR_ANY;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd);
    if (bind(fd, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0)
        openssl_abort("bind failed");

    struct sockaddr_in remote_addr;
    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &remote_addr.sin_addr) <= 0)
        openssl_abort("Invalid remote address");

    printf("Connecting...\n");
    BIO *bio = BIO_new_dgram(fd, BIO_NOCLOSE);
    if (connect(fd, (struct sockaddr *) &remote_addr, sizeof(remote_addr)))
        openssl_abort("connect failed");
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &remote_addr);

    SSL *ssl = SSL_new(ctx);
    SSL_set_bio(ssl, bio, bio);

    printf("DTLS handshake initiated...\n");
    if (SSL_connect(ssl) <= 0)
        openssl_abort("DTLS handshake failed");
    printf("DTLS handshake successful\n");

    #define BUFSIZE 1024

    char data[BUFSIZE];
    memset(data, 0xaa, BUFSIZE);
    size_t written = 0;

    int writes = 0;
    while(1) {
        if (SSL_write_ex(ssl, data, sizeof(data), &written) <= 0)
            openssl_abort("DTLS write failed");
        if (written != sizeof(data))
            openssl_abort("DTLS all data not sent");

        ++writes;
        if (writes % 100000 == 0) {
            printf("Number of writes: %dk\n", writes/1000);
#ifndef OPENSSL_NO_CRYPTO_MDEBUG
            int mcount = 0, rcount = 0, fcount = 0;
            CRYPTO_get_alloc_counts(&mcount, &rcount, &fcount);
            printf("malloc-count=%d, realloc-count=%d, free-count=%d\n", mcount, rcount, fcount);
#endif
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}
