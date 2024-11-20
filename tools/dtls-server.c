#include <assert.h>
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <unistd.h>

#define SERVER_PORT 4433
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

static int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
    unsigned char *buf = (unsigned char *)OPENSSL_malloc(1024);
    assert(buf);
    if (!SSL_get_server_random(ssl, buf, 32))
        openssl_abort("SSL_get_server_random failed");
    if (!SSL_get_client_random(ssl, buf + 32, 32))
        openssl_abort("SSL_get_client_random failed");
    int len = 32 + 32;

    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int resultlen;
    if (!EVP_Digest(buf, len, result, &resultlen, EVP_sha1(), NULL))
        openssl_abort("EVP_Digest failed");
    memcpy(cookie, result, 16);
    *cookie_len = 16;
    OPENSSL_free(buf);
    return 1;
}

static int verify_cookie(SSL *ssl UNUSED, const unsigned char *cookie UNUSED, unsigned int cookie_len UNUSED) {
    return 1; /* Always accept */
}

int main(int argc UNUSED, char **argv UNUSED)
{
    printf("Using %s\n", OPENSSL_VERSION_TEXT);

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd);

    if (bind(fd, (struct sockaddr *) &server_addr, sizeof(server_addr)))
        openssl_abort("Failed to bind");
    printf("Bind successful\n");

    /* Setup context. */
    SSL_CTX *ctx = SSL_CTX_new(DTLS_server_method());
    openssl_assert(ctx, "Failed to create context");

    if (SSL_CTX_use_certificate_file(ctx, "dtls/server.crt", SSL_FILETYPE_PEM) != 1)
        openssl_abort("Failed to load certificate file");
    if (SSL_CTX_use_PrivateKey_file(ctx, "dtls/server.key", SSL_FILETYPE_PEM) != 1)
        openssl_abort("Failed to load private key file");
    if (SSL_CTX_check_private_key(ctx) != 1)
        openssl_abort("Invalid private key");

    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(ctx, &verify_cookie);

    /* Create a Basic I/O */
    BIO *bio = BIO_new_dgram(fd, BIO_NOCLOSE);

    SSL *ssl = SSL_new(ctx);
    SSL_set_bio(ssl, bio, bio);

    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));

    printf("DTLSv1 listen...\n");
    while (DTLSv1_listen(ssl, (BIO_ADDR *)&client_addr) <= 0)
        ERR_print_errors_fp(stderr);

    printf("DTLSv1 listen got a connection from: %s:%d\n",
           inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    if (SSL_accept(ssl) <= 0)
        openssl_abort("DTLS accept failed");
    printf("DTLS accept successful\n");

    #define BUFSIZE 2048
    char buffer[BUFSIZE];
    memset(buffer, 0, BUFSIZE);

    while (1) {
        int bytes = SSL_read(ssl, buffer, BUFSIZE);
        if (bytes <= 0)
            openssl_abort("DTLS read failed");
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}
