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

int main(int argc UNUSED, char **argv UNUSED)
{
    printf("Using %s\n", OPENSSL_VERSION_TEXT);

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd);

    if (bind(fd, (struct sockaddr *) &server_addr, sizeof(server_addr)))
        openssl_abort("Failed to bind");
    printf("Bind successful\n");

    /* Setup context. */
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    openssl_assert(ctx, "Failed to create context");

    if (SSL_CTX_use_certificate_file(ctx, "dtls/server.crt", SSL_FILETYPE_PEM) != 1)
        openssl_abort("Failed to load certificate file");
    if (SSL_CTX_use_PrivateKey_file(ctx, "dtls/server.key", SSL_FILETYPE_PEM) != 1)
        openssl_abort("Failed to load private key file");
    if (SSL_CTX_check_private_key(ctx) != 1)
        openssl_abort("Invalid private key");

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    memset(&client_addr, 0, client_len);

    if (listen(fd, 1) < 0)
        openssl_abort("Unable to listen on socket");
    int c_fd = accept(fd, (struct sockaddr *)&client_addr, &client_len);
    openssl_assert(c_fd, "Unable to accept client connection");

    SSL *ssl = SSL_new(ctx);
    SSL_set_max_proto_version(ssl, TLS1_2_VERSION); /* TLSv1.2 only */
    SSL_set_fd(ssl, c_fd);

    printf("Got a connection from: %s:%d\n",
           inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    if (SSL_accept(ssl) <= 0)
        openssl_abort("Handshake failed");
    printf("Handshake successful\n");

    #define BUFSIZE 2048
    char buffer[BUFSIZE];
    memset(buffer, 0, BUFSIZE);

    while (1) {
        int bytes = SSL_read(ssl, buffer, BUFSIZE);
        if (bytes <= 0)
            openssl_abort("TLS read failed");
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}
