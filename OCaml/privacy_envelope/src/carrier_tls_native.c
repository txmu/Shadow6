/* Standard TLS 1.3 carrier. Never parses S6EPE records or Native Core bytes. */
#include "carrier_tls_native.h"
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

struct s6_tls_context { SSL_CTX *ctx; };
struct s6_tls { SSL *ssl; int established; int failed; };

static int trailing_space(BIO *bio) {
    unsigned char bytes[256]; int n;
    while ((n = BIO_read(bio, bytes, sizeof bytes)) > 0)
        for (int i = 0; i < n; ++i)
            if (bytes[i] != ' ' && bytes[i] != '\n' && bytes[i] != '\r' && bytes[i] != '\t') return 0;
    return BIO_ctrl_pending(bio) == 0;
}
static X509 *certificate(const char *data, size_t size) {
    const char prefix[] = "-----BEGIN CERTIFICATE-----\n";
    if (!data || size < sizeof prefix - 1 || size > 16384 || memcmp(data, prefix, sizeof prefix - 1)) return NULL;
    BIO *bio = BIO_new_mem_buf(data, (int)size);
    if (!bio) return NULL;
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (cert && !trailing_space(bio)) { X509_free(cert); cert = NULL; }
    BIO_free(bio);
    if (cert) {
        EVP_PKEY *public_key = X509_get_pubkey(cert);
        int valid = public_key && EVP_PKEY_id(public_key) == EVP_PKEY_ED25519;
        EVP_PKEY_free(public_key);
        if (!valid) { X509_free(cert); cert = NULL; }
    }
    return cert;
}
static int no_password(char *buffer, int size, int writing, void *arg) {
    (void)buffer; (void)size; (void)writing; (void)arg; return 0;
}
static EVP_PKEY *private_key(const char *data, size_t size) {
    const char prefix[] = "-----BEGIN PRIVATE KEY-----\n";
    if (!data || size < sizeof prefix - 1 || size > 16384 || memcmp(data, prefix, sizeof prefix - 1)) return NULL;
    BIO *bio = BIO_new_mem_buf(data, (int)size);
    if (!bio) return NULL;
    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, NULL, no_password, NULL);
    if (key && (!trailing_space(bio) || EVP_PKEY_id(key) != EVP_PKEY_ED25519)) { EVP_PKEY_free(key); key = NULL; }
    BIO_free(bio); return key;
}
s6_tls_context *s6_tls_context_create(const char *cert_data, size_t cert_size,
                                     const char *key_data, size_t key_size,
                                     const char *ca_data, size_t ca_size) {
    ERR_clear_error();
    X509 *cert = certificate(cert_data, cert_size), *ca = certificate(ca_data, ca_size);
    EVP_PKEY *key = private_key(key_data, key_size);
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    int valid = cert && ca && key && ctx && X509_check_ca(ca) > 0 &&
        X509_get_signature_nid(cert) == NID_ED25519 && X509_get_signature_nid(ca) == NID_ED25519;
    if (valid) valid = SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) == 1 &&
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) == 1 &&
        SSL_CTX_set1_groups_list(ctx, "X25519") == 1 &&
        SSL_CTX_set1_sigalgs_list(ctx, "ed25519") == 1 &&
        SSL_CTX_use_certificate(ctx, cert) == 1 && SSL_CTX_use_PrivateKey(ctx, key) == 1 &&
        SSL_CTX_check_private_key(ctx) == 1 && X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), ca) == 1 &&
        SSL_CTX_set_num_tickets(ctx, 0) == 1 && SSL_CTX_set_max_early_data(ctx, 0) == 1;
    X509_free(cert); X509_free(ca); EVP_PKEY_free(key);
    if (!valid) { SSL_CTX_free(ctx); return NULL; }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 1);
    SSL_CTX_set_max_cert_list(ctx, 16384);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET | SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    s6_tls_context *context = malloc(sizeof *context);
    if (!context) { SSL_CTX_free(ctx); return NULL; }
    context->ctx = ctx; return context;
}
void s6_tls_context_free(s6_tls_context *context) {
    if (context) { SSL_CTX_free(context->ctx); free(context); }
}
s6_tls *s6_tls_create(s6_tls_context *context, int fd, int server, const char *peer_name) {
    int type = 0; socklen_t length = sizeof type;
    int flags = fcntl(fd, F_GETFL);
    if (!context || !peer_name || !*peer_name || strlen(peer_name) > 253 ||
        flags < 0 || !(flags & O_NONBLOCK) ||
        getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) || type != SOCK_STREAM) return NULL;
    SSL *ssl = SSL_new(context->ctx);
    if (!ssl) return NULL;
    X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT | X509_CHECK_FLAG_NO_WILDCARDS);
    int numeric_ip = X509_VERIFY_PARAM_set1_ip_asc(param, peer_name) == 1;
    if (SSL_set_fd(ssl, fd) != 1 || (!numeric_ip && SSL_set1_host(ssl, peer_name) != 1) ||
        (!server && !numeric_ip && SSL_set_tlsext_host_name(ssl, peer_name) != 1)) {
        SSL_free(ssl); return NULL;
    }
    if (server) SSL_set_accept_state(ssl); else SSL_set_connect_state(ssl);
    s6_tls *session = malloc(sizeof *session);
    if (!session) { SSL_free(ssl); return NULL; }
    session->ssl = ssl; session->established = 0; session->failed = 0; return session;
}
void s6_tls_free(s6_tls *session) {
    if (session) { SSL_free(session->ssl); free(session); }
}
static int retry(s6_tls *session, int result, int allow_eof) {
    int error = SSL_get_error(session->ssl, result);
    if (error == SSL_ERROR_WANT_READ) return -1;
    if (error == SSL_ERROR_WANT_WRITE) return -2;
    if (allow_eof && error == SSL_ERROR_ZERO_RETURN) return 0;
    session->failed = 1;
    return -3; /* Includes unnotified TCP EOF and certificate/auth failures. */
}
int s6_tls_handshake(s6_tls *session) {
    if (!session || session->failed) return -3;
    ERR_clear_error(); int result = SSL_do_handshake(session->ssl);
    if (result != 1) return retry(session, result, 0);
    X509 *peer = SSL_get1_peer_certificate(session->ssl);
    int valid = peer && SSL_get_verify_result(session->ssl) == X509_V_OK;
    X509_free(peer);
    if (valid) session->established = 1; else session->failed = 1;
    return valid ? 1 : -3;
}
int s6_tls_read(s6_tls *session, void *data, size_t size) {
    if (!session || session->failed || !session->established || !data || size == 0 || size > 131072) return -3;
    ERR_clear_error(); size_t count = 0;
    int result = SSL_read_ex(session->ssl, data, size, &count);
    return result == 1 ? (int)count : retry(session, result, 1);
}
int s6_tls_write(s6_tls *session, const void *data, size_t size) {
    if (!session || session->failed || !session->established || !data || size == 0 || size > 131072) return -3;
    ERR_clear_error(); size_t count = 0;
    int result = SSL_write_ex(session->ssl, data, size, &count);
    return result == 1 ? (int)count : retry(session, result, 0);
}
int s6_tls_pending(s6_tls *session) { return session ? SSL_pending(session->ssl) : 0; }
int s6_tls_has_pending(s6_tls *session) { return session ? SSL_has_pending(session->ssl) : 0; }
int s6_tls_shutdown_send(s6_tls *session) {
    if (!session || session->failed || !session->established) return -3;
    ERR_clear_error(); int result = SSL_shutdown(session->ssl);
    /* Do not wait for peer close_notify: TLS receive-half remains usable. */
    return result >= 0 ? 1 : retry(session, result, 0);
}
