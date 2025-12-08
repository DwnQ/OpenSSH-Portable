#include "includes.h"
#include "sshkey.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "log.h"

#include <string.h>
#include <stdlib.h>

#include <pqclean_falcon-512_clean/api.h>

#define SSH_FALCON512 "pqc-falcon512"

#include <sys/time.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

static void
log_benchmark(const char *stage)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    struct tm *tm_info = localtime(&tv.tv_sec);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm_info);

    debug3("falcon: [%s.%06ld] %s",
        ts,
        (long)tv.tv_usec,
        stage ? stage : "");
}
static int
falcon512_alloc(struct sshkey *k)
{
    debug3("falcon512_alloc");

    k->falcon512_pk = NULL;
    k->falcon512_pk_len = 0;

    k->falcon512_sk = NULL;
    k->falcon512_sk_len = 0;

    return 0;
}

static void
falcon512_cleanup(struct sshkey *k)
{
    debug3("falcon512_cleanup");

    if (k->falcon512_pk) {
        explicit_bzero(k->falcon512_pk, k->falcon512_pk_len);
        free(k->falcon512_pk);
    }
    if (k->falcon512_sk) {
        explicit_bzero(k->falcon512_sk, k->falcon512_sk_len);
        free(k->falcon512_sk);
    }
}

static int
falcon512_generate(struct sshkey *k, int unused_bits)
{
    log_benchmark("falcon_generate:start");
    debug3("falcon512_generate keypair");

    k->falcon512_pk_len = PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES;
    k->falcon512_sk_len = PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES;

    k->falcon512_pk = malloc(k->falcon512_pk_len);
    k->falcon512_sk = malloc(k->falcon512_sk_len);
    if (!k->falcon512_pk || !k->falcon512_sk)
        return SSH_ERR_ALLOC_FAIL;

    if (PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(
            k->falcon512_pk, k->falcon512_sk) != 0)
    {
        return SSH_ERR_LIBCRYPTO_ERROR;
    }

    k->type = KEY_FALCON512;
    log_benchmark("falcon_generate:eng");
    return 0;
}


static int
falcon512_serialize_public(const struct sshkey *k, struct sshbuf *b,
                           enum sshkey_serialize_rep rep)
{
    log_benchmark("falcon_serialize_public");
    debug3("falcon512_serialize_public");

    if (!k->falcon512_pk)
        return SSH_ERR_INVALID_ARGUMENT;

    int r;
    if ((r = sshbuf_put_string(b, k->falcon512_pk,
                               k->falcon512_pk_len)) != 0)
        return r;

    return 0;
}


static int
falcon512_deserialize_public(const char *typename, struct sshbuf *b,
                             struct sshkey *k)
{
    log_benchmark("falcon_deserialize_public");

    debug3("falcon512_deserialize_public");

    u_char *pk = NULL;
    size_t pklen = 0;
    int r;

    if ((r = sshbuf_get_string(b, &pk, &pklen)) != 0) {
        debug3("falcon512_deserialize_public: sshbuf_get_string failed: %d", r);
        return r;
    }

    /* Validate public key length */
    if (pklen != PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES) {
        debug3("falcon512_deserialize_public: invalid pk len %zu (expected %d)", pklen, PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES);
        free(pk);
        return SSH_ERR_INVALID_FORMAT;
    }

    k->falcon512_pk = pk;
    k->falcon512_pk_len = pklen;
    k->type = KEY_FALCON512;

    return 0;
}


static int
falcon512_serialize_private(const struct sshkey *k, struct sshbuf *b,
                            enum sshkey_serialize_rep rep)
{
    log_benchmark("falcon_serialize_private");

    debug3("falcon512_serialize_private");
    
    int r;

    if ((r = falcon512_serialize_public(k, b, rep)) != 0)
        return r;

    if ((r = sshbuf_put_string(b, k->falcon512_sk,
                               k->falcon512_sk_len)) != 0)
        return r;

    if ((r = sshbuf_put_cstring(b, "")) != 0)
        return r;

    return 0;
}


static int
falcon512_deserialize_private(const char *typename, struct sshbuf *b,
                              struct sshkey *k)
{
    log_benchmark("falcon_deserialize_private");

    debug3("falcon512_deserialize_private");

    int r;

    if ((r = falcon512_deserialize_public(typename, b, k)) != 0)
        return r;

    u_char *sk = NULL;
    size_t sklen = 0;

    if ((r = sshbuf_get_string(b, &sk, &sklen)) != 0)
        return r;

    if (sklen != PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES) {
        free(sk);
        return SSH_ERR_INVALID_FORMAT;
    }

    k->falcon512_sk = sk;
    k->falcon512_sk_len = sklen;

    char *comment = NULL;
    if ((r = sshbuf_get_cstring(b, &comment, NULL)) != 0) {
        return r;
    }
    free(comment);    

    return 0;
}


static int
falcon512_copy_public(const struct sshkey *from, struct sshkey *to)
{
    debug3("falcon512_copy_public");

    to->falcon512_pk = malloc(from->falcon512_pk_len);
    if (!to->falcon512_pk)
        return SSH_ERR_ALLOC_FAIL;

    memcpy(to->falcon512_pk, from->falcon512_pk, from->falcon512_pk_len);
    to->falcon512_pk_len = from->falcon512_pk_len;
    to->type = KEY_FALCON512;

    return 0;
}


static int
falcon512_equal(const struct sshkey *a, const struct sshkey *b)
{
    if (!a->falcon512_pk || !b->falcon512_pk)
        return 0;

    if (a->falcon512_pk_len != b->falcon512_pk_len)
        return 0;

    return memcmp(a->falcon512_pk, b->falcon512_pk,
                  a->falcon512_pk_len) == 0;
}


static int
falcon512_sign(struct sshkey *k,
               u_char **sigp, size_t *lenp,
               const u_char *data, size_t datalen,
               const char *alg,
               const char *sk_app, const char *sk_pin,
               u_int compat)
{
    log_benchmark("falcon512_sign:start");
    debug3("falcon512_sign");

    if (!k->falcon512_sk)
        return SSH_ERR_INVALID_ARGUMENT;

    uint8_t sigbuf[PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES];
    size_t siglen = sizeof(sigbuf);

    if (PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(
            sigbuf, &siglen, data, datalen, k->falcon512_sk) != 0)
        return SSH_ERR_LIBCRYPTO_ERROR;

    struct sshbuf *b = sshbuf_new();
    if (!b)
        return SSH_ERR_ALLOC_FAIL;

    int r;
    if ((r = sshbuf_put_cstring(b, SSH_FALCON512)) != 0 ||
        (r = sshbuf_put_string(b, sigbuf, siglen)) != 0)
        goto out;

    size_t len = sshbuf_len(b);
    *sigp = malloc(len);
    if (!*sigp) { sshbuf_free(b); return SSH_ERR_ALLOC_FAIL; }
    memcpy(*sigp, sshbuf_ptr(b), len);
    *lenp = len;
    r = 0;

out:
    sshbuf_free(b);
    log_benchmark("falcon512_sign:eng");
    return r;
}


static int
falcon512_verify(const struct sshkey *k,
                 const u_char *sig, size_t siglen,
                 const u_char *data, size_t datalen,
                 const char *alg,
                 u_int compat,
                 struct sshkey_sig_details **detailsp)
{
    log_benchmark("falcon512_verify:start");

    debug3("falcon512_verify");

    if (!k->falcon512_pk)
        return SSH_ERR_INVALID_ARGUMENT;

    struct sshbuf *b = sshbuf_from(sig, siglen);
    if (!b)
        return SSH_ERR_ALLOC_FAIL;

    char *sig_alg = NULL;
    u_char *raw = NULL;
    size_t rawlen = 0;
    int r = 0;

    if ((r = sshbuf_get_cstring(b, &sig_alg, NULL)) != 0)
        goto out;

    if (strcmp(sig_alg, SSH_FALCON512) != 0) {
        r = SSH_ERR_KEY_TYPE_MISMATCH;
        goto out;
    }

    if ((r = sshbuf_get_string(b, &raw, &rawlen)) != 0)
        goto out;

    if (PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(
            raw, rawlen, data, datalen, k->falcon512_pk) != 0)
    {
        r = SSH_ERR_SIGNATURE_INVALID;
        goto out;
    }

    r = 0;

out:
    free(sig_alg);
    free(raw);
    sshbuf_free(b);
    log_benchmark("falcon512_verify:end");
    
    return r;
}


static const struct sshkey_impl_funcs falcon512_funcs = {
    .alloc              = falcon512_alloc,
    .cleanup            = falcon512_cleanup,
    .equal              = falcon512_equal,
    .serialize_public   = falcon512_serialize_public,
    .deserialize_public = falcon512_deserialize_public,
    .serialize_private  = falcon512_serialize_private,
    .deserialize_private= falcon512_deserialize_private,
    .generate           = falcon512_generate,
    .copy_public        = falcon512_copy_public,
    .sign               = falcon512_sign,
    .verify             = falcon512_verify,
};

/* ---------- final OpenSSH registration ---------- */

const struct sshkey_impl sshkey_falcon512_impl = {
    .name      = "pqc-falcon512",
    .shortname = "falcon512",
    .sigalg    = SSH_FALCON512,
    .type      = KEY_FALCON512,
    .nid       = 0, 
    .cert      = 0,
    .sigonly   = 0,
    .keybits   = 512,
    .funcs     = &falcon512_funcs,
};
