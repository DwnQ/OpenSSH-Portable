#include "includes.h"

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "sshkey.h"
#include "kex.h"
#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"

#include "includes.h"
#include "sshkey.h"
#include "kex.h"
#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"
#include "log.h"
#include <openssl/sha.h>
#include <stdint.h>

#include <oqs/oqs.h>
#include <oqs/sha3.h>
#include <api.h>
#include <indcpa.h>
#include <openssl/sha.h>

#include <time.h>
#include <sys/time.h>

#define AES_IV_LEN 12
#define AES_TAG_LEN 12
#define AES_CIPHERTEXT_LEN 8
#define AES_LEN (AES_IV_LEN + AES_TAG_LEN + AES_CIPHERTEXT_LEN)

#include <sys/time.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

static void
log_benchmark(const struct kex *kex, const char *stage)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);

	struct tm *tm_info = localtime(&tv.tv_sec);
	char ts[64];
	strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm_info);

	const char *role = (kex && kex->server) ? "SERVER" : "CLIENT";

	debug3("kyber: [%s.%03ld] %s: %s",
	    ts, (long)(tv.tv_usec / 1000),
	    role, stage ? stage : "");
}


int kex_kem_mlkemcustom_keypair(struct kex *kex)
{
	struct sshbuf *buf = NULL;
	u_char *cp = NULL;
	size_t need;
	int r = 0;

	log_benchmark(kex, "keypair start");

	if ((buf = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	need = pqcrystals_kyber768_PUBLICKEYBYTES;
	if ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		goto out;

	pqcrystals_kyber768_ref_keypair(cp, kex->mlkem768_client_key);

	kex->client_pub = buf;
	buf = NULL;

out:
	log_benchmark(kex, "keypair end");
	sshbuf_free(buf);
	return r;
}

int kex_kem_mlkemcustom_enc(struct kex *kex,
							const struct sshbuf *client_blob,
							struct sshbuf **server_blobp,
							struct sshbuf **shared_secretp)
{
	struct sshbuf *server_blob = NULL;
	struct sshbuf *buf = NULL;
	const u_char *client_pub;
	u_char *kem_key, *outp;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t need;
	int r;

	u_char aes_key[32];

	uint8_t iv_len = AES_IV_LEN, tag_len = AES_TAG_LEN, ciphertext_len = AES_CIPHERTEXT_LEN;
	uint8_t *ivp = NULL, *tagp = NULL, *gcm_ctp = NULL;
	uint8_t payload[AES_CIPHERTEXT_LEN] = {0};

	*server_blobp = NULL;
	*shared_secretp = NULL;

	log_benchmark(kex, "encapsulation start");
	fflush(NULL);
	need = pqcrystals_kyber768_PUBLICKEYBYTES;
	if (sshbuf_len(client_blob) != need)
	{
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	client_pub = sshbuf_ptr(client_blob);

	if ((buf = sshbuf_new()) == NULL)
	{
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_reserve(buf, pqcrystals_kyber768_BYTES, &kem_key)) != 0)
		goto out;

	if ((server_blob = sshbuf_new()) == NULL)
	{
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	need = pqcrystals_kyber768_CIPHERTEXTBYTES + AES_LEN;
	if ((r = sshbuf_reserve(server_blob, need, &outp)) != 0)
		goto out;

	/* Kyber encapsulation */
	pqcrystals_kyber768_ref_enc(outp, kem_key, client_pub);

    /*  Derive AES key from Kyber shared secret using SHAKE-256 */
	if (SHA256(kem_key, pqcrystals_kyber768_BYTES, aes_key) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

    /* AES-GCM encryption using derived key */
    aes_gcm_256b_encrypt(payload, sizeof(payload),
                         (char *)aes_key, NULL, 0,
                         &ivp, &iv_len, &tagp, &tag_len,
                         &gcm_ctp, &ciphertext_len);

	/* Layout: [KyberCT | IV | TAG | GCM-CT] */
	memcpy(outp + pqcrystals_kyber768_CIPHERTEXTBYTES, ivp, iv_len);
	memcpy(outp + pqcrystals_kyber768_CIPHERTEXTBYTES + AES_IV_LEN, tagp, tag_len);
	memcpy(outp + pqcrystals_kyber768_CIPHERTEXTBYTES + AES_IV_LEN + AES_TAG_LEN,
		   gcm_ctp, ciphertext_len);

	/* Hash (Kyber SS + AES data) → final shared secret */
	if ((r = sshbuf_put(buf, kem_key, pqcrystals_kyber768_BYTES)) != 0)
		goto out;
	if ((r = sshbuf_put(buf, outp + pqcrystals_kyber768_CIPHERTEXTBYTES, AES_LEN)) != 0)
		goto out;
	if ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, sizeof(hash))) != 0)
		goto out;

	sshbuf_reset(buf);
	if ((r = sshbuf_put_string(buf, hash,
							   ssh_digest_bytes(kex->hash_alg))) != 0)
		goto out;

	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = NULL;
	buf = NULL;

out:
    log_benchmark(kex, "encapsulation end");
	if (ivp)
		OPENSSL_free(ivp);
	if (tagp)
		OPENSSL_free(tagp);
	if (gcm_ctp)
		OPENSSL_free(gcm_ctp);
	explicit_bzero(hash, sizeof(hash));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	explicit_bzero(aes_key, sizeof(aes_key)); 
	return r;
}

int kex_kem_mlkemcustom_dec(struct kex *kex,
							const struct sshbuf *server_blob,
							struct sshbuf **shared_secretp)
{
	struct sshbuf *buf = NULL;
	u_char *kem_key = NULL;
	const u_char *p;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t need;
	int r, ok;

	uint8_t iv[AES_IV_LEN];
	uint8_t iv_len = AES_IV_LEN;
	uint8_t tag[AES_TAG_LEN];
	uint8_t tag_len = AES_TAG_LEN;
	uint8_t ctext[AES_CIPHERTEXT_LEN];
	uint8_t ciphertext_len = AES_CIPHERTEXT_LEN;
	uint8_t *pt = NULL;
	uint8_t pt_len = 0;

	u_char aes_key[32];

	log_benchmark(kex, "decapsulation start");

	*shared_secretp = NULL;

	need = pqcrystals_kyber768_CIPHERTEXTBYTES + AES_LEN;
	if (sshbuf_len(server_blob) != need)
	{
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	p = sshbuf_ptr(server_blob);

	const u_char *ciphertext = p;
	p += pqcrystals_kyber768_CIPHERTEXTBYTES;
	memcpy(iv, p, AES_IV_LEN);
	p += AES_IV_LEN;
	memcpy(tag, p, AES_TAG_LEN);
	p += AES_TAG_LEN;
	memcpy(ctext, p, AES_CIPHERTEXT_LEN);

	if ((buf = sshbuf_new()) == NULL)
	{
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_reserve(buf, pqcrystals_kyber768_BYTES, &kem_key)) != 0)
		goto out;

	ok = pqcrystals_kyber768_ref_dec(kem_key, ciphertext, kex->mlkem768_client_key);
	if (ok != 0)
	{
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}

	/* Derive 32B AES key from Kyber shared secret using SHA-256 */
	if (SHA256(kem_key, pqcrystals_kyber768_BYTES, aes_key) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

    ok = aes_gcm_256b_decrypt(ctext, ciphertext_len,
                              (char *)aes_key, NULL, 0,
                              iv, iv_len, tag, tag_len,
                              &pt, &pt_len);
	if (ok != 0 || pt_len != AES_CIPHERTEXT_LEN)
	{
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}

	/* Hash (Kyber SS + AES data) → final shared secret */
	if ((r = sshbuf_put(buf, kem_key, pqcrystals_kyber768_BYTES)) != 0)
		goto out;
	if ((r = sshbuf_put(buf, iv, AES_IV_LEN)) != 0)
		goto out;
	if ((r = sshbuf_put(buf, tag, AES_TAG_LEN)) != 0)
		goto out;
	if ((r = sshbuf_put(buf, ctext, AES_CIPHERTEXT_LEN)) != 0)
		goto out;

	if ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, sizeof(hash))) != 0)
		goto out;

	sshbuf_reset(buf);
	if ((r = sshbuf_put_string(buf, hash,
							   ssh_digest_bytes(kex->hash_alg))) != 0)
		goto out;

	*shared_secretp = buf;
	buf = NULL;

out:
    log_benchmark(kex, "decapsulation end");
    explicit_bzero(aes_key, sizeof(aes_key));
	explicit_bzero(hash, sizeof(hash));
	if (pt)
		OPENSSL_free(pt);
	sshbuf_free(buf);
	return r;
}