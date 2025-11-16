[1mdiff --git a/kexmlkemcustom.c b/kexmlkemcustom.c[m
[1mindex 6b8d317..5489828 100644[m
[1m--- a/kexmlkemcustom.c[m
[1m+++ b/kexmlkemcustom.c[m
[36m@@ -28,37 +28,77 @@[m
 #include <indcpa.h>[m
 #include <openssl/sha.h>[m
 [m
[32m+[m[32m#include <time.h>[m[41m[m
[32m+[m[32m#include <sys/time.h>[m[41m[m
 [m
 #define AES_IV_LEN 12[m
 #define AES_TAG_LEN 12[m
 #define AES_CIPHERTEXT_LEN 8[m
 #define AES_LEN (AES_IV_LEN + AES_TAG_LEN + AES_CIPHERTEXT_LEN)[m
 [m
[32m+[m[32m#include <sys/time.h>[m[41m[m
[32m+[m[32m#include <time.h>[m[41m[m
[32m+[m[32m#include <fcntl.h>[m[41m[m
[32m+[m[32m#include <unistd.h>[m[41m[m
[32m+[m[32m#include <errno.h>[m[41m[m
[32m+[m[41m[m
[32m+[m[32mstatic void[m[41m[m
[32m+[m[32mlog_benchmark(const struct kex *kex, const char *stage)[m[41m[m
[32m+[m[32m{[m[41m[m
[32m+[m	[32m/* wall-clock for readable timestamp */[m[41m[m
[32m+[m	[32mstruct timeval tv;[m[41m[m
[32m+[m	[32mgettimeofday(&tv, NULL);[m[41m[m
[32m+[m	[32mstruct tm *tm_info = localtime(&tv.tv_sec);[m[41m[m
[32m+[m	[32mchar ts[64];[m[41m[m
[32m+[m	[32mstrftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm_info);[m[41m[m
[32m+[m[41m[m
[32m+[m	[32m/* monotonic clock for accurate deltas */[m[41m[m
[32m+[m	[32mstatic int t0_init = 0;[m[41m[m
[32m+[m	[32mstatic struct timespec t0;[m[41m[m
[32m+[m	[32mstruct timespec now;[m[41m[m
[32m+[m	[32mif (!t0_init) {[m[41m[m
[32m+[m		[32mclock_gettime(CLOCK_MONOTONIC, &t0);[m[41m[m
[32m+[m		[32mt0_init = 1;[m[41m[m
[32m+[m	[32m}[m[41m[m
[32m+[m	[32mclock_gettime(CLOCK_MONOTONIC, &now);[m[41m[m
[32m+[m	[32mlong dms = (now.tv_sec - t0.tv_sec) * 1000L +[m[41m[m
[32m+[m	[32m           (now.tv_nsec - t0.tv_nsec) / 1000000L;[m[41m[m
[32m+[m[41m[m
[32m+[m	[32mconst char *role = (kex && kex->server) ? "SERVER" : "CLIENT";[m[41m[m
[32m+[m	[32mconst char *kname = (kex && kex->name) ? kex->name : "?";[m[41m[m
[32m+[m	[32mconst char *hname = (kex) ? ssh_digest_alg_name(kex->hash_alg) : "?";[m[41m[m
[32m+[m[41m[m
[32m+[m	[32mdebug3("[%s.%03ld] %s: %s | +%ldms | kex=%s hash=%s",[m[41m[m
[32m+[m	[32m    ts, (long)(tv.tv_usec / 1000),[m[41m[m
[32m+[m	[32m    role, stage ? stage : "", dms, kname, hname);[m[41m[m
[32m+[m[32m}[m[41m[m
[32m+[m[41m[m
[32m+[m[41m[m
 int kex_kem_mlkemcustom_keypair(struct kex *kex)[m
 {[m
[31m-    struct sshbuf *buf = NULL;[m
[31m-    u_char *cp = NULL;[m
[31m-    size_t need;[m
[31m-    int r = 0;                 [m
[32m+[m	[32mstruct sshbuf *buf = NULL;[m[41m[m
[32m+[m	[32mu_char *cp = NULL;[m[41m[m
[32m+[m	[32msize_t need;[m[41m[m
[32m+[m	[32mint r = 0;[m[41m[m
 [m
[31m-    if ((buf = sshbuf_new()) == NULL)[m
[31m-        return SSH_ERR_ALLOC_FAIL;[m
[32m+[m	[32mlog_benchmark(kex, "keypair start");[m[41m[m
 [m
[31m-    /* include ONLY the Kyber public key */[m
[31m-    need = pqcrystals_kyber768_PUBLICKEYBYTES;       [m
[31m-    if ((r = sshbuf_reserve(buf, need, &cp)) != 0)[m
[31m-        goto out;[m
[32m+[m	[32mif ((buf = sshbuf_new()) == NULL)[m[41m[m
[32m+[m		[32mreturn SSH_ERR_ALLOC_FAIL;[m[41m[m
 [m
[31m-    /* Kyber keypair generation: pk=cp, sk=kex->mlkem768_client_key */[m
[31m-    pqcrystals_kyber768_ref_keypair(cp, kex->mlkem768_client_key);[m
[32m+[m	[32mneed = pqcrystals_kyber768_PUBLICKEYBYTES;[m[41m[m
[32m+[m	[32mif ((r = sshbuf_reserve(buf, need, &cp)) != 0)[m[41m[m
[32m+[m		[32mgoto out;[m[41m[m
 [m
[31m-    /* no AES placeholder here */[m
[32m+[m	[32m// pqcrystals_kyber768_ref_keypair(cp, kex->mlkem768_client_key);[m[41m[m
[32m+[m	[32mpqcrystals_kyber768_avx2_keypair(cp, kex->mlkem768_client_key);[m[41m[m
[32m+[m	[32mkex->client_pub = buf;[m[41m[m
[32m+[m	[32mbuf = NULL;[m[41m[m
 [m
[31m-    kex->client_pub = buf;[m
[31m-    buf = NULL;[m
 out:[m
[31m-    sshbuf_free(buf);[m
[31m-    return r;[m
[32m+[m	[32mlog_benchmark(kex, "keypair end");[m[41m[m
[32m+[m	[32msshbuf_free(buf);[m[41m[m
[32m+[m	[32mreturn r;[m[41m[m
 }[m
 [m
 int kex_kem_mlkemcustom_enc(struct kex *kex,[m
[36m@@ -83,6 +123,8 @@[m [mint kex_kem_mlkemcustom_enc(struct kex *kex,[m
 	*server_blobp = NULL;[m
 	*shared_secretp = NULL;[m
 [m
[32m+[m	[32mlog_benchmark(kex, "encapsulation start");[m[41m[m
[32m+[m	[32mfflush(NULL);[m[41m[m
 	need = pqcrystals_kyber768_PUBLICKEYBYTES;[m
 	if (sshbuf_len(client_blob) != need)[m
 	{[m
[36m@@ -109,7 +151,9 @@[m [mint kex_kem_mlkemcustom_enc(struct kex *kex,[m
 		goto out;[m
 [m
 	/* Kyber encapsulation */[m
[31m-	pqcrystals_kyber768_ref_enc(outp, kem_key, client_pub);[m
[32m+[m	[32m// pqcrystals_kyber768_ref_enc(outp, kem_key, client_pub);[m[41m[m
[32m+[m	[32mpqcrystals_kyber768_avx2_enc(outp, kem_key, client_pub);[m[41m[m
[32m+[m[41m	[m
 [m
     /*  Derive AES key from Kyber shared secret using SHAKE-256 */[m
 if (SHA256(kem_key, pqcrystals_kyber768_BYTES, aes_key) == NULL) {[m
[36m@@ -148,6 +192,7 @@[m [mif (SHA256(kem_key, pqcrystals_kyber768_BYTES, aes_key) == NULL) {[m
 	buf = NULL;[m
 [m
 out:[m
[32m+[m[32m    log_benchmark(kex, "encapsulation end");[m[41m[m
 	if (ivp)[m
 		OPENSSL_free(ivp);[m
 	if (tagp)[m
[36m@@ -183,6 +228,8 @@[m [mint kex_kem_mlkemcustom_dec(struct kex *kex,[m
 [m
 	u_char aes_key[32];[m
 [m
[32m+[m	[32mlog_benchmark(kex, "decapsulation start");[m[41m[m
[32m+[m[41m[m
 	*shared_secretp = NULL;[m
 [m
 	need = pqcrystals_kyber768_CIPHERTEXTBYTES + AES_LEN;[m
[36m@@ -209,7 +256,8 @@[m [mint kex_kem_mlkemcustom_dec(struct kex *kex,[m
 	if ((r = sshbuf_reserve(buf, pqcrystals_kyber768_BYTES, &kem_key)) != 0)[m
 		goto out;[m
 [m
[31m-	ok = pqcrystals_kyber768_ref_dec(kem_key, ciphertext, kex->mlkem768_client_key);[m
[32m+[m	[32m// ok = pqcrystals_kyber768_ref_dec(kem_key, ciphertext, kex->mlkem768_client_key);[m[41m[m
[32m+[m	[32mok = pqcrystals_kyber768_avx2_dec(kem_key, ciphertext, kex->mlkem768_client_key);[m[41m[m
 	if (ok != 0)[m
 	{[m
 		r = SSH_ERR_SIGNATURE_INVALID;[m
[36m@@ -254,6 +302,7 @@[m [mint kex_kem_mlkemcustom_dec(struct kex *kex,[m
 	buf = NULL;[m
 [m
 out:[m
[32m+[m[32m    log_benchmark(kex, "decapsulation end");[m[41m[m
     explicit_bzero(aes_key, sizeof(aes_key));[m
 	explicit_bzero(hash, sizeof(hash));[m
 	if (pt)[m
[1mdiff --git a/liboqs b/liboqs[m
[1m--- a/liboqs[m
[1m+++ b/liboqs[m
[36m@@ -1 +1 @@[m
[31m-Subproject commit 4a0ae6525fbaae4b7dab2a998e6dc192fc4ce661[m
[32m+[m[32mSubproject commit 4a0ae6525fbaae4b7dab2a998e6dc192fc4ce661-dirty[m
