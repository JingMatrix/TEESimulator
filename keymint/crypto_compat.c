// Compatibility shims for BoringSSL entry points the KeyMint TA references but
// the host keystore2 process's platform libcrypto does not export.
//
// The TA links against a stub libcrypto.so and expects the host's real BoringSSL
// to supply the symbols at runtime. That holds for everything except the legacy
// EVP_CipherFinal alias: modern BoringSSL keeps only EVP_CipherFinal_ex in its
// export map, so resolving EVP_CipherFinal against the host fails and the whole
// dlopen aborts (see issue #202 on Android 12).
//
// Upstream BoringSSL defines EVP_CipherFinal as nothing more than a forwarder to
// EVP_CipherFinal_ex, so we reproduce that here and let the linker satisfy the
// TA's reference locally. The definition is hidden and the version script keeps
// it local, so it is never exported nor interposed by the host. Only the modern
// EVP_CipherFinal_ex is left to resolve at runtime, which the host does export.

#include <stdint.h>

typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

extern int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, uint8_t *out, int *out_len);

__attribute__((visibility("hidden"))) int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, uint8_t *out, int *out_len) {
    return EVP_CipherFinal_ex(ctx, out, out_len);
}
