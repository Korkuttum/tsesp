// Checks our NaCl box against libsodium's answers for a range of message
// lengths, with 32 bytes in the middle of that range because that is where
// NaCl's reserved keystream block ends.
#include <stdio.h>
#include <string.h>
#include "nacl_box.h"
#include "nacl_vectors.h"

static int fails = 0;

static void report(const char *what, size_t mlen,
                   const uint8_t *got, const uint8_t *want, size_t n) {
    size_t i;
    printf("  FAIL %s (mlen=%zu)\n       got  ", what, mlen);
    for (i = 0; i < n && i < 24; i++) printf("%02x", got[i]);
    printf("\n       want ");
    for (i = 0; i < n && i < 24; i++) printf("%02x", want[i]);
    printf("\n");
    fails++;
}

int main(void) {
    int i;
    uint8_t shared[32], sealed[256], opened[256];

    printf("NaCl box against libsodium (%d vectors)\n", nacl_vectors_count);

    for (i = 0; i < nacl_vectors_count; i++) {
        const nacl_vector *v = &nacl_vectors[i];

        if (nacl_box_beforenm(shared, v->pk_b, v->sk_a) != 0) {
            printf("  FAIL beforenm rejected a valid key pair (mlen=%zu)\n", v->mlen);
            fails++;
            continue;
        }
        if (memcmp(shared, v->shared, 32) != 0) {
            report("beforenm", v->mlen, shared, v->shared, 32);
            continue;
        }

        nacl_secretbox(sealed, v->msg, v->mlen, v->nonce, shared);
        if (memcmp(sealed, v->sealed, v->mlen + NACL_TAG_LEN) != 0) {
            report("secretbox", v->mlen, sealed, v->sealed, v->mlen + NACL_TAG_LEN);
            continue;
        }

        if (nacl_secretbox_open(opened, v->sealed, v->mlen + NACL_TAG_LEN,
                                v->nonce, shared) != 0) {
            printf("  FAIL open rejected a valid box (mlen=%zu)\n", v->mlen);
            fails++;
            continue;
        }
        if (v->mlen && memcmp(opened, v->msg, v->mlen) != 0) {
            report("open", v->mlen, opened, v->msg, v->mlen);
            continue;
        }

        // Flipping any byte of the tag or ciphertext must be caught.
        memcpy(sealed, v->sealed, v->mlen + NACL_TAG_LEN);
        sealed[v->mlen + NACL_TAG_LEN - 1] ^= 0x01;
        if (nacl_secretbox_open(opened, sealed, v->mlen + NACL_TAG_LEN,
                                v->nonce, shared) == 0) {
            printf("  FAIL open accepted a corrupted box (mlen=%zu)\n", v->mlen);
            fails++;
            continue;
        }

        printf("  ok   mlen=%-4zu beforenm, seal, open, tamper-reject\n", v->mlen);
    }

    // In-place decryption is what the packet path will actually do.
    {
        const nacl_vector *v = &nacl_vectors[nacl_vectors_count - 1];
        uint8_t buf[256];
        nacl_box_beforenm(shared, v->pk_b, v->sk_a);
        memcpy(buf, v->sealed, v->mlen + NACL_TAG_LEN);
        if (nacl_secretbox_open(buf + NACL_TAG_LEN, buf, v->mlen + NACL_TAG_LEN,
                                v->nonce, shared) != 0 ||
            memcmp(buf + NACL_TAG_LEN, v->msg, v->mlen) != 0) {
            printf("  FAIL in-place open\n");
            fails++;
        } else {
            printf("  ok   in-place open (out == in + 16)\n");
        }
    }

    printf("\n%s\n", fails ? "NACL TESTS FAILED" : "all NaCl box tests passed");
    return fails ? 1 : 0;
}
