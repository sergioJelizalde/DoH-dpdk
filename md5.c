#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <rte_eal.h>
#include <rte_cycles.h>
#include <openssl/evp.h>

#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

static void md5_c_multi(const uint8_t *msg, size_t len, uint8_t digest[16]) {
    uint32_t a0 = 0x67452301;   // A
    uint32_t b0 = 0xefcdab89;   // B
    uint32_t c0 = 0x98badcfe;   // C
    uint32_t d0 = 0x10325476;   // D

    // Constants for MD5
    static const uint32_t r[] = {
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
        5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
    };

    static const uint32_t k[] = {
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
    };

    uint64_t bit_len = (uint64_t)len * 8;
    size_t new_len = len + 1;
    while ((new_len % 64) != 56) new_len++;
    uint8_t *msg_padded = calloc(new_len + 8, 1);
    memcpy(msg_padded, msg, len);
    msg_padded[len] = 0x80;

    for (int i = 0; i < 8; i++)
        msg_padded[new_len + i] = (bit_len >> (8 * i)) & 0xff;

    for (size_t offset = 0; offset < new_len; offset += 64) {
        uint32_t *w = (uint32_t *)(msg_padded + offset);
        uint32_t a = a0, b = b0, c = c0, d = d0;

        for (int i = 0; i < 64; i++) {
            uint32_t f, g;
            if (i < 16) {
                f = (b & c) | ((~b) & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | ((~d) & c);
                g = (5 * i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3 * i + 5) % 16;
            } else {
                f = c ^ (b | (~d));
                g = (7 * i) % 16;
            }
            uint32_t tmp = d;
            d = c;
            c = b;
            b = b + LEFTROTATE(a + f + k[i] + w[g], r[i]);
            a = tmp;
        }

        a0 += a; b0 += b; c0 += c; d0 += d;
    }

    free(msg_padded);

    memcpy(digest +  0, &a0, 4);
    memcpy(digest +  4, &b0, 4);
    memcpy(digest +  8, &c0, 4);
    memcpy(digest + 12, &d0, 4);
}

bool md5_compare(const uint8_t h1[16], const uint8_t h2[16]) {
    return memcmp(h1, h2, 16) == 0;
}

static void md5_openssl_oneshot(const uint8_t *data, size_t len, uint8_t digest[16]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int out_len = 0;
    if (!ctx) return;
    EVP_Digest(data, len, digest, &out_len, EVP_md5(), NULL);
    EVP_MD_CTX_free(ctx);
}

int main(int argc, char **argv) {
    if (rte_eal_init(argc, argv) < 0) {
        fprintf(stderr, "EAL init failed\n");
        return 1;
    }

       /* Message to hash */
    const char msg[] =
        "771,49192-49191-49172-49171-159-158-57-51-157-156-61-60-53-47-49196-49195-49188-49187-49162-49161-106-64-56-50-10-19,0-5-10-11-13-35-23-65281,23-24,0";

    size_t len = strlen(msg);
    printf("strlen(msg): %zu\n", len);

    uint8_t digest_c[16];
    uint64_t t0 = rte_rdtsc();
    md5_c_multi((const uint8_t *)msg, len, digest_c);
    uint64_t t1 = rte_rdtsc();

    double hz = rte_get_tsc_hz();
    printf("MD5 C digest: ");
    for (int i = 0; i < 16; i++) printf("%02x", digest_c[i]);
    printf("\nLatency: %.2f ns (%lu cycles)\n", (t1 - t0) * 1e9 / hz, t1 - t0);

    uint8_t digest_openssl[16];
    uint64_t t2 = rte_rdtsc();
    md5_openssl_oneshot((const uint8_t *)msg, len, digest_openssl);
    uint64_t t3 = rte_rdtsc();

    printf("MD5 OpenSSL digest: ");
    for (int i = 0; i < 16; i++) printf("%02x", digest_openssl[i]);
    printf("\nLatency: %.2f ns (%lu cycles)\n", (t3 - t2) * 1e9 / hz, t3 - t2);

    printf("Hashes match? %s\n", md5_compare(digest_c, digest_openssl) ? "YES" : "NO");

    return 0;
}
