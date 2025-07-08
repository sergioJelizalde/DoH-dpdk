/*
 * sha256_neon_dpdk.c
 *
 * Hardware-accelerated SHA-256 with NEON.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <rte_eal.h>
#include <rte_cycles.h>
#include <arm_neon.h>
#include <openssl/evp.h>

/* SHA-256 constants K[0..63] (Fractional parts of the cube roots of the first 64 prime numbers) */
static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/* Load 4 big-endian 32-bit words from p into a NEON register */
static inline uint32x4_t load_be_q(const uint8_t *p) {
    return vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p)));
}

/* One 4-word round: abcd, efgh = SHA256_round4(abcd, efgh, sched + K[round..round+3]) */
static inline void sha256_neon_round4(
    uint32x4_t *abcd, uint32x4_t *efgh,
    uint32x4_t sched, unsigned round_idx)
{
    uint32x4_t k = vld1q_u32(&K[round_idx]);
    uint32x4_t round_in = vaddq_u32(sched, k);
    uint32x4_t abcd_new = vsha256hq_u32(*abcd, *efgh, round_in);
    uint32x4_t efgh_new = vsha256h2q_u32(*efgh, *abcd, round_in);
    *abcd = abcd_new;
    *efgh = efgh_new;
}

/* Compute the next 4 schedule words W[t..t+3] given W[t–16..t–13]=m4, W[t–15..t–12]=m3,
   W[t–7..t–4]=m2, W[t–2..t+1]=m1. */
static inline uint32x4_t sha256_neon_sched(
    uint32x4_t m4, uint32x4_t m3, uint32x4_t m2, uint32x4_t m1)
{
    return vsha256su1q_u32(
        vsha256su0q_u32(m4, m3),
        m2,
        m1
    );
}

bool sha256_compare_neon(const uint8_t hash1[32], const uint8_t hash2[32]) {
    uint8x16_t h1_part1 = vld1q_u8(hash1);        // load first 16 bytes
    uint8x16_t h1_part2 = vld1q_u8(hash1 + 16);   // load next 16 bytes

    uint8x16_t h2_part1 = vld1q_u8(hash2);
    uint8x16_t h2_part2 = vld1q_u8(hash2 + 16);

    uint8x16_t cmp1 = veorq_u8(h1_part1, h2_part1);  // XOR: 0 if equal
    uint8x16_t cmp2 = veorq_u8(h1_part2, h2_part2);

    // Use vmaxvq_u8 to OR-reduce the result to see if anything is non-zero
    return (vmaxvq_u8(cmp1) | vmaxvq_u8(cmp2)) == 0;
}

/* Process one 512-bit block pointed to by `block` */
static void sha256_neon_block(uint32x4_t *h0h1, uint32x4_t *h2h3, const uint8_t block[64]) {
    uint32x4_t a = *h0h1, e = *h2h3;
    uint32x4_t W0 = load_be_q(block +    0);  /* W0..W3  = M0..M3 */
    sha256_neon_round4(&a, &e, W0,   0);
    uint32x4_t W1 = load_be_q(block +   16);  /* W4..W7  = M4..M7 */
    sha256_neon_round4(&a, &e, W1,   4);
    uint32x4_t W2 = load_be_q(block +   32);  /* W8..W11 = M8..M11 */
    sha256_neon_round4(&a, &e, W2,   8);
    uint32x4_t W3 = load_be_q(block +   48);  /* W12..W15= M12..M15 */
    sha256_neon_round4(&a, &e, W3,  12);

    /* W16..W63, 4 words at a time */
    uint32x4_t S0, S1, S2, S3;

    /* W16..W19 */
    S0 = sha256_neon_sched(W0, W1, W2, W3);
    sha256_neon_round4(&a, &e, S0, 16);

    /* W20..W23 */
    S1 = sha256_neon_sched(W1, W2, W3, S0);
    sha256_neon_round4(&a, &e, S1, 20);

    /* W24..W27 */
    S2 = sha256_neon_sched(W2, W3, S0, S1);
    sha256_neon_round4(&a, &e, S2, 24);

    /* W28..W31 */
    S3 = sha256_neon_sched(W3, S0, S1, S2);
    sha256_neon_round4(&a, &e, S3, 28);

    /* W32..W35 */
    W0 = sha256_neon_sched(S0, S1, S2, S3);
    sha256_neon_round4(&a, &e, W0, 32);

    /* W36..W39 */
    W1 = sha256_neon_sched(S1, S2, S3, W0);
    sha256_neon_round4(&a, &e, W1, 36);

    /* W40..W43 */
    W2 = sha256_neon_sched(S2, S3, W0, W1);
    sha256_neon_round4(&a, &e, W2, 40);

    /* W44..W47 */
    W3 = sha256_neon_sched(S3, W0, W1, W2);
    sha256_neon_round4(&a, &e, W3, 44);

    /* W48..W51 */
    S0 = sha256_neon_sched(W0, W1, W2, W3);
    sha256_neon_round4(&a, &e, S0, 48);

    /* W52..W55 */
    S1 = sha256_neon_sched(W1, W2, W3, S0);
    sha256_neon_round4(&a, &e, S1, 52);

    /* W56..W59 */
    S2 = sha256_neon_sched(W2, W3, S0, S1);
    sha256_neon_round4(&a, &e, S2, 56);

    /* W60..W63 */
    S3 = sha256_neon_sched(W3, S0, S1, S2);
    sha256_neon_round4(&a, &e, S3, 60);

    /* Add back to state */
    *h0h1 = vaddq_u32(*h0h1, a);
    *h2h3 = vaddq_u32(*h2h3, e);
}

/* Compute SHA-256 of exactly one 512-bit block (padded externally). */
static void sha256_neon(const uint8_t block[64], uint8_t digest[32]) {
    /* Initial hash values: H0..H7 */
    uint32x4_t h0h1 = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a };
    uint32x4_t h2h3 = { 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

    /* Process the single block */
    sha256_neon_block(&h0h1, &h2h3, block);

    /* Store big-endian H0..H7 into digest[0..31] */
    vst1q_u8(digest,      vrev32q_u8(vreinterpretq_u8_u32(h0h1)));
    vst1q_u8(digest + 16, vrev32q_u8(vreinterpretq_u8_u32(h2h3)));
}

static void sha256_openssl_oneshot(const uint8_t *data, size_t len, uint8_t digest[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int out_len = 0;

    if (!ctx) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        return;
    }

    if (EVP_Digest(data, len, digest, &out_len, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "EVP_Digest one-shot failed\n");
    }

    EVP_MD_CTX_free(ctx);
}

int main(int argc, char **argv) {
    if (rte_eal_init(argc, argv) < 0) {
        fprintf(stderr, "EAL init failed\n");
        return 1;
    }

    /* Message to hash: 34 bytes */
    const char msg[] = "771,4865-4866-4867,0-11-10,23-24,0";
    size_t len = strlen(msg);

    /* Build one 512-bit block: message || 0x80 || zero pad || 64-bit length */
    uint8_t block[64] = {0};
    memcpy(block, msg, len);
    block[len] = 0x80;
    uint64_t bit_len = len * 8;
    /* Append length in big-endian at bytes 56..63 */
    block[56] = (bit_len >> 56) & 0xFF;
    block[57] = (bit_len >> 48) & 0xFF;
    block[58] = (bit_len >> 40) & 0xFF;
    block[59] = (bit_len >> 32) & 0xFF;
    block[60] = (bit_len >> 24) & 0xFF;
    block[61] = (bit_len >> 16) & 0xFF;
    block[62] = (bit_len >> 8)  & 0xFF;
    block[63] =  bit_len        & 0xFF;

    /* For debugging: print length and input bytes */
    printf("strlen(msg): %zu\n", len);
    for (size_t i = 0; i < len; i++) {
        printf("%02zu: '%c' (0x%02x)\n", i, msg[i], (unsigned char)msg[i]);
    }

    printf("Input hex: ");
    for (int i = 0; i < 64; i++) {
        printf("%02x", block[i]);
    }
    printf("\n");

    /* Time the NEON SHA-256 */
    uint8_t digest[32];
    uint64_t t0 = rte_rdtsc();
    sha256_neon(block, digest);
    uint64_t t1 = rte_rdtsc();

    /* Print SHA-256 digest */
    printf("SHA-256 digest: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    /* Compute elapsed time in nanoseconds */
    double hz = rte_get_tsc_hz();
    printf("Latency: %.2f ns (%lu cycles)\n", (t1 - t0) * 1e9 / hz, (unsigned long)(t1 - t0));

        // Time the OpenSSL SHA-256
    uint8_t digest_openssl[32];
    uint64_t t2 = rte_rdtsc();
    sha256_openssl_oneshot((const uint8_t *)msg, len, digest_openssl);
    uint64_t t3 = rte_rdtsc();

    printf("OpenSSL SHA-256 digest: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", digest_openssl[i]);
    }
    printf("\n");

    printf("OpenSSL Latency: %.2f ns (%lu cycles)\n", (t3 - t2) * 1e9 / hz, (unsigned long)(t3 - t2));

    // Compare digests (should match if padded message matches exactly)
    bool match = sha256_compare_neon(digest, digest_openssl);
    printf("Hashes match? %s\n", match ? "YES" : "NO");


    return 0;
}
