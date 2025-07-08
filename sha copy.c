/*
 * sha256_neon_dpdk_multi.c
 *
 * Hardware‐accelerated SHA‐256 with NEON, multi‐block support.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <rte_eal.h>
#include <rte_cycles.h>
#include <arm_neon.h>
#include <openssl/evp.h>

/* SHA-256 constants K[0..63] */
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
    // vld1q_u8 loads 16 bytes, then vrev32q_u8 swaps each 32-bit word from BE→LE ordering
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

/* Compute the next 4 schedule words W[t..t+3] */
static inline uint32x4_t sha256_neon_sched(
    uint32x4_t m4, uint32x4_t m3, uint32x4_t m2, uint32x4_t m1)
{
    // vsha256su0 and vsha256su1 implement the σ0, σ1 expansions
    return vsha256su1q_u32(
        vsha256su0q_u32(m4, m3),
        m2,
        m1
    );
}

/* Process one 512-bit block pointed to by `block` (updates the state in‐place) */
static void sha256_neon_block(uint32x4_t *h0h1, uint32x4_t *h2h3, const uint8_t block[64]) {
    // a, e hold (a,b,c,d) and (e,f,g,h) in 4‐word NEON vectors
    uint32x4_t a = *h0h1, e = *h2h3;

    // Load the first 16 words (W0..W15) directly from the 64‐byte chunk
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

    /* Add back into the running hash state */
    *h0h1 = vaddq_u32(*h0h1, a);
    *h2h3 = vaddq_u32(*h2h3, e);
}

/* Compare two 32‐byte digests in NEON (returns true if equal). */
bool sha256_compare_neon(const uint8_t hash1[32], const uint8_t hash2[32]) {
    uint8x16_t h1_part1 = vld1q_u8(hash1);
    uint8x16_t h1_part2 = vld1q_u8(hash1 + 16);
    uint8x16_t h2_part1 = vld1q_u8(hash2);
    uint8x16_t h2_part2 = vld1q_u8(hash2 + 16);

    uint8x16_t cmp1 = veorq_u8(h1_part1, h2_part1);
    uint8x16_t cmp2 = veorq_u8(h1_part2, h2_part2);

    return (vmaxvq_u8(cmp1) | vmaxvq_u8(cmp2)) == 0;
}

/*
 * Multi‐block SHA-256 with NEON:
 *   - Initializes H0..H7
 *   - Processes every 64‐byte block via sha256_neon_block
 *   - Builds final padding block(s)
 *   - Outputs 32‐byte digest in big‐endian
 */
static void sha256_neon_multi(const uint8_t *data, size_t len, uint8_t digest[32]) {
    /* 1) Initialize state: H0..H7 */
    uint32x4_t h0h1 = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a };
    uint32x4_t h2h3 = { 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

    /* 2) Process all full 64‐byte blocks */
    size_t num_full_blocks = len / 64;
    for (size_t i = 0; i < num_full_blocks; i++) {
        const uint8_t *blk_ptr = data + (i * 64);
        sha256_neon_block(&h0h1, &h2h3, blk_ptr);
    }

    /* 3) Handle the final partial block + padding */
    size_t rem = len % 64;
    uint8_t final_block[64];
    memset(final_block, 0, 64);

    /* Copy the remaining bytes */
    if (rem > 0) {
        memcpy(final_block, data + (num_full_blocks * 64), rem);
    }
    /* Append 0x80 just after the message bytes */
    final_block[rem] = 0x80;

    /* If there is not enough room in this block for the 64‐bit length,
       we’ll need two calls to sha256_neon_block:
       - 1st: this partially‐filled block (with 0x80 and zeros)
       - 2nd: an all‐zero block except the last 8 bytes = bit‐length
    */
    uint64_t bit_len = (uint64_t)len * 8;

    if (rem + 1 + 8 <= 64) {
        /* We can fit <0x80 + length> in one 64‐byte block: put bit‐len at bytes 56..63 */
        uint8_t *len_place = final_block + 56;
        len_place[0] = (bit_len >> 56) & 0xFF;
        len_place[1] = (bit_len >> 48) & 0xFF;
        len_place[2] = (bit_len >> 40) & 0xFF;
        len_place[3] = (bit_len >> 32) & 0xFF;
        len_place[4] = (bit_len >> 24) & 0xFF;
        len_place[5] = (bit_len >> 16) & 0xFF;
        len_place[6] = (bit_len >>  8) & 0xFF;
        len_place[7] = (bit_len      ) & 0xFF;

        /* Process this final padded block */
        sha256_neon_block(&h0h1, &h2h3, final_block);

    } else {
        /* rem + 1 + 8 > 64, so:
         * - process the “0x80 + zeros” block now (length not appended here)
         * - then process a second block that is all zeros except for the 64‐bit length at the end.
         */
        // First block: we already have final_block with remainder + 0x80 + padding zeros
        sha256_neon_block(&h0h1, &h2h3, final_block);

        // Build a completely zeroed block, then put bit_len at bytes 56..63
        uint8_t second_block[64];
        memset(second_block, 0, 64);
        uint8_t *len_place2 = second_block + 56;
        len_place2[0] = (bit_len >> 56) & 0xFF;
        len_place2[1] = (bit_len >> 48) & 0xFF;
        len_place2[2] = (bit_len >> 40) & 0xFF;
        len_place2[3] = (bit_len >> 32) & 0xFF;
        len_place2[4] = (bit_len >> 24) & 0xFF;
        len_place2[5] = (bit_len >> 16) & 0xFF;
        len_place2[6] = (bit_len >>  8) & 0xFF;
        len_place2[7] = (bit_len      ) & 0xFF;

        sha256_neon_block(&h0h1, &h2h3, second_block);
    }

    /* 4) Emit big‐endian state into digest[] */
    vst1q_u8(digest,      vrev32q_u8(vreinterpretq_u8_u32(h0h1)));
    vst1q_u8(digest + 16, vrev32q_u8(vreinterpretq_u8_u32(h2h3)));
}

/* “One‐shot” OpenSSL fallback for comparison */
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

    /* Message to hash */
    const char msg[] =
        "771,4865-4866-4867-49195-49199-49196-49200-"
        "52393-52392-49171-49172-156-157-47-53-"
        "10,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0";
    size_t len = strlen(msg);

    printf("strlen(msg): %zu\n", len);

    /* Time the NEON multi-block SHA‐256 */
    uint8_t digest_neon[32];
    uint64_t t0 = rte_rdtsc();
    sha256_neon_multi((const uint8_t *)msg, len, digest_neon);
    uint64_t t1 = rte_rdtsc();

    printf("NEON SHA-256 digest: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", digest_neon[i]);
    }
    printf("\n");
    double hz = rte_get_tsc_hz();
    printf("NEON Latency: %.2f ns (%lu cycles)\n",
           (t1 - t0) * 1e9 / hz, (unsigned long)(t1 - t0));

    /* Time the OpenSSL SHA‐256 for reference */
    uint8_t digest_openssl[32];
    uint64_t t2 = rte_rdtsc();
    sha256_openssl_oneshot((const uint8_t *)msg, len, digest_openssl);
    uint64_t t3 = rte_rdtsc();

    printf("OpenSSL SHA-256 digest: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", digest_openssl[i]);
    }
    printf("\n");
    printf("OpenSSL Latency: %.2f ns (%lu cycles)\n",
           (t3 - t2) * 1e9 / hz, (unsigned long)(t3 - t2));

    /* Compare NEON vs OpenSSL */
    bool match = sha256_compare_neon(digest_neon, digest_openssl);
    printf("Hashes match? %s\n", match ? "YES" : "NO");

    return 0;
}
