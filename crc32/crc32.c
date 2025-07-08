#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <rte_eal.h>
#include <rte_cycles.h>
#include <arm_acle.h>   // For __crc32* intrinsics 
#include <zlib.h>       // For crc32() software

// Hardware-accelerated CRC32 using ARMv8 CRC32 intrinsics.
// 'seed' is the initial CRC state. 
uint32_t crc32_hw(const uint8_t *buf, size_t len, uint32_t seed) {
    uint32_t crc = ~seed;  // invert initial seed
    // Process 8 bytes at a time
    while (len >= 8) {
        uint64_t v;
        memcpy(&v, buf, sizeof(v));
        crc = __crc32d(crc, v);
        buf += 8; len -= 8;
    }
    // Process 4 bytes
    while (len >= 4) {
        uint32_t v;
        memcpy(&v, buf, sizeof(v));
        crc = __crc32w(crc, v);
        buf += 4; len -= 4;
    }
    // Process 2 bytes
    while (len >= 2) {
        uint16_t v;
        memcpy(&v, buf, sizeof(v));
        crc = __crc32h(crc, v);
        buf += 2; len -= 2;
    }
    // Process remaining bytes
    while (len--) {
        crc = __crc32b(crc, *buf++);
    }
    return ~crc;  // invert back
}

// Software CRC32 using zlib, seeded with 'seed'
uint32_t crc32_sw(const uint8_t *buf, size_t len, uint32_t seed) {
    return crc32(seed, buf, len);
}

int main(int argc, char **argv) {
    // 1) Initialize DPDK EAL
    if (rte_eal_init(argc, argv) < 0) {
        fprintf(stderr, "Error: EAL initialization failed\n");
        return EXIT_FAILURE;
    }

    // 2) Hard-coded list of hex seeds to try
    const uint32_t seeds[] = {
        0x00000000,  
        0xDEADBEEF,  
        0xCAFEBABE,  
        0xFEEDFACE,  
        0x1234ABCD   
    };
    const int n_seeds = sizeof(seeds) / sizeof(*seeds);

    // 3) Test message
    const char msg[] =
        "771,49192-49191-49172-49171-159-158-57-51-157-156-61-60-53-47-"
        "49196-49195-49188-49187-49162-49161-106-64-56-50-10-19,"
        "0-5-10-11-13-35-23-65281,23-24,0";
    const size_t len = strlen(msg);

    printf("Message length: %zu bytes\n\n", len);

    // 4) Timestamp frequency
    const double hz = rte_get_tsc_hz();

    // 5) Loop over each seed
    for (int i = 0; i < n_seeds; i++) {
        uint32_t seed = seeds[i];
        printf("=== Seed %d: 0x%08x ===\n", i + 1, seed);

        // Hardware CRC32
        uint64_t hw_t0 = rte_rdtsc();
        uint32_t crc_h = crc32_hw((const uint8_t *)msg, len, seed);
        uint64_t hw_t1 = rte_rdtsc();

        // Software CRC32
        uint64_t sw_t0 = rte_rdtsc();
        uint32_t crc_s = crc32_sw((const uint8_t *)msg, len, seed);
        uint64_t sw_t1 = rte_rdtsc();

        // Print results
        printf(" Hardware CRC32:  0x%08x  (%.2f ns, %lu cycles)\n",
               crc_h,
               (hw_t1 - hw_t0) * 1e9 / hz,
               (unsigned long)(hw_t1 - hw_t0));
        printf(" Software CRC32:  0x%08x  (%.2f ns, %lu cycles)\n",
               crc_s,
               (sw_t1 - sw_t0) * 1e9 / hz,
               (unsigned long)(sw_t1 - sw_t0));
        printf(" Match?           %s\n\n",
               (crc_h == crc_s) ? "YES" : "NO");
    }

    return EXIT_SUCCESS;
}
