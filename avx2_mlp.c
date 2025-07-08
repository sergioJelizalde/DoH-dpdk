#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <immintrin.h>
#include <rte_eal.h>
#include <rte_cycles.h>
//#include <rte_exit.h>
#include "mlp_model.h"

#define MAX_NEURONS 128
#define DEFAULT_ITERS 1000ULL

static inline float relu(float x) {
    return x > 0.0f ? x : 0.0f;
}

// Returns clock cycles and sets final output value (scalar)
static double run_mlp_scalar_cycles(const float *input, float *out_val) {
    static float buffer0[MAX_NEURONS];
    static float buffer1[MAX_NEURONS];
    const float *in = input;
    float *out = buffer0;
    uint64_t start = rte_rdtsc();

    for (int l = 0; l < NUM_LAYERS; ++l) {
        int in_dim  = LAYER_SIZES[l];
        int out_dim = LAYER_SIZES[l + 1];
        const float *W = WEIGHTS[l];
        const float *b = BIASES[l];

        for (int j = 0; j < out_dim; ++j) {
            float acc = b[j];
            const float *w_row = W + (size_t)j * in_dim;
            for (int i = 0; i < in_dim; ++i) {
                acc += w_row[i] * in[i];
            }
            out[j] = (l < NUM_LAYERS - 1) ? relu(acc) : acc;
        }
        in  = out;
        out = (out == buffer0) ? buffer1 : buffer0;
    }

    uint64_t end = rte_rdtsc();
    *out_val = in[0];  // final output
    return (double)(end - start);
}

// Returns clock cycles and sets final output value (AVX2)
static double run_mlp_avx2_cycles(const float *input, float *out_val) {
    static float hidden[MAX_NEURONS];
    const float *W0_ptr = W0;
    const float *b0     = B0;
    uint64_t start = rte_rdtsc();

    // Vectorized first layer
    __m256 in256 = _mm256_set_ps(input[3], input[2], input[1], input[0],
                                 input[3], input[2], input[1], input[0]);
    for (int j = 0; j < LAYER_SIZES[1]; j += 2) {
        __m256 w_vec = _mm256_load_ps(&W0_ptr[j * LAYER_SIZES[0]]);
        __m256 prod  = _mm256_mul_ps(w_vec, in256);
        __m128 lo = _mm256_castps256_ps128(prod);
        __m128 hi = _mm256_extractf128_ps(prod, 1);
        __m128 sum_lo = _mm_hadd_ps(lo, lo);
        sum_lo = _mm_hadd_ps(sum_lo, sum_lo);
        __m128 sum_hi = _mm_hadd_ps(hi, hi);
        sum_hi = _mm_hadd_ps(sum_hi, sum_hi);
        hidden[j]     = relu(_mm_cvtss_f32(sum_lo) + b0[j]);
        hidden[j + 1] = relu(_mm_cvtss_f32(sum_hi) + b0[j + 1]);
    }

    // Remaining layers scalar
    static float hidden2[4];
    const float *W1_ptr = W1;
    const float *b1     = B1;
    for (int j = 0; j < LAYER_SIZES[2]; ++j) {
        float acc = b1[j];
        const float *w_row = W1_ptr + (size_t)j * LAYER_SIZES[1];
        for (int i = 0; i < LAYER_SIZES[1]; ++i) {
            acc += w_row[i] * hidden[i];
        }
        hidden2[j] = (j < LAYER_SIZES[2]) ? relu(acc) : acc;
    }
    float acc = B2[0];
    for (int i = 0; i < LAYER_SIZES[2]; ++i) {
        acc += W2[i] * hidden2[i];
    }

    uint64_t end = rte_rdtsc();
    *out_val = acc;
    return (double)(end - start);
}

// Random float generator in [0, 1)
static inline float randomf(void) {
    return (float)rand() / (float)RAND_MAX;
}

int main(int argc, char **argv) {
    // Initialize EAL
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    argc -= ret;
    argv += ret;

    unsigned long long iters = (argc > 1) ? strtoull(argv[1], NULL, 0) : DEFAULT_ITERS;
    srand((unsigned)time(NULL));

    FILE *csv = fopen("latencies.csv", "w");
    if (!csv) {
        perror("fopen");
        return 1;
    }
    fprintf(csv, "iteration,scalar_ns,avx2_ns\n");

    double tsc_hz = (double)rte_get_tsc_hz();
    float input[LAYER_SIZES[0]];
    unsigned long long match_count = 0;

    for (unsigned long long n = 0; n < iters; ++n) {
        for (int i = 0; i < LAYER_SIZES[0]; ++i) {
            input[i] = randomf();
        }

        float out_scalar = 0.0f, out_avx = 0.0f;
        double sc_cycles = run_mlp_scalar_cycles(input, &out_scalar);
        double av_cycles = run_mlp_avx2_cycles(input, &out_avx);
        double sc_ns = sc_cycles / tsc_hz * 1e9;
        double av_ns = av_cycles / tsc_hz * 1e9;

        fprintf(csv, "%llu,%.2f,%.2f\n", n, sc_ns, av_ns);

        if (fabsf(out_scalar - out_avx) < 1e-4f)
            match_count++;
    }

    fclose(csv);
    printf("Matched outputs: %llu out of %llu iterations\n", match_count, iters);
    printf("Nanosecond latencies written to latencies.csv\n");
    return 0;
}
