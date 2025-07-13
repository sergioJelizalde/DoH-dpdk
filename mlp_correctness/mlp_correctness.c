#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <arm_neon.h>
#include <rte_eal.h>
#include <rte_cycles.h>

// -----------------------------------------------------------------------------
//  Model + feature‐stats headers (auto‐generated)
#include "feature_stats.h"    // defines FEATURE_MEAN[NUM_FEATURES], FEATURE_STD[…]
#include "mlp_8.h"            // pick one mlp_<spec>.h per run
// #include "mlp_32.h"
// #include "mlp_64_32.h"
// #include "mlp_128_64_32.h"
// #include "mlp_256_128_64_32.h"

// -----------------------------------------------------------------------
#define ITERATIONS      5000
#define MIN_PKT_SIZE    64.0f
#define MAX_PKT_SIZE    9000.0f
#define MAX_LEN_RANGE   (MAX_PKT_SIZE - MIN_PKT_SIZE)

// helper: uniform [0,1)
static inline float randomf(void) {
    return (float)rand() / (float)RAND_MAX;
}

// piecewise‐linear sigmoid for output layer
static inline float fast_sigmoid_scalar(float x) {
    if (x <= -4.0f)      return 0.0f;
    else if (x <= -2.0f) return 0.0625f * x + 0.25f;
    else if (x <=  0.0f) return 0.125f * x + 0.5f;
    else if (x <=  2.0f) return -0.125f * x + 0.5f;
    else if (x <=  4.0f) return -0.0625f * x + 0.75f;
    else                 return 1.0f;
}

// --------------------------------------------------------------------------------
// Scalar MLP (arbitrary layers)
static int predict_mlp_c_general(const float *in_features,
                                 float *buf_a, float *buf_b) {
    float *in_buf  = buf_a, *out_buf = buf_b;

    memcpy(in_buf, in_features, LAYER_SIZES[0] * sizeof(float));

    for (int L = 0; L < NUM_LAYERS; L++) {
        int size_in   = LAYER_SIZES[L];
        int size_out  = LAYER_SIZES[L+1];
        int is_output = (L == NUM_LAYERS - 1);

        const float *W = WEIGHTS[L];
        const float *B = BIASES[L];

        for (int j = 0; j < size_out; j++) {
            float acc = B[j];
            for (int k = 0; k < size_in; k++)
                acc += W[k*size_out + j] * in_buf[k];
            out_buf[j] = is_output
                       ? fast_sigmoid_scalar(acc)
                       : (acc > 0.0f ? acc : 0.0f);
        }

        // swap buffers
        float *tmp = in_buf; in_buf = out_buf; out_buf = tmp;
    }

    // argmax
    int final_size = LAYER_SIZES[NUM_LAYERS], best = 0;
    float best_v = in_buf[0];
    for (int i = 1; i < final_size; i++) {
        if (in_buf[i] > best_v) {
            best_v = in_buf[i];
            best   = i;
        }
    }
    float score = in_buf[0];
    return (score > 0.5f) ? 1 : 0;
}

// -------------------------------------------------------------------------
// NEON‐vectorized layer
static void layer_forward_neon(const float *W, const float *B,
                               const float *in, float *out,
                               int size_in, int size_out,
                               int is_output) {
    int j = 0;
    for (; j + 4 <= size_out; j += 4) {
        float32x4_t acc = vld1q_f32(&B[j]);
        for (int k = 0; k < size_in; k++) {
            acc = vfmaq_f32(acc,
                            vdupq_n_f32(in[k]),
                            vld1q_f32(&W[k*size_out + j]));
        }
        if (!is_output)  acc = vmaxq_f32(acc, vdupq_n_f32(0.0f));
        vst1q_f32(&out[j], acc);
    }
    // tail scalar in case the model does not align to multiple of 4
    for (; j < size_out; j++) {
        float a = B[j];
        for (int k = 0; k < size_in; k++)
            a += W[k*size_out + j] * in[k];
        out[j] = is_output ? a : (a > 0.0f ? a : 0.0f);
    }
    if (is_output) {
        for (int i = 0; i < size_out; i++)
            out[i] = fast_sigmoid_scalar(out[i]);
    }
}

// NEON MLP over arbitrary layers
static int predict_mlp_neon_general(const float *in_features,
                                    float *buf_a, float *buf_b) {
    float *in_buf  = buf_a, *out_buf = buf_b;
    memcpy(in_buf, in_features, LAYER_SIZES[0] * sizeof(float));

    for (int L = 0; L < NUM_LAYERS; L++) {
        layer_forward_neon(
          WEIGHTS[L], BIASES[L],
          in_buf, out_buf,
          LAYER_SIZES[L],
          LAYER_SIZES[L+1],
          (L == NUM_LAYERS - 1)
        );
        float *tmp = in_buf; in_buf = out_buf; out_buf = tmp;
    }

    // argmax
    int final_size = LAYER_SIZES[NUM_LAYERS], best = 0;
    float best_v = in_buf[0];
    for (int i = 1; i < final_size; i++) {
        if (in_buf[i] > best_v) {
            best_v = in_buf[i];
            best   = i;
        }
    }
    float score = in_buf[0];
    return (score > 0.5f) ? 1 : 0;
}

// -----------------------------------------------------------------------------
// main program
int main(int argc, char **argv) {
    if (rte_eal_init(argc, argv) < 0)
        rte_exit(EXIT_FAILURE, "EAL init failed\n");

    // find maximum neurons 
    int max_neurons = 0;
    for (int i = 0; i <= NUM_LAYERS; i++)
        if (LAYER_SIZES[i] > max_neurons)
            max_neurons = LAYER_SIZES[i];

    // allocate aligned buffers for neon 16bytes (128bits)
    float *scratch_a, *scratch_b, *raw_input, *input;
    if (posix_memalign((void**)&scratch_a, 16, max_neurons * sizeof(float)) ||
        posix_memalign((void**)&scratch_b, 16, max_neurons * sizeof(float)) ||
        posix_memalign((void**)&raw_input, 16, LAYER_SIZES[0] * sizeof(float)) ||
        posix_memalign((void**)&input,     16, LAYER_SIZES[0] * sizeof(float)))
    {
        rte_exit(EXIT_FAILURE, "posix_memalign failed\n");
    }

    FILE *out = fopen("latencies.csv", "w");
    if (!out) rte_exit(EXIT_FAILURE, "Cannot open latencies.csv\n");
    fprintf(out, "iter,latency_c_ns,latency_neon_ns\n");

    srand((unsigned)rte_get_tsc_cycles());
    const uint64_t hz = rte_get_tsc_hz();

    int matches = 0, mismatches = 0;
    int cnt_c0      = 0, cnt_c1      = 0;  // scalar output counts
    int cnt_n0      = 0, cnt_n1      = 0;  // NEON   output counts

    for (int it = 0; it < ITERATIONS; it++) {
        //  generate raw features
        raw_input[0] = MIN_PKT_SIZE + randomf() * MAX_LEN_RANGE;
        for (int k = 1; k < LAYER_SIZES[0]; k++)
            raw_input[k] = randomf();

        //  z-score normalization (from StandardScaler in python)
        for (int k = 0; k < LAYER_SIZES[0]; k++)
            input[k] = (raw_input[k] - FEATURE_MEAN[k]) / FEATURE_STD[k];

        // benchmark scalar
        uint64_t t0 = rte_rdtsc_precise();
        int cls_c = predict_mlp_c_general(input, scratch_a, scratch_b);
        uint64_t t1 = rte_rdtsc_precise();
        double ns_c = (double)(t1 - t0) * 1e9 / hz;
        if (cls_c == 0) cnt_c0++;
            else            cnt_c1++;

        // benchmark NEON
        t0 = rte_rdtsc_precise();
        int cls_n = predict_mlp_neon_general(input, scratch_a, scratch_b);
        t1 = rte_rdtsc_precise();
        double ns_n = (double)(t1 - t0) * 1e9 / hz;
        if (cls_n == 0) cnt_n0++;
            else            cnt_n1++;

        if (cls_c == cls_n)       matches++;
            else                      mismatches++;
    
        fprintf(out, "%d,%.2f,%.2f\n", it, ns_c, ns_n);
    }
    // summary
    printf("Scalar:   class 0 = %d, class 1 = %d\n", cnt_c0, cnt_c1);
    printf("NEON:     class 0 = %d, class 1 = %d\n", cnt_n0, cnt_n1);
    printf("Agreement: %d/%d matches (%d mismatches)\n", matches, ITERATIONS, mismatches);
    
    fclose(out);
    free(scratch_a);
    free(scratch_b);
    free(raw_input);
    free(input);
    return 0;
}
