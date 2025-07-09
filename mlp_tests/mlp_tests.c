/* SPDX-License-Identifier: BSD-3-Clause
 * Compare generalized scalar vs NEON-accelerated MLP inference latency
 * over ITERATIONS random input samples with packet-size feature in [64,9000],
 * using DPDK’s TSC.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <arm_neon.h>
#include <rte_eal.h>
#include <rte_cycles.h>

// models
#include "mlp_model_xs.h"
//#include "mlp_model_s.h"  
//#include "mlp_model_m.h"  
//#include "mlp_model_l.h"      

#define ITERATIONS      5000
#define MIN_PKT_SIZE    64.0f
#define MAX_PKT_SIZE    9000.0f
#define MAX_LEN_RANGE   (MAX_PKT_SIZE - MIN_PKT_SIZE)

// helper: uniform [0,1)
static inline float randomf(void) {
    return (float)rand() / (float)RAND_MAX;
}

// scalar sigmoid for output layer
static inline float fast_sigmoid_scalar(float x) {
    if (x <= -4.0f)      return 0.0f;
    else if (x <= -2.0f) return 0.0625f * x + 0.25f;
    else if (x <=  0.0f) return 0.125f * x + 0.5f;
    else if (x <=  2.0f) return -0.125f * x + 0.5f;
    else if (x <=  4.0f) return -0.0625f * x + 0.75f;
    else                 return 1.0f;
}

// Scalar (pure C) MLP over arbitrary layers
static int predict_mlp_c_general(const float *in_features,
                                 float *buf_a, float *buf_b) {
    float *in_buf  = buf_a;
    float *out_buf = buf_b;

    // copy inputs
    memcpy(in_buf, in_features, LAYER_SIZES[0] * sizeof(float));

    // forward through layers
    for (int L = 0; L < NUM_LAYERS; L++) {
        int size_in   = LAYER_SIZES[L];
        int size_out  = LAYER_SIZES[L+1];
        int is_output = (L == NUM_LAYERS - 1);

        const float *W = WEIGHTS[L];
        const float *B = BIASES[L];

        for (int j = 0; j < size_out; j++) {
            float acc = B[j];
            for (int k = 0; k < size_in; k++) {
                acc += W[k*size_out + j] * in_buf[k];
            }
            if (!is_output) {
                out_buf[j] = acc > 0.0f ? acc : 0.0f;
            } else {
                out_buf[j] = fast_sigmoid_scalar(acc);
            }
        }

        // swap in/out buffers
        float *tmp = in_buf; in_buf = out_buf; out_buf = tmp;
    }

    // in_buf holds final outputs
    int final_size = LAYER_SIZES[NUM_LAYERS];
    int best_idx = 0;
    float best_v = in_buf[0];
    for (int i = 1; i < final_size; i++) {
        if (in_buf[i] > best_v) {
            best_v   = in_buf[i];
            best_idx = i;
        }
    }
    return best_idx;
}

// NEON helper: process one layer
static void layer_forward_neon(const float *W, const float *B,
                               const float *in, float *out,
                               int size_in, int size_out,
                               int is_output_layer) {
    int j = 0;
    for (; j + 4 <= size_out; j += 4) {
        float32x4_t acc = vld1q_f32(&B[j]);
        for (int k = 0; k < size_in; k++) {
            float32x4_t w = vld1q_f32(&W[k*size_out + j]);
            float32x4_t x = vdupq_n_f32(in[k]);
            acc = vfmaq_f32(acc, x, w);
        }
        if (!is_output_layer) {
            acc = vmaxq_f32(acc, vdupq_n_f32(0.0f));
        }
        vst1q_f32(&out[j], acc);
    }
    for (; j < size_out; j++) {
        float a = B[j];
        for (int k = 0; k < size_in; k++) {
            a += W[k*size_out + j] * in[k];
        }
        if (!is_output_layer) {
            out[j] = a > 0.0f ? a : 0.0f;
        } else {
            out[j] = a;
        }
    }
    if (is_output_layer) {
        for (int i = 0; i < size_out; i++) {
            out[i] = fast_sigmoid_scalar(out[i]);
        }
    }
}

// NEON-accelerated general MLP
static int predict_mlp_neon_general(const float *in_features,
                                    float *buf_a, float *buf_b) {
    float *in_buf  = buf_a;
    float *out_buf = buf_b;

    memcpy(in_buf, in_features, LAYER_SIZES[0] * sizeof(float));

    for (int L = 0; L < NUM_LAYERS; L++) {
        int size_in   = LAYER_SIZES[L];
        int size_out  = LAYER_SIZES[L+1];
        int is_output = (L == NUM_LAYERS - 1);

        layer_forward_neon(
            WEIGHTS[L], BIASES[L],
            in_buf, out_buf,
            size_in, size_out,
            is_output
        );
        float *tmp = in_buf; in_buf = out_buf; out_buf = tmp;
    }

    int final_size = LAYER_SIZES[NUM_LAYERS];
    int best_idx = 0;
    float best_v = in_buf[0];
    for (int i = 1; i < final_size; i++) {
        if (in_buf[i] > best_v) {
            best_v   = in_buf[i];
            best_idx = i;
        }
    }
    return best_idx;
}

int main(int argc, char **argv) {
    if (rte_eal_init(argc, argv) < 0)
        rte_exit(EXIT_FAILURE, "EAL init failed\n");

    // compute max neurons
    int max_neurons = 0;
    for (int i = 0; i <= NUM_LAYERS; i++) {
        if (LAYER_SIZES[i] > max_neurons)
            max_neurons = LAYER_SIZES[i];
    }

    // allocate aligned buffers and check errors
    float *scratch_a, *scratch_b;
    int rc;
    rc = posix_memalign((void**)&scratch_a, 16, max_neurons * sizeof(float));
    if (rc) rte_exit(EXIT_FAILURE, "posix_memalign scratch_a failed: %s\n", strerror(rc));
    rc = posix_memalign((void**)&scratch_b, 16, max_neurons * sizeof(float));
    if (rc) rte_exit(EXIT_FAILURE, "posix_memalign scratch_b failed: %s\n", strerror(rc));

    int input_size = LAYER_SIZES[0];
    float *input = malloc(input_size * sizeof(float));

    FILE *out = fopen("latencies.csv", "w");
    if (!out) rte_exit(EXIT_FAILURE, "Cannot open latencies.csv\n");
    fprintf(out, "iter,latency_c_ns,latency_neon_ns\n");

    srand((unsigned)rte_get_tsc_cycles());
    uint64_t hz = rte_get_tsc_hz();

    for (int it = 0; it < ITERATIONS; it++) {
        // generate features: first is packet size in [64,9000], others uniform
        input[0] = MIN_PKT_SIZE + randomf() * MAX_LEN_RANGE;
        for (int k = 1; k < input_size; k++) {
            input[k] = randomf();
        }

        uint64_t t0 = rte_rdtsc_precise();
        predict_mlp_c_general(input, scratch_a, scratch_b);
        uint64_t t1 = rte_rdtsc_precise();
        double ns_c = (double)(t1 - t0) * 1e9 / hz;

        t0 = rte_rdtsc_precise();
        predict_mlp_neon_general(input, scratch_a, scratch_b);
        t1 = rte_rdtsc_precise();
        double ns_n = (double)(t1 - t0) * 1e9 / hz;

        fprintf(out, "%d,%.2f,%.2f\n", it, ns_c, ns_n);
    }

    fclose(out);
    free(input);
    free(scratch_a);
    free(scratch_b);
    return 0;
}