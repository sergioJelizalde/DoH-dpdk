#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <arm_neon.h>
#include <rte_eal.h>
#include <rte_cycles.h>
#include <math.h>

// -----------------------------------------------------------------------------
// Model + feature-stats headers (auto-generated)
#include "feature_stats.h"    // defines FEATURE_MEAN[NUM_FEATURES], FEATURE_STD[…]
#include "mlp_weights.h"      // pick one mlp_<spec>.h per run
#include "test_data.h"

// -----------------------------------------------------------------------

// piecewise-linear sigmoid for output layer
static inline float fast_sigmoid_scalar(float x) {
    if (x <= -4.0f)      return 0.0f;
    else if (x <= -2.0f) return 0.0625f * x + 0.25f;
    else if (x <=  0.0f) return 0.125f * x + 0.5f;
    else if (x <=  2.0f) return -0.125f * x + 0.5f;
    else if (x <=  4.0f) return -0.0625f * x + 0.75f;
    else                 return 1.0f;
}

// Fast piecewise sigmoid approximation
static inline float sigmoid_piece(float x) {
    if (x <= -4.0f) return 0.0f;
    else if (x <= -2.0f) return 0.0625f * x + 0.25f;
    else if (x <= 0.0f)  return 0.125f * x + 0.5f;
    else if (x <= 2.0f)  return -0.125f * x + 0.5f;
    else if (x <= 4.0f)  return -0.0625f * x + 0.75f;
    else return 1.0f;
}

// NEON version for vectorized code
static inline float32x4_t sigmoid_neon(float32x4_t x) {
    float32x4_t abs_x = vabsq_f32(x);
    float32x4_t one = vdupq_n_f32(1.0f);
    float32x4_t ratio = vdivq_f32(abs_x, vaddq_f32(one, abs_x));
    uint32x4_t mask = vcgeq_f32(x, vdupq_n_f32(0.0f));
    float32x4_t pos = ratio;
    float32x4_t neg = vsubq_f32(one, ratio);
    return vbslq_f32(mask, pos, neg);
}

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
        if (!is_output) acc = vmaxq_f32(acc, vdupq_n_f32(0.0f));
        vst1q_f32(&out[j], acc);
    }

    // Tail handling
    for (; j < size_out; j++) {
        float a = B[j];
        for (int k = 0; k < size_in; k++)
            a += W[k*size_out + j] * in[k];
        if (!is_output) a = (a > 0.0f) ? a : 0.0f;
        out[j] = a;
    }
}

static int predict_mlp_neon_general(const float *in_features, float *buf_a, float *buf_b) {
    float *in_buf = buf_a, *out_buf = buf_b;
    memcpy(in_buf, in_features, LAYER_SIZES[0] * sizeof(float));

    for (int L = 0; L < NUM_LAYERS; L++) {
        int is_output_layer = (L == NUM_LAYERS - 1);
        layer_forward_neon(WEIGHTS[L], BIASES[L],
                           in_buf, out_buf,
                           LAYER_SIZES[L],
                           LAYER_SIZES[L+1],
                           is_output_layer);
        
        // Apply activation functions ONLY to final output
        if (is_output_layer) {
            #if IS_BINARY_CLASSIFICATION
            // Apply sigmoid to final output only
            for (int i = 0; i < LAYER_SIZES[L+1]; i++)
                out_buf[i] = sigmoid_piece(out_buf[i]);
            
            #elif IS_MULTICLASS_CLASSIFICATION  
            // Apply softmax to final output only
            float max_val = out_buf[0];
            for (int i = 1; i < LAYER_SIZES[L+1]; i++) {
                if (out_buf[i] > max_val) max_val = out_buf[i];
            }
            
            float sum = 0.0f;
            for (int i = 0; i < LAYER_SIZES[L+1]; i++) {
                out_buf[i] = expf(out_buf[i] - max_val);
                sum += out_buf[i];
            }
            
            for (int i = 0; i < LAYER_SIZES[L+1]; i++) {
                out_buf[i] /= sum;
            }
            #endif
        }
        
        float *tmp = in_buf; in_buf = out_buf; out_buf = tmp;
    }

    // Final result is now in in_buf (due to the last swap)
    int final_size = LAYER_SIZES[NUM_LAYERS];
    
    #if IS_BINARY_CLASSIFICATION
    return (in_buf[0] >= 0.5f) ? 1 : 0;
    
    #elif IS_MULTICLASS_CLASSIFICATION
    int best_class = 0; 
    float best_probability = in_buf[0];
    for (int i = 1; i < final_size; i++) {
        if (in_buf[i] > best_probability) { 
            best_probability = in_buf[i]; 
            best_class = i; 
        }
    }
    return best_class;
    #endif
}

// Scalar reference implementation
static int predict_mlp_c_general(const float *in_features, float *buf_a, float *buf_b) {
    float *in_buf = buf_a, *out_buf = buf_b;
    memcpy(in_buf, in_features, LAYER_SIZES[0] * sizeof(float));

    for (int L = 0; L < NUM_LAYERS; L++) {
        int is_output_layer = (L == NUM_LAYERS - 1);
        
        // Scalar matrix multiplication
        for (int j = 0; j < LAYER_SIZES[L+1]; j++) {
            float sum = BIASES[L][j];
            for (int k = 0; k < LAYER_SIZES[L]; k++) {
                sum += WEIGHTS[L][k * LAYER_SIZES[L+1] + j] * in_buf[k];
            }
            
            // ReLU activation for hidden layers
            if (!is_output_layer) {
                sum = (sum > 0.0f) ? sum : 0.0f;
            }
            out_buf[j] = sum;
        }
        
        // Apply activation functions ONLY to final output
        if (is_output_layer) {
            #if IS_BINARY_CLASSIFICATION
            // Apply sigmoid to final output only
            for (int i = 0; i < LAYER_SIZES[L+1]; i++)
                out_buf[i] = sigmoid_piece(out_buf[i]);
            
            #elif IS_MULTICLASS_CLASSIFICATION  
            // Apply softmax to final output only
            float max_val = out_buf[0];
            for (int i = 1; i < LAYER_SIZES[L+1]; i++) {
                if (out_buf[i] > max_val) max_val = out_buf[i];
            }
            
            float sum = 0.0f;
            for (int i = 0; i < LAYER_SIZES[L+1]; i++) {
                out_buf[i] = expf(out_buf[i] - max_val);
                sum += out_buf[i];
            }
            
            for (int i = 0; i < LAYER_SIZES[L+1]; i++) {
                out_buf[i] /= sum;
            }
            #endif
        }
        
        float *tmp = in_buf; in_buf = out_buf; out_buf = tmp;
    }

    // Final result is now in in_buf (due to the last swap)
    int final_size = LAYER_SIZES[NUM_LAYERS];
    
    #if IS_BINARY_CLASSIFICATION
    return (in_buf[0] >= 0.5f) ? 1 : 0;
    
    #elif IS_MULTICLASS_CLASSIFICATION
    int best_class = 0; 
    float best_probability = in_buf[0];
    for (int i = 1; i < final_size; i++) {
        if (in_buf[i] > best_probability) { 
            best_probability = in_buf[i]; 
            best_class = i; 
        }
    }
    return best_class;
    #endif
}

// Helper function for random float generation (if needed)
static inline float randomf() {
    return (float)rand() / (float)RAND_MAX;
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
    float *scratch_a, *scratch_b, *input;
    if (posix_memalign((void**)&scratch_a, 16, max_neurons * sizeof(float)) ||
        posix_memalign((void**)&scratch_b, 16, max_neurons * sizeof(float)) ||
        posix_memalign((void**)&input,     16, LAYER_SIZES[0] * sizeof(float)))
    {
        rte_exit(EXIT_FAILURE, "posix_memalign failed\n");
    }

    FILE *out = fopen("latencies.csv", "w");
    if (!out) rte_exit(EXIT_FAILURE, "Cannot open latencies.csv\n");
    fprintf(out, "iter,expected,scalar_output,neon_output,latency_c_ns,latency_neon_ns,match_scalar,match_neon\n");

    srand((unsigned)rte_get_tsc_cycles());
    const uint64_t hz = rte_get_tsc_hz();

    int scalar_matches = 0, neon_matches = 0;
    int total_tests = TEST_N ;

    printf("Running %d test cases...\n", total_tests);
    printf("Expected classes distribution:\n");

    // Count expected class distribution
    int class_counts[4] = {0};
    for (int i = 0; i < total_tests; i++) {
        if (y_expected[i] >= 0 && y_expected[i] < 4) {
            class_counts[y_expected[i]]++;
        }
    }
    for (int i = 0; i < 4; i++) {
        printf("  Class %d: %d samples\n", i, class_counts[i]);
    }

    for (int it = 0; it < total_tests; it++) {
        // Use test data directly (already normalized)
        memcpy(input, X_test[it], LAYER_SIZES[0] * sizeof(float));

        int expected_class = y_expected[it];

        // benchmark scalar
        uint64_t t0 = rte_rdtsc_precise();
        int cls_c = predict_mlp_c_general(input, scratch_a, scratch_b);
        uint64_t t1 = rte_rdtsc_precise();
        double ns_c = (double)(t1 - t0) * 1e9 / hz;

        // benchmark NEON
        t0 = rte_rdtsc_precise();
        int cls_n = predict_mlp_neon_general(input, scratch_a, scratch_b);
        t1 = rte_rdtsc_precise();
        double ns_n = (double)(t1 - t0) * 1e9 / hz;

        // Check matches
        int match_scalar = (cls_c == expected_class);
        int match_neon = (cls_n == expected_class);
        
        if (match_scalar) scalar_matches++;
        if (match_neon) neon_matches++;

        fprintf(out, "%d,%d,%d,%d,%.2f,%.2f,%d,%d\n", 
                it, expected_class, cls_c, cls_n, ns_c, ns_n, match_scalar, match_neon);

        // Print mismatches for debugging
        if (!match_scalar || !match_neon) {
            printf("Mismatch at test %d: expected=%d, scalar=%d, neon=%d\n", 
                   it, expected_class, cls_c, cls_n);
        }
    }

    // Summary
    printf("\n=== RESULTS ===\n");
    printf("Total test cases: %d\n", total_tests);
    printf("Scalar accuracy: %d/%d (%.2f%%)\n", 
           scalar_matches, total_tests, 100.0 * scalar_matches / total_tests);
    printf("NEON accuracy:   %d/%d (%.2f%%)\n", 
           neon_matches, total_tests, 100.0 * neon_matches / total_tests);
    printf("Scalar-NEON agreement: %s\n", 
           (scalar_matches == neon_matches) ? "PERFECT" : "DIFFERENT");

    fclose(out);
    free(scratch_a);
    free(scratch_b);
    free(input);
    
    return 0;
}