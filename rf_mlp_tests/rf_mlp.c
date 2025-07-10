/* SPDX-License-Identifier: BSD-3-Clause
 * Combined RF and NEON-accelerated MLP inference latency benchmark.
 * Measures per-iteration latency of Random Forest (from JSON) vs.
 * NEON-optimized MLP (from header) over ITERATIONS random samples.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <arm_neon.h>
#include <rte_eal.h>
#include <rte_cycles.h>
#include <jansson.h>            // JSON parsing

//  Model + feature‐stats headers (auto‐generated)

#include "feature_stats.h"    // defines FEATURE_MEAN[NUM_FEATURES], FEATURE_STD[…]

#include "mlp_8.h"            // pick one mlp_<spec>.h per run
#define RF_MODEL_JSON  "rf_1_trees.json"

// #include "mlp_32.h"
//#define RF_MODEL_JSON  "rf_3_trees.json"

// #include "mlp_64_32.h"
//#define RF_MODEL_JSON  "rf_5_trees.json"

// #include "mlp_128_64_32.h"
//#define RF_MODEL_JSON  "rf_11_trees.json"

// #include "mlp_256_128_64_32.h"
//#define RF_MODEL_JSON  "rf_17_trees.json"


#define ITERATIONS    5000
#define MIN_PKT_SIZE  64.0f
#define MAX_PKT_SIZE  9000.0f
#define MAX_LEN_RANGE (MAX_PKT_SIZE - MIN_PKT_SIZE)

// Random Forest limits
#define MAX_TREES 100
#define MAX_NODES 500

// uniform random [0,1)
static inline float randomf(void) {
    return (float)rand() / (float)RAND_MAX;
}

// piecewise‐linear sigmoid
static inline float fast_sigmoid_scalar(float x) {
    if (x <= -4.0f)      return 0.0f;
    else if (x <= -2.0f) return 0.0625f * x + 0.25f;
    else if (x <=  0.0f) return 0.125f * x + 0.5f;
    else if (x <=  2.0f) return -0.125f * x + 0.5f;
    else if (x <=  4.0f) return -0.0625f * x + 0.75f;
    else                 return 1.0f;
}

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
        if (!is_output) acc = vmaxq_f32(acc, vdupq_n_f32(0.0f));
        vst1q_f32(&out[j], acc);
    }
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
static int predict_mlp_neon(const float *in_features,
                            float *buf_a, float *buf_b) {
    float *in_buf = buf_a, *out_buf = buf_b;
    memcpy(in_buf, in_features, LAYER_SIZES[0] * sizeof(float));
    for (int L = 0; L < NUM_LAYERS; L++) {
        layer_forward_neon(
            WEIGHTS[L], BIASES[L],
            in_buf, out_buf,
            LAYER_SIZES[L], LAYER_SIZES[L+1],
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
    return best;
}

// Random Forest structures & JSON loader

typedef struct {
    int n_nodes;
    int left_child;
    int right_child;
    int feature;
    double threshold;
    int is_leaf;
    int class_label;
} TreeNode;

typedef struct {
    int n_estimators;
    int max_depth;
    double feature_importances[NUM_FEATURES];
    TreeNode trees[MAX_TREES][MAX_NODES];
} RandomForest;

// Load RF from JSON file
int load_rf_model(const char *filename, RandomForest *rf) {
    json_error_t error;
    json_t *root = json_load_file(filename, 0, &error);
    if (!root) {
        fprintf(stderr, "Error loading %s: %s\n", filename, error.text);
        return -1;
    }
    json_t *je = json_object_get(root, "n_estimators");
    rf->n_estimators = json_integer_value(je);
    je = json_object_get(root, "max_depth");
    rf->max_depth = json_integer_value(je);

    // feature importances
    je = json_object_get(root, "feature_importances");
    for (int i = 0; i < NUM_FEATURES; i++) {
        rf->feature_importances[i] =
            json_real_value(json_array_get(je, i));
    }

    // parse trees
    json_t *estimators = json_object_get(root, "estimators");
    size_t idx;
    json_t *tn;
    json_array_foreach(estimators, idx, tn) {
        TreeNode *tree = rf->trees[idx];
        int n_nodes = json_integer_value(
            json_object_get(tn, "n_nodes"));
        // arrays
        json_t *left  = json_object_get(tn, "children_left");
        json_t *right = json_object_get(tn, "children_right");
        json_t *feat  = json_object_get(tn, "feature");
        json_t *th    = json_object_get(tn, "threshold");
        json_t *cl    = json_object_get(tn, "class_label");
        json_t *leaf  = json_object_get(tn, "leaves");
        for (int i = 0; i < n_nodes; i++) {
            tree[i].n_nodes     = n_nodes;
            tree[i].left_child  = json_integer_value(
                                   json_array_get(left, i));
            tree[i].right_child = json_integer_value(
                                   json_array_get(right, i));
            tree[i].feature     = json_integer_value(
                                   json_array_get(feat, i));
            tree[i].threshold   = json_real_value(
                                   json_array_get(th, i));
            tree[i].class_label = json_integer_value(
                                   json_array_get(cl, i));
            tree[i].is_leaf     = json_integer_value(
                                   json_array_get(leaf, i));
        }
    }

    json_decref(root);
    return 0;
}

// recursive tree predictor
static int predict_tree(const TreeNode *tree, const double *sample, int idx) {
    if (tree[idx].is_leaf)
        return tree[idx].class_label;
    if (sample[tree[idx].feature] <= tree[idx].threshold)
        return predict_tree(tree, sample, tree[idx].left_child);
    else
        return predict_tree(tree, sample, tree[idx].right_child);
}

// majority‐vote RF predictor
int predict_rf(const RandomForest *rf, const double *sample) {
    int counts[NUM_FEATURES] = {0};
    for (int e = 0; e < rf->n_estimators; e++) {
        int p = predict_tree(rf->trees[e], sample, 0);
        if (p >= 0 && p < NUM_FEATURES) counts[p]++;
    }
    // find max
    int best = 0, maxc = counts[0];
    for (int i = 1; i < NUM_FEATURES; i++) {
        if (counts[i] > maxc) {
            maxc = counts[i];
            best = i;
        }
    }
    return best;
}


int main(int argc, char **argv) {
    if (rte_eal_init(argc, argv) < 0)
        rte_exit(EXIT_FAILURE, "EAL init failed\n");

    // 1) Load RF model
    RandomForest rf;
    if (load_rf_model(RF_MODEL_JSON, &rf) != 0)
        return -1;

    // 2) Allocate MLP buffers
    int max_neurons = 0;
    for (int i = 0; i <= NUM_LAYERS; i++)
        if (LAYER_SIZES[i] > max_neurons)
            max_neurons = LAYER_SIZES[i];

    float *scratch_a, *scratch_b, *raw_feat, *mlp_in;
    if (posix_memalign((void**)&scratch_a, 16, max_neurons*sizeof(float)) ||
        posix_memalign((void**)&scratch_b, 16, max_neurons*sizeof(float)) ||
        posix_memalign((void**)&raw_feat,   16, NUM_FEATURES*sizeof(float)) ||
        posix_memalign((void**)&mlp_in,     16, NUM_FEATURES*sizeof(float)))
    {
        rte_exit(EXIT_FAILURE, "posix_memalign failed\n");
    }

    // 3) Open CSV
    FILE *out = fopen("latencies.csv","w");
    if (!out) rte_exit(EXIT_FAILURE, "Cannot open latencies.csv\n");
    fprintf(out, "iter,rf_ns,mlp_ns\n");

    srand((unsigned)rte_get_tsc_cycles());
    const uint64_t hz = rte_get_tsc_hz();

    // 4) Benchmark loop
    for (int it = 0; it < ITERATIONS; it++) {
        // a) random raw features
        raw_feat[0] = MIN_PKT_SIZE + randomf()*MAX_LEN_RANGE;
        for (int k = 1; k < NUM_FEATURES; k++)
            raw_feat[k] = randomf();

        // b) prepare RF sample (double)
        double sample[NUM_FEATURES];
        for (int k = 0; k < NUM_FEATURES; k++)
            sample[k] = raw_feat[k];

        // c) prepare MLP input (z-score)
        for (int k = 0; k < NUM_FEATURES; k++)
            mlp_in[k] = (raw_feat[k] - FEATURE_MEAN[k]) / FEATURE_STD[k];

        // d) time RF
        uint64_t t0 = rte_rdtsc_precise();
        int rf_pred = predict_rf(&rf, sample);
        uint64_t t1 = rte_rdtsc_precise();
        double rf_ns = (double)(t1 - t0)*1e9/hz;

        // e) time MLP
        t0 = rte_rdtsc_precise();
        int mlp_pred = predict_mlp_neon(mlp_in, scratch_a, scratch_b);
        t1 = rte_rdtsc_precise();
        double mlp_ns = (double)(t1 - t0)*1e9/hz;

        // f) write CSV
        fprintf(out, "%d,%.2f,%.2f\n", it, rf_ns, mlp_ns);
    }

    fclose(out);
    free(scratch_a);
    free(scratch_b);
    free(raw_feat);
    free(mlp_in);
    return 0;
}
