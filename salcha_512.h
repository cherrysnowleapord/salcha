#ifndef SALCHA_512_H
#define SALCHA_512_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#define ROTL32(v, n) ((v << n) | (v >> (32 - n)))

#ifndef SALCHA_MATRIX_ROUNDS
#define SALCHA_MATRIX_ROUNDS 3
#endif

#ifndef SALCHA_DIFFUSION_MULIPLIER
#define SALCHA_DIFFUSION_MULIPLIER 1
#endif

#define SALCHA_NONCE_SIZE     12
#define SALCHA_32_BLOCK_COUNT 16 /* 16 elements 4 bytes each ( uint32_t ) 64 bytes total */
#define SALCHA_RAW_STATE_SIZE 64 /*   STATE_32BIT_SIZE * sizeof(state[0])   */
#define SALCHA_CONSTANTS_SIZE 24

#define COL 0
#define ROW 1
#define DIA 2

typedef struct {
    uint32_t state[SALCHA_32_BLOCK_COUNT];

    uint32_t matrix_state[4][3];
    bool matrix_state_init;

    size_t position;
} salcha_ctx_t;

#define SALCHA_DIAGANOL_INDEX(state, idx, skip) &state[(idx + skip) & 15]
#define SALCHA_COLUMN_INDEX(state, idx, col) &state[((idx & 3) << 2) + col]
#define SALCHA_ROW_INDEX(state, idx, row) &state[(row << 2) + (idx & 3)]

void salcha_xor(const uint8_t *bytes, const size_t bytes_len, uint8_t *out, salcha_ctx_t *ctx);
void salcha_init(salcha_ctx_t *ctx, const uint8_t *key, const size_t key_len, const uint8_t nonce[SALCHA_NONCE_SIZE]);

#endif
