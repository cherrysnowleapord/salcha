/**
 * salcha_512.c
 *
 * Implements the Salcha-512 stream cipher for 32-bit CPUs.
 *
 * Features:
 *   - 32-bit state initialization with key and nonce.
 *   - Full-state diffusion via matrix rounding.
 *   - XOR encryption/decryption with generated keystream.
 *   - Uses diagonal, row, and column mixing for strong diffusion.
 */

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

#include "salcha_512.h"

/* Constants*/

static const uint32_t constants[SALCHA_CONSTANTS_SIZE] = {
    0x70eabe81, 0x751f44a1, 0x60e8d9e,  0x30543b9, 
    0x61e72878, 0x3d4bfaa5, 0x47cc0d42, 0x21c13742, 
    0x4451acfc, 0x4da23970, 0x3c443c58, 0x7c5e5d6b, 
    0x46301d09, 0x610761f7, 0x53922d3c, 0x76710ee4, 
    0x9448c67,  0x6f4d8734, 0x22ddde87, 0xa4686ea, 
    0x8d59093,  0x16c2b03a, 0x693b07da, 0x65380107,
};

/* Exported functions */
void salcha_init(salcha_ctx_t *ctx, const uint8_t *key, const size_t key_len, const uint8_t nonce[SALCHA_NONCE_SIZE]);
void salcha_xor(const uint8_t *input, const size_t input_len, uint8_t *out, salcha_ctx_t *ctx);

/* Static internal helpers */
static void salcha_inject_to_state(salcha_ctx_t *ctx, const uint8_t *input, const size_t input_len);
static void salcha_state_init(salcha_ctx_t *ctx, const size_t key_len);
static void salcha_set_quarters(salcha_ctx_t *ctx, uint32_t *quarters[4][3], int x);
static void salcha_matrix_rounding(salcha_ctx_t *ctx);
static void salcha_init_matrix_state(salcha_ctx_t *ctx);

void lround4(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d, const uint32_t p1, const uint32_t p2) {
    *a += (p2 + *b); 
    *b ^= *a;  
    *b = ROTL32((*b + p1), 5);   
    *a = ROTL32((*a + p1), 11);

    *c += (p1 + *d); 
    *d ^= *c;  
    *d = ROTL32((*d + p2), 12);  
    *c = ROTL32((*c + p2), 15);

    *a += (p1 + *b); 
    *b ^= *a;  
    *b = ROTL32((*b + p2), 14);
    *a = ROTL32((*a + p2), 25);

    *c += (p2 + *d); 
    *d ^= *c;  
    *d = ROTL32((*c + p1), 7);
    *c = ROTL32((*c + p1), 30);
}

void salcha_init(salcha_ctx_t *ctx, const uint8_t *key, const size_t key_len, const uint8_t nonce[SALCHA_NONCE_SIZE]) {
    if(ctx == NULL || key == NULL || !key_len)
        return;
    
    _memset(ctx, 0, sizeof(salcha_ctx_t));

    salcha_state_init(ctx, key_len);

    /* inject key and nonce across the whole state */
    salcha_inject_to_state(ctx, key, key_len);
    salcha_inject_to_state(ctx, nonce, SALCHA_NONCE_SIZE);

    salcha_init_matrix_state(ctx);
    salcha_matrix_rounding(ctx);
}

void salcha_xor(const uint8_t *input, const size_t input_len, uint8_t *out, salcha_ctx_t *ctx) {
    if(!input_len || input == NULL || out == NULL || ctx == NULL)
        return;

    size_t offset = 0;
    size_t blocks_size;
    size_t counter = 0;

    _memcpy(out, input, input_len);

    while(offset < input_len) {
        blocks_size = (input_len - offset) < SALCHA_RAW_STATE_SIZE ? (input_len - offset) : SALCHA_RAW_STATE_SIZE;
        
        ctx->state[15] += ++counter;

        salcha_matrix_rounding(ctx);

        for(size_t i = 0; i < blocks_size; i++)
            out[offset + i] ^= ((uint8_t *)ctx->state)[i];

        offset += blocks_size;
    }
}

/* ensures all input data is permutated across the whole state */
static void salcha_inject_to_state(salcha_ctx_t *ctx, const uint8_t *input, const size_t input_len) {
    size_t state_index = 0;

    for (size_t i = 0; i < input_len; i++) {
        ((uint8_t *)&ctx->state[state_index])[i % 4] ^= input[i];

        if ((i + 1) % 4 == 0)
            state_index = (state_index + 1) % SALCHA_32_BLOCK_COUNT;
    }
}

static void salcha_init_matrix_state(salcha_ctx_t *ctx) {
    if(ctx == NULL || ctx->matrix_state_init == true)
        return;
    
    for(int i = 0; i < 4; i++) {
        for(int x = 0; x < 3; x++) {
            int idx_op = (i * 7 + x * 11);
            ctx->matrix_state[i][x] ^= (ctx->state[(idx_op) % SALCHA_32_BLOCK_COUNT] ^ constants[idx_op % SALCHA_CONSTANTS_SIZE]);
        }
    }
    
    ctx->matrix_state_init = true;
}

static void salcha_state_init(salcha_ctx_t *ctx, const size_t key_len) {
    for(int i = 0; i < SALCHA_32_BLOCK_COUNT; i++)
        ctx->state[i] = constants[((key_len << 21) * (i + 1)) % SALCHA_CONSTANTS_SIZE];
}

static void salcha_set_quarters(salcha_ctx_t *ctx, uint32_t *quarters[4][3], int x) {
    quarters[0][COL] = SALCHA_COLUMN_INDEX(ctx->state, x, 0);
    quarters[1][COL] = SALCHA_COLUMN_INDEX(ctx->state, x, 1);
    quarters[2][COL] = SALCHA_COLUMN_INDEX(ctx->state, x, 2);
    quarters[3][COL] = SALCHA_COLUMN_INDEX(ctx->state, x, 3);

    quarters[0][ROW] = SALCHA_ROW_INDEX(ctx->state, x, 0);
    quarters[1][ROW] = SALCHA_ROW_INDEX(ctx->state, x, 1);
    quarters[2][ROW] = SALCHA_ROW_INDEX(ctx->state, x, 2);
    quarters[3][ROW] = SALCHA_ROW_INDEX(ctx->state, x, 3);

    quarters[0][DIA] = SALCHA_DIAGANOL_INDEX(ctx->state, x, 0);
    quarters[1][DIA] = SALCHA_DIAGANOL_INDEX(ctx->state, x, 5);
    quarters[2][DIA] = SALCHA_DIAGANOL_INDEX(ctx->state, x, 10);
    quarters[3][DIA] = SALCHA_DIAGANOL_INDEX(ctx->state, x, 15);
}

static void salcha_matrix_rounding(salcha_ctx_t *ctx) {
    uint32_t *quarters[4][3] = {0};

    static int multiplier = SALCHA_DIFFUSION_MULIPLIER * 4;

    for(int i = 0; i < multiplier; i++) {
        salcha_set_quarters(ctx, quarters, i);

        for(int x = 0; x < SALCHA_MATRIX_ROUNDS; x++) {
            lround4(quarters[0][COL], quarters[3][ROW], quarters[2][DIA], quarters[1][ROW],
                    ctx->matrix_state[3][COL], ctx->matrix_state[2][DIA]);

            lround4(quarters[1][COL], quarters[0][ROW], quarters[3][DIA], quarters[2][ROW],
                    ctx->matrix_state[0][COL], ctx->matrix_state[3][DIA]);

            lround4(quarters[2][COL], quarters[1][ROW], quarters[0][DIA], quarters[3][ROW],
                    ctx->matrix_state[1][COL], ctx->matrix_state[0][DIA]);

            lround4(quarters[3][COL], quarters[2][ROW], quarters[1][DIA], quarters[0][ROW],
                    ctx->matrix_state[2][COL], ctx->matrix_state[1][DIA]);
        }

        for(int h = 0; h < 4; h++) {
            for(int x = 0; x < 3; x++)
                ctx->matrix_state[h][x] = *quarters[h][x];
        }
    }
}
