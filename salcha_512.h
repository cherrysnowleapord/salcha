#ifndef SALCHA_512_H
#define SALCHA_512_H

#include <stdlib.h>
#include <stdint.h>

#include "bits/bool.h"
#include "crypto/types.h"

#define SALCHA_DIAGANOL_INDEX(state, idx, skip) &state[(idx + skip) & 15]
#define SALCHA_COLUMN_INDEX(state, idx, col) &state[((idx & 3) << 2) + col]
#define SALCHA_ROW_INDEX(state, idx, row) &state[(row << 2) + (idx & 3)]

void salcha_xor(const uint8_t *bytes, const size_t bytes_len, uint8_t *out, salcha_ctx_t *ctx);
void salcha_init(salcha_ctx_t *ctx, const uint8_t *key, const size_t key_len, const uint8_t nonce[SALCHA_NONCE_SIZE]);

#endif
