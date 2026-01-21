# SalCha-512 Stream Cipher

⚠️ **Note**: This is a custom/educational implementation intended for learning and demonstration purposes. For production systems, use well-established cryptographic libraries like OpenSSL.

## Overview
🔒 A custom implementation of the SalCha-512 stream cipher optimized for 32-bit CPU architectures. This cryptographic library provides secure encryption/decryption capabilities with strong diffusion properties and efficient performance.

## Features
✅ **32-bit Optimized**: Specifically designed for 32-bit processor efficiency
✅ **Strong Diffusion**: Matrix-based rounding with diagonal, row, and column mixing
✅ **Secure Key Derivation**: Full-state initialization with key and nonce
✅ **High Performance**: Capable of 287+ MB/s encryption throughput

## Core Functionality

### Initialization
```c
void salcha_init(salcha_ctx_t *ctx, const uint8_t *key, const size_t key_len, const uint8_t nonce[SALCHA_NONCE_SIZE]);
```

### Encryption/Decryption
```c
void salcha_xor(const uint8_t *input, const size_t input_len, uint8_t *out, salcha_ctx_t *ctx);
```

## Security Features
🛡️ **Full-State Diffusion**: Ensures key and nonce material is thoroughly mixed throughout the entire state
🛡️ **Matrix Rounding**: Advanced permutation using diagonal, row, and column operations
🛡️ **Counter Mode**: Secure incremental counter for keystream generation
🛡️ **Constant-Time Operations**: Resistance to timing-based side-channel attacks

## Performance Benchmarks
```
Large Data Benchmark Summary
==================================================
Average run time: 988.456 ms
Total time: 2965.367 ms
Total data processed: 576.00 MB
Total throughput: 194.24 MB/s

Successful decryptions: 3/3

Benchmark config:
    Total Runs: 3
    Crypto input buffer size: 64 MB
    Cipher algo used: SalCha-512

Encryption benchmark:
    Total time: 668.222 ms
    Average time: 222.741 ms
    Average throughput: 287.33 MB/s

Decryption benchmark:
    Total time: 660.757 ms
    Average time: 220.252 ms
    Average throughput: 290.58 MB/s
```

## Architecture
The cipher implements a sophisticated state transformation process:
1. **State Initialization**: Key and nonce injection across entire state space
2. **Matrix Setup**: Preparation of mixing coefficients for diffusion
3. **Rounding Operations**: Multiple passes of diagonal, row, and column mixing
4. **Keystream Generation**: Counter-based XOR operations for encryption/decryption

## Use Cases
- Secure data encryption for storage
- Real-time communication encryption
- Cryptographic tool development
- Educational cryptography implementation

## Integration
```c
#include "salcha_512.h"

salcha_ctx_t ctx;
uint8_t key[32] = { /* your key */ };
uint8_t nonce[32] = { /* your nonce */ };

// Initialize cipher
salcha_init(&ctx, key, 32, nonce);

// Encrypt data
salcha_xor(plaintext, data_len, ciphertext, &ctx);
```

## Development Notes
This implementation demonstrates advanced cryptographic engineering principles including:
- Memory-safe C programming practices
- Efficient 32-bit arithmetic optimization
- Secure key scheduling and state management
- Comprehensive error handling and validation

## ⚠️ Disclaimer

This is an educational implementation created to demonstrate cryptographic concepts and C programming skills. While implemented with security best practices in mind, it has not undergone formal cryptanalysis or security auditing. Use established cryptographic libraries for production applications requiring security guarantees.
