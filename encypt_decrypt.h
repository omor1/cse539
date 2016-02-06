#ifndef encypt_decrypt_h
#define encypt_decrypt_h

#include <stdint.h>

uint32_t hw1_encrypt_block(const uint32_t block, const uint32_t key);
uint32_t hw1_decrypt_block(const uint32_t ciphertext, const uint32_t key);

#endif /* encypt_decrypt_h */
