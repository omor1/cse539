#ifndef encypt_decrypt_h
#define encypt_decrypt_h

#include <stdint.h>

union block {
    uint32_t i;
    uint8_t arr[4];
};

uint32_t encrypt_block(const uint32_t block, const uint32_t key);
uint32_t decrypt_block(const uint32_t ciphertext, const uint32_t key);

uint32_t encrypt_cbc(const uint32_t plaintext, const uint32_t key,
                     const uint32_t previous_ciphertext);
uint32_t decrypt_cbc(const uint32_t ciphertext, const uint32_t key,
                     const uint32_t previous_ciphertext);

#endif /* encypt_decrypt_h */
