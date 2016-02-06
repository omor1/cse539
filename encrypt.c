#include <stdio.h>

#include "encypt_decrypt.h"

int main(int argc, const char * argv[]) {
    uint32_t key = 0x5711FBC8;
    uint32_t orig_plaintext = 0xFFCD5792;
    uint32_t ciphertext = hw1_encrypt_block(orig_plaintext, key);
    uint32_t plaintext = hw1_decrypt_block(ciphertext, key);
    printf("0x%X\n", orig_plaintext);
    printf("0x%08X\n", ciphertext);
    printf("0x%X\n", plaintext);
    return 0;
}
