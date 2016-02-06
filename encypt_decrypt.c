#include <stdint.h>
#include <math.h>

#include "encypt_decrypt.h"

union block {
    uint32_t i;
    uint8_t arr[4];
};

#define S_mod 257
// inverse mod 257
// TODO: lookup table
uint8_t S(const uint8_t blk) {
    uint16_t sub = blk;
    for (uint8_t i = 0; i < 254; i++) {
        sub = (sub*blk) % S_mod;
    }
    return sub;
}

// S is its own inverse
#define S_inverse(blk) S((blk))

#define LEFT_BITS 0x88
#define INNER_LEFT_BITS 0x44
#define INNER_RIGHT_BITS 0x22
#define RIGHT_BITS 0x11

uint32_t P(const uint32_t block) {
    union block orig = { block };
    union block new = { 0x00000000 };
    
    new.arr[0] |= orig.arr[0] & LEFT_BITS;
    new.arr[1] |= orig.arr[1] & LEFT_BITS;
    new.arr[2] |= orig.arr[2] & LEFT_BITS;
    new.arr[3] |= orig.arr[3] & LEFT_BITS;
    
    new.arr[0] |= orig.arr[1] & INNER_LEFT_BITS;
    new.arr[1] |= orig.arr[2] & INNER_LEFT_BITS;
    new.arr[2] |= orig.arr[3] & INNER_LEFT_BITS;
    new.arr[3] |= orig.arr[0] & INNER_LEFT_BITS;
    
    new.arr[0] |= orig.arr[2] & INNER_RIGHT_BITS;
    new.arr[1] |= orig.arr[3] & INNER_RIGHT_BITS;
    new.arr[2] |= orig.arr[0] & INNER_RIGHT_BITS;
    new.arr[3] |= orig.arr[1] & INNER_RIGHT_BITS;
    
    new.arr[0] |= orig.arr[3] & RIGHT_BITS;
    new.arr[1] |= orig.arr[0] & RIGHT_BITS;
    new.arr[2] |= orig.arr[1] & RIGHT_BITS;
    new.arr[3] |= orig.arr[2] & RIGHT_BITS;
    
    return new.i;
}

uint32_t P_inverse(const uint32_t block) {
    union block orig = { block };
    union block new = { 0x00000000 };
    
    new.arr[0] |= orig.arr[0] & LEFT_BITS;
    new.arr[1] |= orig.arr[1] & LEFT_BITS;
    new.arr[2] |= orig.arr[2] & LEFT_BITS;
    new.arr[3] |= orig.arr[3] & LEFT_BITS;
    
    new.arr[0] |= orig.arr[3] & INNER_LEFT_BITS;
    new.arr[1] |= orig.arr[0] & INNER_LEFT_BITS;
    new.arr[2] |= orig.arr[1] & INNER_LEFT_BITS;
    new.arr[3] |= orig.arr[2] & INNER_LEFT_BITS;
    
    new.arr[0] |= orig.arr[2] & INNER_RIGHT_BITS;
    new.arr[1] |= orig.arr[3] & INNER_RIGHT_BITS;
    new.arr[2] |= orig.arr[0] & INNER_RIGHT_BITS;
    new.arr[3] |= orig.arr[1] & INNER_RIGHT_BITS;
    
    new.arr[0] |= orig.arr[1] & RIGHT_BITS;
    new.arr[1] |= orig.arr[2] & RIGHT_BITS;
    new.arr[2] |= orig.arr[3] & RIGHT_BITS;
    new.arr[3] |= orig.arr[0] & RIGHT_BITS;
    
    return new.i;
}

uint32_t round_key(const uint32_t master_key, const uint8_t round) {
    union block key = { master_key };
    union block round_key;
    round_key.arr[0] = S(key.arr[(0 + round) % 4]);
    round_key.arr[1] = S(key.arr[(1 + round) % 4]);
    round_key.arr[2] = S(key.arr[(2 + round) % 4]);
    round_key.arr[3] = S(key.arr[(3 + round) % 4]);
    return round_key.i;
}

uint32_t hw1_encrypt_block(const uint32_t plaintext, const uint32_t key) {
    union block block = { plaintext };
    for (int i = 0; i < 3; i++) {
        block.i ^= round_key(key, i);
        for (int j = 0; j < 4; j++) {
            block.arr[j] = S(block.arr[j]);
        }
        block.i = P(block.i);
    }
    block.i ^= round_key(key, 3);
    return block.i;
}

uint32_t hw1_decrypt_block(const uint32_t ciphertext, const uint32_t key) {
    union block block = { ciphertext };
    block.i ^= round_key(key, 3);
    for (int i = 2; i >= 0; i--) {
        block.i = P_inverse(block.i);
        for (int j = 0; j < 4; j++) {
            block.arr[j] = S_inverse(block.arr[j]);
        }
        block.i ^= round_key(key, i);
    }
    return block.i;
}

#define IV 0xD1CEBABE //magic numbers are spooky
// TODO: encrypt array (using CBC)