#include <stdint.h>
#include <math.h>

#include "encrypt_decrypt.h"


static const uint8_t S_lookup[256] =
{
    0x00, 0x01, 0x81, 0x56, 0xC1, 0x67, 0x2B, 0x93,
    0xE1, 0xC8, 0xB4, 0xBB, 0x96, 0xB2, 0xCA, 0x78,
    0xF1, 0x79, 0x64, 0xE6, 0x5A, 0x31, 0xDE, 0xBE,
    0x4B, 0x48, 0x59, 0xEE, 0x65, 0xC3, 0x3C, 0xC7,
    0xF9, 0x94, 0xBD, 0xEB, 0x32, 0x84, 0x73, 0x91,
    0x2D, 0xA3, 0x99, 0x06, 0x6F, 0x28, 0x5F, 0xAF,
    0xA6, 0x15, 0x24, 0x7E, 0xAD, 0x61, 0x77, 0xF3,
    0xB3, 0xF8, 0xE2, 0x3D, 0x1E, 0x3B, 0xE4, 0x66,
    0xFD, 0x57, 0x4A, 0xEA, 0xDF, 0x95, 0xF6, 0xB5,
    0x19, 0xA9, 0x42, 0x18, 0xBA, 0xF7, 0xC9, 0xF4,
    0x97, 0xA5, 0xD2, 0x60, 0xCD, 0x7F, 0x03, 0x41,
    0xB8, 0x1A, 0x14, 0xD1, 0xB0, 0x98, 0xD8, 0x2E,
    0x53, 0x35, 0x8B, 0x87, 0x12, 0x1C, 0x3F, 0x05,
    0xD7, 0xA4, 0xB1, 0xF5, 0xBC, 0xE0, 0xFA, 0x2C,
    0xDA, 0x74, 0x7C, 0x26, 0x71, 0x86, 0x9F, 0x36,
    0x0F, 0x11, 0x9E, 0x8C, 0x72, 0xDC, 0x33, 0x55,
    0xFF, 0x02, 0xAC, 0xCE, 0x25, 0x8F, 0x75, 0x63,
    0xF0, 0xF2, 0xCB, 0x62, 0x7B, 0x90, 0xDB, 0x85,
    0x8D, 0x27, 0xD5, 0x07, 0x21, 0x45, 0x0C, 0x50,
    0x5D, 0x2A, 0xFC, 0xC2, 0xE5, 0xEF, 0x7A, 0x76,
    0xCC, 0xAE, 0xD3, 0x29, 0x69, 0x51, 0x30, 0xED,
    0xE7, 0x49, 0xC0, 0xFE, 0x82, 0x34, 0xA1, 0x2F,
    0x5C, 0x6A, 0x0D, 0x38, 0x0A, 0x47, 0xE9, 0xBF,
    0x58, 0xE8, 0x4C, 0x0B, 0x6C, 0x22, 0x17, 0xB7,
    0xAA, 0x04, 0x9B, 0x1D, 0xC6, 0xE3, 0xC4, 0x1F,
    0x09, 0x4E, 0x0E, 0x8A, 0xA0, 0x54, 0x83, 0xDD,
    0xEC, 0x5B, 0x52, 0xA2, 0xD9, 0x92, 0xFB, 0x68,
    0x5E, 0xD4, 0x70, 0x8E, 0x7D, 0xCF, 0x16, 0x44,
    0x6D, 0x08, 0x3A, 0xC5, 0x3E, 0x9C, 0x13, 0xA8,
    0xB9, 0xB6, 0x43, 0x23, 0xD0, 0xA7, 0x1B, 0x9D,
    0x88, 0x10, 0x89, 0x37, 0x4F, 0x6B, 0x46, 0x4D,
    0x39, 0x20, 0x6E, 0xD6, 0x9A, 0x40, 0xAB, 0x80
};
//#define S_mod 257
// inverse mod 257
uint8_t S(const uint8_t blk)
{
    // original code below, used to generate lookup table
    // naive exponentiation – costly, but works
//    uint16_t sub = blk;
//    for (uint8_t i = 0; i < 254; i++) {
//        sub = (sub*blk) % S_mod;
//    }
//    return sub;
    return S_lookup[blk];
}

// S is its own inverse
#define S_inverse(blk) S((blk))

#define LEFT_BITS 0x88
#define INNER_LEFT_BITS 0x44
#define INNER_RIGHT_BITS 0x22
#define RIGHT_BITS 0x11

// permute bits between the four 8-bit blocklets that make up the block
uint32_t P(const uint32_t block)
{
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

uint32_t P_inverse(const uint32_t block)
{
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

uint32_t round_key(const uint32_t master_key, const uint8_t round)
{
    union block key = { master_key };
    union block round_key;
    round_key.arr[0] = S(key.arr[(0 + round) % 4]);
    round_key.arr[1] = S(key.arr[(1 + round) % 4]);
    round_key.arr[2] = S(key.arr[(2 + round) % 4]);
    round_key.arr[3] = S(key.arr[(3 + round) % 4]);
    return round_key.i;
}

uint32_t encrypt_block(const uint32_t plaintext, const uint32_t key)
{
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

uint32_t decrypt_block(const uint32_t ciphertext, const uint32_t key)
{
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

uint32_t encrypt_cbc(const uint32_t plaintext, const uint32_t key,
                     const uint32_t previous_ciphertext)
{
    return encrypt_block(plaintext ^ previous_ciphertext, key);
}

uint32_t decrypt_cbc(const uint32_t ciphertext, const uint32_t key,
                     const uint32_t previous_ciphertext)
{
    return decrypt_block(ciphertext, key) ^ previous_ciphertext;
}