#include "crypto.h"

// Rotate left 16 bits
static uint16_t rotl16(uint16_t x, unsigned r) {
    return (uint16_t)((x << r) | (x >> (16 - r)));
}

// Rotate right 16 bits
static uint16_t rotr16(uint16_t x, unsigned r) {
    return (uint16_t)((x >> r) | (x << (16 - r)));
}

// 4-bit S-box
static const uint8_t SBOX[16] = {
    0xC, 0x5, 0x6, 0xB,
    0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8,
    0x4, 0x7, 0x1, 0x2
};

// inverse S-box
static const uint8_t SBOX_INV[16] = {
    0x5, 0xE, 0xF, 0x8,
    0xC, 0x1, 0x2, 0xD,
    0xB, 0x4, 0x6, 0x3,
    0x0, 0x7, 0x9, 0xA
};

static uint16_t sbox16(uint16_t x) {
    uint16_t out = 0;
    for (int i = 0; i < 4; i++) {
        uint8_t nib = (x >> (i * 4)) & 0xF;
        out |= (uint16_t)SBOX[nib] << (i * 4);
    }
    return out;
}

static uint16_t sbox16_inv(uint16_t x) {
    uint16_t out = 0;
    for (int i = 0; i < 4; i++) {
        uint8_t nib = (x >> (i * 4)) & 0xF;
        out |= (uint16_t)SBOX_INV[nib] << (i * 4);
    }
    return out;
}

// Encrypt one 16-bit block
uint16_t enc_func(uint16_t block, uint16_t k0, uint16_t k1) {
    uint16_t state = block;
    for (int r = 0; r < 4; r++) {
        state ^= k0;
        state  = rotl16(state, 3);
        state  = sbox16(state);
        state ^= k1;
    }
    return state;
}

// Decrypt one 16-bit block (inverse of above)
uint16_t dec_func(uint16_t block, uint16_t k0, uint16_t k1) {
    uint16_t state = block;
    for (int r = 0; r < 4; r++) {
        state ^= k1;
        state  = sbox16_inv(state);
        state  = rotr16(state, 3);
        state ^= k0;
    }
    return state;
}
