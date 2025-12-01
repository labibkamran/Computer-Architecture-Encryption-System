#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>

uint16_t enc_func(uint16_t block, uint16_t k0, uint16_t k1);
uint16_t dec_func(uint16_t block, uint16_t k0, uint16_t k1);

#endif // CRYPTO_H
