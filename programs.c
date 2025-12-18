#include "isa.h"
#include "memory.h"
#include <stdint.h>
#include <stdio.h>

int program_size = 0;   // number of valid instructions

// Helpers to encode instructions
static uint16_t encode_I(Opcode op, uint8_t rt, uint8_t rs, int8_t imm6) {
    uint16_t uimm = (uint16_t)(imm6 & 0x3F);
    return (uint16_t)((op << 12) | (rt << 9) | (rs << 6) | uimm);
}

static uint16_t encode_R(Opcode op, uint8_t rd, uint8_t rs) {
    return (uint16_t)((op << 12) | (rd << 9) | (rs << 6));
}

// Build streaming ENC/DEC program that processes block count in data_mem[1],
// plaintext at PLAIN_BASE, ciphertext immediately after plaintext, and writes decrypted
// text back into the plaintext region.
void build_streaming_program(void) {
    int pc = 0;

    instr_mem[pc++] = encode_I(OPC_LDK, 6, 0, 0);                  // K0 = data[0]
    instr_mem[pc++] = encode_I(OPC_LD,  3, 0, 1);                  // R3 = block count
    instr_mem[pc++] = encode_I(OPC_ADDI,4, 0, (int8_t)PLAIN_BASE); // R4 = plaintext base
    instr_mem[pc++] = encode_I(OPC_ADDI,5, 4, 0);                  // R5 = plaintext base (will move to ciphertext base)
    instr_mem[pc++] = encode_I(OPC_ADDI,6, 3, 0);                  // R6 = block count (for pointer advance)

    // Advance R5 by count to point at ciphertext start
    instr_mem[pc++] = encode_I(OPC_BNE, 6, 0, 1);                  // if R6 != 0 jump to body (PC+1 semantics)
    instr_mem[pc++] = (OPC_NOP << 12);
    instr_mem[pc++] = encode_I(OPC_ADDI,5, 5, 1);                  // R5 += 1
    instr_mem[pc++] = encode_I(OPC_ADDI,6, 6,-1);                  // R6 -= 1
    instr_mem[pc++] = encode_I(OPC_BNE, 6, 0,-3);                  // loop while R6 != 0

    // Encrypt loop
    instr_mem[pc++] = encode_I(OPC_LD,  1, 4, 0);                  // R1 = *R4
    instr_mem[pc++] = encode_R(OPC_ENC, 2, 1);                     // R2 = ENC(R1)
    instr_mem[pc++] = encode_I(OPC_ST,  2, 5, 0);                  // *R5 = R2
    instr_mem[pc++] = encode_I(OPC_ADDI,4, 4, 1);                  // R4 += 1
    instr_mem[pc++] = encode_I(OPC_ADDI,5, 5, 1);                  // R5 += 1
    instr_mem[pc++] = encode_I(OPC_ADDI,3, 3,-1);                  // R3 -= 1
    instr_mem[pc++] = encode_I(OPC_BNE, 3, 0,-7);                  // loop if R3 != 0

    // Prepare for decrypt loop
    instr_mem[pc++] = encode_I(OPC_LD,  3, 0, 1);                  // R3 = block count
    instr_mem[pc++] = encode_I(OPC_ADDI,4, 5, 0);                  // R4 = current R5 (end of ciphertext)
    instr_mem[pc++] = encode_I(OPC_ADDI,6, 3, 0);                  // R6 = block count (walk back)

    // Walk R4 back to ciphertext start
    instr_mem[pc++] = encode_I(OPC_BNE, 6, 0, 1);
    instr_mem[pc++] = (OPC_NOP << 12);
    instr_mem[pc++] = encode_I(OPC_ADDI,4, 4,-1);
    instr_mem[pc++] = encode_I(OPC_ADDI,6, 6,-1);
    instr_mem[pc++] = encode_I(OPC_BNE, 6, 0,-3);

    instr_mem[pc++] = encode_I(OPC_ADDI,5, 0, (int8_t)PLAIN_BASE); // R5 = plaintext base (decrypt dest)

    // Decrypt loop
    instr_mem[pc++] = encode_I(OPC_LD,  1, 4, 0);                 // R1 = *R4 (ciphertext)
    instr_mem[pc++] = encode_R(OPC_DEC, 2, 1);                    // R2 = DEC(R1)
    instr_mem[pc++] = encode_I(OPC_ST,  2, 5, 0);                 // *R5 = R2
    instr_mem[pc++] = encode_I(OPC_ADDI,4, 4, 1);                 // R4 += 1
    instr_mem[pc++] = encode_I(OPC_ADDI,5, 5, 1);                 // R5 += 1
    instr_mem[pc++] = encode_I(OPC_ADDI,3, 3,-1);                 // R3 -= 1
    instr_mem[pc++] = encode_I(OPC_BNE, 3, 0,-7);                 // loop if R3 != 0

    instr_mem[pc++] = (OPC_HLT << 12);
    program_size = pc;
}

// Load a tiny test program: data_mem[0]=key, data_mem[1]=plaintext, encrypt to [2], decrypt back to [3]
void load_single_block_program(void) {
    init_memory();
    data_mem[0] = 0x1234;
    data_mem[1] = 0xABCD;

    int pc = 0;
    instr_mem[pc++] = encode_I(OPC_LDK, 6, 0, 0);
    instr_mem[pc++] = encode_I(OPC_LD,  1, 0, 1);
    instr_mem[pc++] = encode_R(OPC_ENC, 2, 1);
    instr_mem[pc++] = encode_I(OPC_ST,  2, 0, 2);
    instr_mem[pc++] = encode_R(OPC_DEC, 3, 2);
    instr_mem[pc++] = encode_I(OPC_ST,  3, 0, 3);
    instr_mem[pc++] = (OPC_HLT << 12);
    program_size = pc;
}

// Load a chunk of plaintext words into data memory with the provided key and block count.
int load_chunk_words(uint16_t key, const uint16_t *words, int blocks) {
    if (blocks < 1) return 0;
    int max_blocks = (DATA_MEM_SIZE - PLAIN_BASE) / 2; // space for plaintext + ciphertext
    if (blocks > max_blocks) blocks = max_blocks;

    init_memory();
    data_mem[0] = key;
    data_mem[1] = (uint16_t)blocks;
    for (int i = 0; i < blocks; i++) {
        data_mem[PLAIN_BASE + i] = words[i];
    }

    build_streaming_program();
    return blocks;
}
