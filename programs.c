#include "isa.h"
#include "memory.h"

int program_size = 0;   // number of valid instructions

// Helper: encode I-type (LD, ST, ADDI, LDK)
uint16_t encode_I(Opcode op, uint8_t rt, uint8_t rs, int8_t imm6) {
    uint16_t uimm = (uint16_t)(imm6 & 0x3F);
    return (uint16_t)((op << 12) | (rt << 9) | (rs << 6) | uimm);
}

// Helper: encode R-type (ENC, DEC)
uint16_t encode_R(Opcode op, uint8_t rd, uint8_t rs) {
    return (uint16_t)((op << 12) | (rd << 9) | (rs << 6));
}

// Build a tiny test program:
//  data_mem[0] = key
//  data_mem[1] = plaintext
//  -> encrypt to data_mem[2]
//  -> decrypt back to data_mem[3]
void load_single_block_program(void) {
    init_memory();

    // initialise data
    data_mem[0] = 0x1234;  // key
    data_mem[1] = 0xABCD;  // plaintext

    int pc = 0;

    // LDK K0, 0(R0)   ; key from data[0]
    instr_mem[pc++] = encode_I(OPC_LDK, 6, 0, 0);

    // LD R1, 1(R0)    ; plaintext from data[1]
    instr_mem[pc++] = encode_I(OPC_LD, 1, 0, 1);

    // ENC R2, R1      ; ciphertext = E(K0, R1)
    instr_mem[pc++] = encode_R(OPC_ENC, 2, 1);

    // ST R2, 2(R0)    ; store ciphertext to data[2]
    instr_mem[pc++] = encode_I(OPC_ST, 2, 0, 2);

    // DEC R3, R2      ; decrypt
    instr_mem[pc++] = encode_R(OPC_DEC, 3, 2);

    // ST R3, 3(R0)    ; store decrypted text to data[3]
    instr_mem[pc++] = encode_I(OPC_ST, 3, 0, 3);

    // NOP (end)
    instr_mem[pc++] = (OPC_NOP << 12);

    program_size = pc;
}
