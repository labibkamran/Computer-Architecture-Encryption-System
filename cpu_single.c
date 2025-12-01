#include <stdio.h>
#include "isa.h"
#include "memory.h"
#include "crypto.h"

// Initialise CPU registers
void init_cpu(CpuState *cpu) {
    cpu->PC = 0;
    cpu->K0 = 0;
    cpu->K1 = 0;
    for (int i = 0; i < NUM_REGS; i++) {
        cpu->R[i] = 0;
    }
}

// Decode 16-bit instruction into fields
DecodedInstr decode(uint16_t raw) {
    DecodedInstr d;
    d.raw    = raw;
    d.opcode = (raw >> 12) & 0xF;
    d.f1     = (raw >> 9) & 0x7;   // bits 11-9
    d.f2     = (raw >> 6) & 0x7;   // bits 8-6
    d.f3     = (raw >> 3) & 0x7;   // bits 5-3

    uint8_t imm6 = raw & 0x3F;     // bits 5-0
    if (imm6 & 0x20) {
        // sign-extend 6-bit -> 8-bit then to int8
        d.imm6 = (int8_t)(imm6 | 0xC0);
    } else {
        d.imm6 = (int8_t)imm6;
    }
    return d;
}

// Execute one instruction (single-cycle model)
void step_single(CpuState *cpu) {
    uint16_t raw = instr_mem[cpu->PC];
    DecodedInstr d = decode(raw);

    // default PC = PC + 1 (may change for branch)
    cpu->PC++;

    switch (d.opcode) {

    case OPC_LD: {
        uint8_t rt = d.f1;
        uint8_t rs = d.f2;
        uint16_t ea = (uint16_t)(cpu->R[rs] + d.imm6);
        cpu->R[rt] = data_mem[ea];
        break;
    }

    case OPC_ST: {
        uint8_t rt = d.f1;
        uint8_t rs = d.f2;
        uint16_t ea = (uint16_t)(cpu->R[rs] + d.imm6);
        data_mem[ea] = cpu->R[rt];
        break;
    }

    case OPC_ADDI: {
        uint8_t rt = d.f1;
        uint8_t rs = d.f2;
        cpu->R[rt] = (uint16_t)(cpu->R[rs] + d.imm6);
        break;
    }

    case OPC_LDK: {
        uint8_t rt = d.f1;  // 6 -> K0, 7 -> K1
        uint8_t rs = d.f2;
        uint16_t ea = (uint16_t)(cpu->R[rs] + d.imm6);
        uint16_t key_val = data_mem[ea];
        if (rt == 6) cpu->K0 = key_val;
        else if (rt == 7) cpu->K1 = key_val;
        break;
    }

    case OPC_ENC: {
        uint8_t rd = d.f1;
        uint8_t rs = d.f2;
        uint16_t in = cpu->R[rs];
        cpu->R[rd] = enc_func(in, cpu->K0, cpu->K1);
        break;
    }

    case OPC_DEC: {
        uint8_t rd = d.f1;
        uint8_t rs = d.f2;
        uint16_t in = cpu->R[rs];
        cpu->R[rd] = dec_func(in, cpu->K0, cpu->K1);
        break;
    }

    case OPC_BNE: {
        uint8_t rs1 = d.f1;
        uint8_t rs2 = d.f2;
        if (cpu->R[rs1] != cpu->R[rs2]) {
            cpu->PC = (uint16_t)(cpu->PC + d.imm6);
        }
        break;
    }

    case OPC_NOP:
    default:
        // do nothing
        break;
    }
}
