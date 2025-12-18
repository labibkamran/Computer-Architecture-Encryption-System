#include <stdio.h>
#include "isa.h"
#include "memory.h"
#include "crypto.h"
extern int program_size;

void init_cpu(CpuState *cpu) {
    cpu->PC = 0;
    cpu->K0 = 0;
    cpu->K1 = 0;
    for (int i = 0; i < NUM_REGS; i++) {
        cpu->R[i] = 0;
    }
}

DecodedInstr decode(uint16_t raw) {
    DecodedInstr d;
    d.raw    = raw;
    d.opcode = (raw >> 12) & 0xF;
    d.f1     = (raw >> 9) & 0x7;
    d.f2     = (raw >> 6) & 0x7;
    d.f3     = (raw >> 3) & 0x7;
    uint8_t imm6 = raw & 0x3F;
    d.imm6 = (imm6 & 0x20) ? (int8_t)(imm6 | 0xC0) : (int8_t)imm6;
    return d;
}

static int check_ea(uint16_t ea, const char *op) {
    if (ea >= DATA_MEM_SIZE) {
        fprintf(stderr, "Memory OOB in %s: EA=0x%04X (limit %d)\n", op, ea, DATA_MEM_SIZE);
        return 0;
    }
    return 1;
}

void step_single(CpuState *cpu) {
    if (cpu->PC >= INSTR_MEM_SIZE || cpu->PC >= program_size) {
        cpu->PC = INSTR_MEM_SIZE;
        return;
    }

    uint16_t raw = instr_mem[cpu->PC];
    DecodedInstr d = decode(raw);

    cpu->PC++;

    switch (d.opcode) {
        case OPC_LD: {
            uint16_t ea = (uint16_t)(cpu->R[d.f2] + d.imm6);
            if (!check_ea(ea, "LD")) { cpu->PC = INSTR_MEM_SIZE; return; }
            cpu->R[d.f1] = data_mem[ea];
            break;
        }
        case OPC_ST: {
            uint16_t ea = (uint16_t)(cpu->R[d.f2] + d.imm6);
            if (!check_ea(ea, "ST")) { cpu->PC = INSTR_MEM_SIZE; return; }
            data_mem[ea] = cpu->R[d.f1];
            break;
        }
        case OPC_ADDI:
            cpu->R[d.f1] = (uint16_t)(cpu->R[d.f2] + d.imm6);
            break;
        case OPC_LDK: {
            uint16_t ea = (uint16_t)(cpu->R[d.f2] + d.imm6);
            if (!check_ea(ea, "LDK")) { cpu->PC = INSTR_MEM_SIZE; return; }
            uint16_t key_val = data_mem[ea];
            if (d.f1 == 6) cpu->K0 = key_val;
            else if (d.f1 == 7) cpu->K1 = key_val;
            break;
        }
        case OPC_ENC:
            cpu->R[d.f1] = enc_func(cpu->R[d.f2], cpu->K0, cpu->K1);
            break;
        case OPC_DEC:
            cpu->R[d.f1] = dec_func(cpu->R[d.f2], cpu->K0, cpu->K1);
            break;
        case OPC_BNE:
            if (cpu->R[d.f1] != cpu->R[d.f2]) {
                cpu->PC = (uint16_t)(cpu->PC + d.imm6); // PC already incremented (PC+1 semantics)
            }
            break;
        case OPC_HLT:
            cpu->PC = INSTR_MEM_SIZE;
            return;
        case OPC_NOP:
        default:
            break;
    }
}
