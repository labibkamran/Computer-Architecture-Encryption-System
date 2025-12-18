#include <stdio.h>
#include <stdbool.h>
#include "cpu_pipe.h"
#include "memory.h"
#include "crypto.h"

extern void init_cpu(CpuState *cpu);
extern DecodedInstr decode(uint16_t raw);

static int is_nop_instr(uint16_t raw) {
    return ((raw >> 12) & 0xF) == OPC_NOP;
}

static const char* opcode_name(uint8_t op) {
    switch (op) {
        case OPC_LD:   return "LD";
        case OPC_ST:   return "ST";
        case OPC_ADDI: return "ADDI";
        case OPC_LDK:  return "LDK";
        case OPC_ENC:  return "ENC";
        case OPC_DEC:  return "DEC";
        case OPC_BNE:  return "BNE";
        case OPC_HLT:  return "HLT";
        case OPC_NOP:  return "NOP";
        default:       return "???";
    }
}

void init_pipe_cpu(PipeCpu *cpu) {
    init_cpu(&cpu->core);
    cpu->cycle = 0;

    cpu->if_id.instr = (OPC_NOP << 12);
    cpu->if_id.pc    = 0;

    cpu->id_ex.d.opcode  = OPC_NOP;
    cpu->id_ex.pc        = 0;
    cpu->id_ex.rs_val    = 0;
    cpu->id_ex.rs2_val   = 0;

    cpu->ex_mem.d.opcode = OPC_NOP;
    cpu->ex_mem.pc       = 0;
    cpu->ex_mem.alu_result = 0;
    cpu->ex_mem.rs2_val    = 0;
    cpu->ex_mem.branch_taken  = false;
    cpu->ex_mem.branch_target = 0;

    cpu->mem_wb.d.opcode = OPC_NOP;
    cpu->mem_wb.pc       = 0;
    cpu->mem_wb.write_val = 0;
}

void print_pipe_state(const PipeCpu *cpu) {
    printf("Cycle %2d | IF: %-4s | ID: %-4s | EX: %-4s | MEM: %-4s | WB: %-4s\n",
           cpu->cycle,
           opcode_name((cpu->if_id.instr >> 12) & 0xF),
           opcode_name(cpu->id_ex.d.opcode),
           opcode_name(cpu->ex_mem.d.opcode),
           opcode_name(cpu->mem_wb.d.opcode),
           opcode_name(cpu->mem_wb.d.opcode));
}

static uint16_t forward_val(const PipeCpu *cpu, const EX_MEM *ex_mem, const MEM_WB *mem_wb, uint8_t reg) {
    if ((ex_mem->d.opcode == OPC_ADDI || ex_mem->d.opcode == OPC_ENC || ex_mem->d.opcode == OPC_DEC) && ex_mem->d.f1 == reg) {
        return ex_mem->alu_result;
    }
    if ((mem_wb->d.opcode == OPC_LD || mem_wb->d.opcode == OPC_ADDI || mem_wb->d.opcode == OPC_ENC || mem_wb->d.opcode == OPC_DEC || mem_wb->d.opcode == OPC_LDK) && mem_wb->d.f1 == reg) {
        return mem_wb->write_val;
    }
    return cpu->core.R[reg];
}

void step_pipe(PipeCpu *cpu) {
    cpu->cycle++;

    if (cpu->core.PC >= INSTR_MEM_SIZE) {
        cpu->core.PC = INSTR_MEM_SIZE;
        return;
    }

    MEM_WB mem_wb_prev = cpu->mem_wb;
    EX_MEM ex_mem_prev = cpu->ex_mem;

    // WRITE-BACK
    DecodedInstr wb = mem_wb_prev.d;
    if (wb.opcode == OPC_LD || wb.opcode == OPC_ADDI || wb.opcode == OPC_ENC || wb.opcode == OPC_DEC) {
        cpu->core.R[wb.f1] = mem_wb_prev.write_val;
    } else if (wb.opcode == OPC_LDK) {
        if (wb.f1 == 6) cpu->core.K0 = mem_wb_prev.write_val;
        else if (wb.f1 == 7) cpu->core.K1 = mem_wb_prev.write_val;
    }

    // MEM stage
    MEM_WB next_wb = mem_wb_prev;
    next_wb.d = ex_mem_prev.d;
    next_wb.pc = ex_mem_prev.pc;
    next_wb.write_val = 0;

    switch (ex_mem_prev.d.opcode) {
        case OPC_LD:
        case OPC_LDK:
            if (ex_mem_prev.alu_result >= DATA_MEM_SIZE) { cpu->core.PC = INSTR_MEM_SIZE; return; }
            next_wb.write_val = data_mem[ex_mem_prev.alu_result];
            break;
        case OPC_ST:
            if (ex_mem_prev.alu_result >= DATA_MEM_SIZE) { cpu->core.PC = INSTR_MEM_SIZE; return; }
            data_mem[ex_mem_prev.alu_result] = ex_mem_prev.rs2_val;
            break;
        case OPC_ADDI:
        case OPC_ENC:
        case OPC_DEC:
            next_wb.write_val = ex_mem_prev.alu_result;
            break;
        default:
            break;
    }
    cpu->mem_wb = next_wb;

    // EX stage
    ID_EX prev_id = cpu->id_ex;
    EX_MEM next_ex;
    next_ex.d = prev_id.d;
    next_ex.pc = prev_id.pc;
    next_ex.rs2_val = prev_id.rs2_val;
    next_ex.branch_taken = false;
    next_ex.branch_target = cpu->core.PC;
    next_ex.alu_result = 0;

    switch (prev_id.d.opcode) {
        case OPC_LD:
        case OPC_ST:
        case OPC_ADDI:
        case OPC_LDK:
            next_ex.alu_result = (uint16_t)(prev_id.rs_val + prev_id.d.imm6);
            break;
        case OPC_ENC:
            next_ex.alu_result = enc_func(prev_id.rs_val, cpu->core.K0, cpu->core.K1);
            break;
        case OPC_DEC:
            next_ex.alu_result = dec_func(prev_id.rs_val, cpu->core.K0, cpu->core.K1);
            break;
        case OPC_BNE:
            if (prev_id.rs_val != prev_id.rs2_val) {
                next_ex.branch_taken = true;
                next_ex.branch_target = (uint16_t)(prev_id.pc + 1 + prev_id.d.imm6); // PC+1 semantics
            }
            break;
        case OPC_HLT:
            next_ex.branch_taken = true;
            next_ex.branch_target = INSTR_MEM_SIZE;
            break;
        default:
            break;
    }

    if (next_ex.branch_taken) {
        cpu->core.PC = next_ex.branch_target;
    }
    cpu->ex_mem = next_ex;

    // Hazard detection (load-use)
    bool stall = false;
    IF_ID prev_if = cpu->if_id;
    if (!is_nop_instr(prev_if.instr)) {
        DecodedInstr idd = decode(prev_if.instr);
        uint8_t s1 = idd.f2;
        uint8_t s2 = idd.f3;
        if (idd.opcode == OPC_BNE) { s1 = idd.f1; s2 = idd.f2; }
        if (ex_mem_prev.d.opcode == OPC_LD) {
            uint8_t ld_rd = ex_mem_prev.d.f1;
            if (ld_rd == s1 || ld_rd == s2) stall = true;
        }
    }

    // ID stage
    ID_EX next_id = cpu->id_ex;
    if (stall) {
        next_id.d.opcode = OPC_NOP;
        next_id.rs_val = 0;
        next_id.rs2_val = 0;
        next_id.pc = prev_if.pc;
    } else {
        if (is_nop_instr(prev_if.instr)) {
            next_id.d.opcode = OPC_NOP;
            next_id.rs_val = 0;
            next_id.rs2_val = 0;
            next_id.pc = prev_if.pc;
        } else {
            DecodedInstr d = decode(prev_if.instr);
            next_id.d = d;
            next_id.pc = prev_if.pc;
            if (d.opcode == OPC_BNE) {
                next_id.rs_val  = forward_val(cpu, &ex_mem_prev, &mem_wb_prev, d.f1);
                next_id.rs2_val = forward_val(cpu, &ex_mem_prev, &mem_wb_prev, d.f2);
            } else if (d.opcode == OPC_ST) {
                next_id.rs_val  = forward_val(cpu, &ex_mem_prev, &mem_wb_prev, d.f2);
                next_id.rs2_val = forward_val(cpu, &ex_mem_prev, &mem_wb_prev, d.f1);
            } else {
                next_id.rs_val  = forward_val(cpu, &ex_mem_prev, &mem_wb_prev, d.f2);
                next_id.rs2_val = forward_val(cpu, &ex_mem_prev, &mem_wb_prev, d.f3);
            }
        }
    }
    cpu->id_ex = next_id;

    // IF stage
    IF_ID next_if;
    next_if.pc = cpu->core.PC;
    if (cpu->core.PC >= INSTR_MEM_SIZE) {
        next_if.instr = (OPC_HLT << 12);
    } else {
        next_if.instr = instr_mem[cpu->core.PC];
    }

    if (!stall) {
        cpu->if_id = next_if;
        cpu->core.PC++;
    }
}

