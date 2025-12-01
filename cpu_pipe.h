#ifndef CPU_PIPE_H
#define CPU_PIPE_H

#include <stdbool.h>
#include "isa.h"

// ---- Pipeline register structs ----

// IF/ID: carries raw instruction + PC from fetch to decode
typedef struct {
    uint16_t instr;  // raw 16-bit instruction
    uint16_t pc;     // PC of this instruction
} IF_ID;

// ID/EX: carries decoded instruction + operand values
typedef struct {
    DecodedInstr d;  // decoded instruction (opcode, fields, imm)
    uint16_t pc;     // PC of this instruction
    uint16_t rs_val;   // value of rs    (f2)
    uint16_t rs2_val;  // value of rs2   (f3) - for ST/BNE
} ID_EX;

// EX/MEM: carries ALU results, branch info, and store data
typedef struct {
    DecodedInstr d;
    uint16_t pc;
    uint16_t alu_result;    // EA for LD/ST, result for ADDI/ENC/DEC/LDK
    uint16_t rs2_val;       // store data for ST
    bool     branch_taken;
    uint16_t branch_target;
} EX_MEM;

// MEM/WB: carries data to be written back
typedef struct {
    DecodedInstr d;
    uint16_t pc;
    uint16_t write_val;   // value to write back to reg / key
} MEM_WB;

// Full pipelined CPU state
typedef struct {
    CpuState core;  // architectural state: regs, keys, PC

    IF_ID  if_id;
    ID_EX  id_ex;
    EX_MEM ex_mem;
    MEM_WB mem_wb;

    int cycle;      // current cycle number (for printing)
} PipeCpu;

// Initialise pipeline CPU (clear registers + pipeline regs)
void init_pipe_cpu(PipeCpu *cpu);

// Simulate one pipeline clock cycle
void step_pipe(PipeCpu *cpu);

// Print which instruction is in IF/ID/EX/MEM/WB for this cycle
void print_pipe_state(const PipeCpu *cpu);

#endif // CPU_PIPE_H
