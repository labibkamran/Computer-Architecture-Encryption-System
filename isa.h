#ifndef ISA_H
#define ISA_H

#include <stdint.h>
#include <stdbool.h>

typedef enum {
    OPC_LD   = 0x0,
    OPC_ST   = 0x1,
    OPC_ADDI = 0x2,
    OPC_LDK  = 0x3,
    OPC_ENC  = 0x4,
    OPC_DEC  = 0x5,
    OPC_BNE  = 0x6,
    OPC_NOP  = 0xF
} Opcode;

#define NUM_REGS       8
#define INSTR_MEM_SIZE 256
#define DATA_MEM_SIZE  1024

typedef struct {
    uint16_t R[NUM_REGS];
    uint16_t K0;
    uint16_t K1;
    uint16_t PC;
} CpuState;

typedef struct {
    uint16_t raw;
    uint8_t  opcode;
    uint8_t  f1;
    uint8_t  f2;
    uint8_t  f3;
    int8_t   imm6;
} DecodedInstr;

#endif // ISA_H
