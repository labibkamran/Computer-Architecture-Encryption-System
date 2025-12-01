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
