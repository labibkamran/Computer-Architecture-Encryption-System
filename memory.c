#include "memory.h"

uint16_t instr_mem[INSTR_MEM_SIZE];
uint16_t data_mem[DATA_MEM_SIZE];

void init_memory(void) {
    for (int i = 0; i < INSTR_MEM_SIZE; i++) {
        instr_mem[i] = 0;
    }
    for (int i = 0; i < DATA_MEM_SIZE; i++) {
        data_mem[i] = 0;
    }
}
