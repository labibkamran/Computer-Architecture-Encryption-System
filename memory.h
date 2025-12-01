#ifndef MEMORY_H
#define MEMORY_H

#include <stdint.h>
#include "isa.h"


extern uint16_t instr_mem[INSTR_MEM_SIZE];
extern uint16_t data_mem[DATA_MEM_SIZE];

// Initialise memories (clear to 0)
void init_memory(void);

#endif // MEMORY_H
