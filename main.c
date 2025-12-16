#include <stdio.h>
#include "isa.h"
#include "memory.h"
#include "crypto.h"
#include "cpu_pipe.h"

// Functions from other files
void init_cpu(CpuState *cpu);
void step_single(CpuState *cpu);
void load_single_block_program(void);
extern int program_size;

int main(void) {
    CpuState cpu;

    init_cpu(&cpu);
    load_single_block_program();

    int max_cycles = 50;

    printf("Starting single-cycle simulation...\n\n");

    for (int cycle = 0; cycle < max_cycles && cpu.PC < program_size; cycle++) {
        printf("Cycle %2d: PC = %u\n", cycle, cpu.PC);
        step_single(&cpu);
    }

    printf("\n--- Pipeline test  ---\n");
    PipeCpu pcpu;

    load_single_block_program();  // reuse same program + data
    init_pipe_cpu(&pcpu);

    for (int i = 0; i < 12; i++) {
        print_pipe_state(&pcpu);
        step_pipe(&pcpu);
    }


    printf("\nFinal CPU state:\n");
    printf("K0 = 0x%04X\n", cpu.K0);
    printf("R1 (plaintext)      = 0x%04X\n", cpu.R[1]);
    printf("R2 (ciphertext)     = 0x%04X\n", cpu.R[2]);
    printf("R3 (decrypted text) = 0x%04X\n", cpu.R[3]);

    printf("\nData memory:\n");
    printf("data[0] key        = 0x%04X\n", data_mem[0]);
    printf("data[1] plaintext  = 0x%04X\n", data_mem[1]);
    printf("data[2] ciphertext = 0x%04X\n", data_mem[2]);
    printf("data[3] decrypted  = 0x%04X\n", data_mem[3]);

    return 0;
}
