#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "isa.h"
#include "memory.h"
#include "crypto.h"
#include "cpu_pipe.h"

// External functions
void init_cpu(CpuState *cpu);
void step_single(CpuState *cpu);
DecodedInstr decode(uint16_t raw);
void build_streaming_program(void);
int load_chunk_words(uint16_t key, const uint16_t *words, int blocks);
extern int program_size;

static const char *opcode_name(uint8_t op) {
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

static int read_key16(const char *path, uint16_t *out_key) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    unsigned char kbuf[2] = {0,0};
    size_t n = fread(kbuf, 1, 2, f);
    fclose(f);
    if (n == 0) return 0;
    *out_key = (uint16_t)((kbuf[0] << 8) | (n > 1 ? kbuf[1] : 0));
    return 1;
}

static int pack_words(const unsigned char *bytes, size_t len, uint16_t *out_words, int max_words) {
    int blocks = 0;
    size_t idx = 0;
    while (idx < len && blocks < max_words) {
        unsigned char b0 = bytes[idx++];
        unsigned char b1 = (idx < len) ? bytes[idx++] : 0;
        out_words[blocks++] = (uint16_t)((b0 << 8) | b1);
    }
    return blocks;
}

static int pipeline_empty(const PipeCpu *p) {
    uint8_t if_op = (p->if_id.instr >> 12) & 0xF;
    return ((if_op == OPC_NOP || if_op == OPC_HLT) &&
            (p->id_ex.d.opcode == OPC_NOP || p->id_ex.d.opcode == OPC_HLT) &&
            (p->ex_mem.d.opcode == OPC_NOP || p->ex_mem.d.opcode == OPC_HLT) &&
            (p->mem_wb.d.opcode == OPC_NOP || p->mem_wb.d.opcode == OPC_HLT));
}

static void log_trace(FILE *fp, const char *sim, int chunk, int cycle, uint16_t pc, double t_ns,
                      const char *if_s, const char *id_s, const char *ex_s, const char *mem_s, const char *wb_s,
                      const char *extra) {
    if (!fp) return;
    fprintf(fp,
            "{\"sim\":\"%s\",\"chunk\":%d,\"cycle\":%d,\"pc\":%u,\"t\":%.3f,\"if\":\"%s\",\"id\":\"%s\",\"ex\":\"%s\",\"mem\":\"%s\",\"wb\":\"%s\"%s}\n",
            sim, chunk, cycle, pc, t_ns, if_s, id_s, ex_s, mem_s, wb_s, extra ? extra : "");
}

static int run_single_cycle(int max_cycles, int verbose, int *inst_out, int chunk_idx, FILE *trace_fp, double t_clk_ns) {
    CpuState cpu;
    init_cpu(&cpu);
    int cycles = 0;
    int insts = 0;

    while (cpu.PC < program_size && cycles < max_cycles) {
        uint16_t pc_before = cpu.PC;
        uint16_t raw = instr_mem[pc_before];
        DecodedInstr d = decode(raw);
        char extra[256]; extra[0] = '\0';
        uint16_t ea = 0, before = 0, after = 0, wb_val = 0;
        if (d.opcode == OPC_LD || d.opcode == OPC_ST || d.opcode == OPC_LDK) {
            ea = (uint16_t)(cpu.R[d.f2] + d.imm6);
            before = (ea < DATA_MEM_SIZE) ? data_mem[ea] : 0;
        }
        if (verbose) {
            printf("[SC] cycle %3d PC=%3u OPC=%-4s\n", cycles, pc_before, opcode_name(d.opcode));
        }
        log_trace(trace_fp, "single", chunk_idx, cycles, pc_before, cycles * t_clk_ns,
                  opcode_name(d.opcode), opcode_name(d.opcode), opcode_name(d.opcode), opcode_name(d.opcode), opcode_name(d.opcode),
                  extra[0] ? extra : NULL);

        step_single(&cpu);

        switch (d.opcode) {
            case OPC_LD:
                after = (ea < DATA_MEM_SIZE) ? data_mem[ea] : 0;
                wb_val = cpu.R[d.f1];
                snprintf(extra, sizeof(extra),
                         ",\"mem\":{\"op\":\"LD\",\"ea\":%u,\"before\":%u,\"after\":%u},\"wb\":{\"dest\":\"R%u\",\"val\":%u}",
                         ea, before, after, d.f1, wb_val);
                break;
            case OPC_ST:
                after = (ea < DATA_MEM_SIZE) ? data_mem[ea] : 0;
                snprintf(extra, sizeof(extra),
                         ",\"mem\":{\"op\":\"ST\",\"ea\":%u,\"before\":%u,\"after\":%u,\"val\":%u}",
                         ea, before, after, cpu.R[d.f1]);
                break;
            case OPC_LDK:
                after = (ea < DATA_MEM_SIZE) ? data_mem[ea] : 0;
                wb_val = (d.f1 == 6) ? cpu.K0 : cpu.K1;
                snprintf(extra, sizeof(extra),
                         ",\"mem\":{\"op\":\"LDK\",\"ea\":%u,\"before\":%u},\"wb\":{\"dest\":\"K%u\",\"val\":%u}",
                         ea, before, d.f1 - 6, wb_val);
                break;
            case OPC_ADDI:
            case OPC_ENC:
            case OPC_DEC:
                wb_val = cpu.R[d.f1];
                snprintf(extra, sizeof(extra),
                         ",\"wb\":{\"dest\":\"R%u\",\"val\":%u}", d.f1, wb_val);
                break;
            default:
                extra[0] = '\0';
                break;
        }
        if (trace_fp && extra[0]) {
            // Add a second log line capturing the effects (WB/memory) for this instruction.
            log_trace(trace_fp, "single", chunk_idx, cycles, pc_before, cycles * t_clk_ns,
                      opcode_name(d.opcode), "-", "-", "-", "-",
                      extra);
        }
        insts++;
        cycles++;
    }
    if (inst_out) *inst_out = insts;
    double cpi = insts > 0 ? (double)cycles / (double)insts : 0.0;
    printf("Single-cycle: cycles=%d CPI=%.2f\n", cycles, cpi);
    return cycles;
}

static int run_pipeline(int max_cycles, int verbose, int *inst_out, int chunk_idx, FILE *trace_fp, double t_clk_ns) {
    PipeCpu pcpu;
    init_pipe_cpu(&pcpu);
    int cycles = 0;
    int retired = 0;

    while ((pcpu.core.PC < program_size || !pipeline_empty(&pcpu)) && cycles < max_cycles) {
        const char *if_s  = opcode_name((pcpu.if_id.instr >> 12) & 0xF);
        const char *id_s  = opcode_name(pcpu.id_ex.d.opcode);
        const char *ex_s  = opcode_name(pcpu.ex_mem.d.opcode);
        const char *mem_s = opcode_name(pcpu.ex_mem.d.opcode);
        const char *wb_s  = opcode_name(pcpu.mem_wb.d.opcode);

        char extra[256];
        extra[0] = '\0';
        int off = 0;

        // Mem stage effects (address computed in EX/MEM)
        if (pcpu.ex_mem.d.opcode == OPC_LD || pcpu.ex_mem.d.opcode == OPC_ST || pcpu.ex_mem.d.opcode == OPC_LDK) {
            uint16_t ea = pcpu.ex_mem.alu_result;
            uint16_t before = (ea < DATA_MEM_SIZE) ? data_mem[ea] : 0;
            if (pcpu.ex_mem.d.opcode == OPC_ST) {
                uint16_t after = pcpu.ex_mem.rs2_val;
                off += snprintf(extra + off, sizeof(extra) - off,
                                 ",\"mem\":{\"op\":\"ST\",\"ea\":%u,\"before\":%u,\"after\":%u,\"val\":%u}",
                                 ea, before, after, pcpu.ex_mem.rs2_val);
            } else {
                uint16_t after = before; // loads do not modify memory
                off += snprintf(extra + off, sizeof(extra) - off,
                                 ",\"mem\":{\"op\":\"%s\",\"ea\":%u,\"before\":%u,\"after\":%u}",
                                 (pcpu.ex_mem.d.opcode == OPC_LD ? "LD" : "LDK"), ea, before, after);
            }
        }

        // WB stage effects (writeback already computed in mem_wb)
        DecodedInstr wb = pcpu.mem_wb.d;
        if (wb.opcode == OPC_LD || wb.opcode == OPC_ADDI || wb.opcode == OPC_ENC || wb.opcode == OPC_DEC) {
            off += snprintf(extra + off, sizeof(extra) - off,
                             ",\"wb\":{\"dest\":\"R%u\",\"val\":%u}", wb.f1, pcpu.mem_wb.write_val);
        } else if (wb.opcode == OPC_LDK) {
            off += snprintf(extra + off, sizeof(extra) - off,
                             ",\"wb\":{\"dest\":\"K%u\",\"val\":%u}", wb.f1 - 6, pcpu.mem_wb.write_val);
        }

        if (verbose) {
            printf("[PL] cycle %3d PC=%3u IF=%-4s ID=%-4s EX=%-4s MEM=%-4s WB=%-4s\n",
                   cycles, pcpu.core.PC, if_s, id_s, ex_s, mem_s, wb_s);
        }
        if (wb.opcode != OPC_NOP && wb.opcode != OPC_HLT) retired++;

        log_trace(trace_fp, "pipeline", chunk_idx, cycles, pcpu.core.PC, cycles * t_clk_ns, if_s, id_s, ex_s, mem_s, wb_s,
                  extra[0] ? extra : NULL);

        step_pipe(&pcpu);
        cycles++;
    }
    if (inst_out) *inst_out = retired;
    printf("Pipeline:     cycles=%d (retired=%d)\n", cycles, retired);
    return cycles;
}

int main(int argc, char **argv) {
    const char *key_path = "key.txt";
    const char *input_path = "input.txt";
    const char *trace_path = NULL;
    int verbose = 0;
    double t_single_ns = 5.0; // assumed single-cycle clock period (ns)
    double t_pipe_ns   = 1.0; // assumed pipeline clock period (ns)

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) key_path = argv[++i];
        else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) input_path = argv[++i];
        else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) trace_path = argv[++i];
        else if (strcmp(argv[i], "-v") == 0) verbose = 1;
        else if (strcmp(argv[i], "--t-single") == 0 && i + 1 < argc) t_single_ns = strtod(argv[++i], NULL);
        else if (strcmp(argv[i], "--t-pipe") == 0 && i + 1 < argc)   t_pipe_ns   = strtod(argv[++i], NULL);
    }

    FILE *trace_fp = NULL;
    if (trace_path) {
        trace_fp = fopen(trace_path, "w");
        if (!trace_fp) {
            fprintf(stderr, "Failed to open trace file %s\n", trace_path);
            return 1;
        }
    }

    uint16_t key16 = 0;
    if (!read_key16(key_path, &key16)) {
        fprintf(stderr, "Failed to read key from %s\n", key_path);
        if (trace_fp) fclose(trace_fp);
        return 1;
    }

    FILE *in = fopen(input_path, "rb");
    if (!in) {
        fprintf(stderr, "Failed to open input %s\n", input_path);
        if (trace_fp) fclose(trace_fp);
        return 1;
    }

    const int max_blocks = (DATA_MEM_SIZE - PLAIN_BASE) / 2;
    const size_t chunk_bytes = (size_t)max_blocks * 2;
    unsigned char *buf = malloc(chunk_bytes);
    uint16_t *words = malloc(max_blocks * sizeof(uint16_t));
    if (!buf || !words) {
        fprintf(stderr, "Out of memory\n");
        fclose(in);
        if (trace_fp) fclose(trace_fp);
        free(buf); free(words);
        return 1;
    }

    size_t total_bytes = 0;
    int chunk_idx = 0;
    long total_cycles_sc = 0;
    long total_cycles_pl = 0;
    long total_insts_sc = 0;
    long total_insts_pl = 0;

    while (1) {
        size_t n = fread(buf, 1, chunk_bytes, in);
        if (n == 0) break;
        total_bytes += n;

        int blocks = pack_words(buf, n, words, max_blocks);
        blocks = load_chunk_words(key16, words, blocks);
        int max_cycles = program_size + 8 * blocks + 10;

        printf("\n--- Chunk %d: blocks=%d bytes=%zu ---\n", chunk_idx, blocks, n);
        int inst_sc = 0, inst_pl = 0;
        int c_sc = run_single_cycle(max_cycles, verbose, &inst_sc, chunk_idx, trace_fp, t_single_ns);
        int c_pl = run_pipeline(max_cycles, verbose, &inst_pl, chunk_idx, trace_fp, t_pipe_ns);
        total_cycles_sc += c_sc;
        total_cycles_pl += c_pl;
        total_insts_sc += inst_sc;
        total_insts_pl += inst_pl;

        printf("Ciphertext (hex words): ");
        for (int i = 0; i < blocks; i++) {
            uint16_t ct = data_mem[PLAIN_BASE + blocks + i];
            printf("%04X ", ct);
        }
        printf("\n");

        printf("Ciphertext bytes (hex): ");
        for (size_t i = 0; i < n; i++) {
            uint16_t w = data_mem[PLAIN_BASE + blocks + (i / 2)];
            unsigned char c = (i % 2 == 0) ? (unsigned char)(w >> 8) : (unsigned char)(w & 0xFF);
            printf("%02X", c);
        }
        printf("\nCiphertext text     : ");
        for (size_t i = 0; i < n; i++) {
            uint16_t w = data_mem[PLAIN_BASE + blocks + (i / 2)];
            unsigned char c = (i % 2 == 0) ? (unsigned char)(w >> 8) : (unsigned char)(w & 0xFF);
            if (c >= 32 && c <= 126) {
                printf("%c", c);
            } else {
                printf("\\x%02X", c);
            }
        }
        printf("\n");

        printf("Decrypted bytes (hex): ");
        for (size_t i = 0; i < n; i++) {
            uint16_t w = data_mem[PLAIN_BASE + (i / 2)];
            unsigned char c = (i % 2 == 0) ? (unsigned char)(w >> 8) : (unsigned char)(w & 0xFF);
            printf("%02X", c);
        }
        printf("\nDecrypted text     : ");
        for (size_t i = 0; i < n; i++) {
            uint16_t w = data_mem[PLAIN_BASE + (i / 2)];
            unsigned char c = (i % 2 == 0) ? (unsigned char)(w >> 8) : (unsigned char)(w & 0xFF);
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        printf("\n");

        chunk_idx++;
    }

    printf("\nProcessed %zu bytes from %s (key=0x%04X)\n", total_bytes, input_path, key16);
    printf("Total cycles: single-cycle=%ld (insts=%ld), pipeline=%ld (retired=%ld)\n", total_cycles_sc, total_insts_sc, total_cycles_pl, total_insts_pl);
    double time_single_ns = total_cycles_sc * t_single_ns;
    double time_pipe_ns   = total_cycles_pl * t_pipe_ns;
    if (time_pipe_ns > 0.0) {
        printf("Assumed timing: single=%.3f ns, pipeline=%.3f ns, speedup=%.2fx\n",
               time_single_ns, time_pipe_ns, time_single_ns / time_pipe_ns);
    }

    free(buf);
    free(words);
    fclose(in);
    if (trace_fp) fclose(trace_fp);
    return 0;
}
