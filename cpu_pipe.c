#include <stdio.h>
#include "cpu_pipe.h"
#include "memory.h"
#include "crypto.h"

// We reuse these from cpu_single.c
extern void init_cpu(CpuState *cpu);
extern DecodedInstr decode(uint16_t raw);

// helper: check if raw instruction is a NOP
static int is_nop_instr(uint16_t raw) {
    return ((raw >> 12) & 0xF) == OPC_NOP;
}

static bool writes_reg(DecodedInstr d) {
    switch (d.opcode) {
        case OPC_LD:
        case OPC_ADDI:
        case OPC_ENC:
        case OPC_DEC:
            return true;
        default:
            return false;
    }
}

static uint8_t dest_reg(DecodedInstr d) {
    return d.f1;
}


// ---- Initialisation ----
void init_pipe_cpu(PipeCpu *cpu) {
    // reset architectural state (regs, keys, PC)
    init_cpu(&cpu->core);

    // reset cycle counter
    cpu->cycle = 0;

    // initialise pipeline registers with NOPs
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

// ---- Pretty-print pipeline state ----

static const char* opcode_name(uint8_t op) {
    switch (op) {
        case OPC_LD:   return "LD";
        case OPC_ST:   return "ST";
        case OPC_ADDI: return "ADDI";
        case OPC_LDK:  return "LDK";
        case OPC_ENC:  return "ENC";
        case OPC_DEC:  return "DEC";
        case OPC_BNE:  return "BNE";
        case OPC_NOP:  return "NOP";
        default:       return "???";
    }
}

void print_pipe_state(const PipeCpu *cpu) {
    printf("Cycle %2d | ", cpu->cycle);

    // IF stage: look at raw instruction in IF/ID
    uint8_t if_op = (cpu->if_id.instr >> 12) & 0xF;
    printf("IF: %-4s | ", opcode_name(if_op));

    // ID stage: opcode in ID/EX
    printf("ID: %-4s | ", opcode_name(cpu->id_ex.d.opcode));

    // EX stage: opcode in EX/MEM
    printf("EX: %-4s | ", opcode_name(cpu->ex_mem.d.opcode));

    // MEM stage: opcode in MEM/WB (we treat this as MEM holder)
    printf("MEM: %-4s | ", opcode_name(cpu->mem_wb.d.opcode));

    // WB: also MEM_WB (instruction currently writing back)
    printf("WB: %-4s\n", opcode_name(cpu->mem_wb.d.opcode));
}

// ---- One pipeline cycle ----

void step_pipe(PipeCpu *cpu) {
    cpu->cycle++;

    // -------------------------------
    // 1. WRITE-BACK stage (MEM_WB)
    // -------------------------------
    DecodedInstr wb = cpu->mem_wb.d;

    if (wb.opcode == OPC_LD || wb.opcode == OPC_ADDI ||
        wb.opcode == OPC_ENC || wb.opcode == OPC_DEC) {

        uint8_t rd = cpu->mem_wb.d.f1; // f1 = rd/rt
        cpu->core.R[rd] = cpu->mem_wb.write_val;

    } else if (wb.opcode == OPC_LDK) {

        uint8_t rt = cpu->mem_wb.d.f1;
        if (rt == 6) {
            cpu->core.K0 = cpu->mem_wb.write_val;
        } else if (rt == 7) {
            cpu->core.K1 = cpu->mem_wb.write_val;
        }
    }
    // ST, BNE, NOP: no WB action

    // -------------------------------
    // 2. MEM stage (EX_MEM -> MEM_WB)
    // -------------------------------
    EX_MEM prev_ex = cpu->ex_mem;
    MEM_WB next_wb;
    next_wb.d         = prev_ex.d;
    next_wb.pc        = prev_ex.pc;
    next_wb.write_val = 0;

    switch (prev_ex.d.opcode) {
        case OPC_LD: {
            // EA already computed in EX
            uint16_t ea = prev_ex.alu_result;
            next_wb.write_val = data_mem[ea];
            break;
        }
        case OPC_ST: {
            uint16_t ea = prev_ex.alu_result;
            data_mem[ea] = prev_ex.rs2_val;
            break;
        }
        case OPC_ADDI:
        case OPC_ENC:
        case OPC_DEC:
        case OPC_LDK:
            next_wb.write_val = prev_ex.alu_result;
            break;
        default:
            break;
    }

    cpu->mem_wb = next_wb;

    // -------------------------------
    // 3. EX stage (ID_EX -> EX_MEM)
    // -------------------------------
    ID_EX prev_id = cpu->id_ex;
    EX_MEM next_ex;
    next_ex.d            = prev_id.d;
    next_ex.pc           = prev_id.pc;
    next_ex.rs2_val      = prev_id.rs2_val;
    next_ex.branch_taken = false;
    next_ex.branch_target= cpu->core.PC; // default, may be overwritten
    next_ex.alu_result   = 0;

    switch (prev_id.d.opcode) {
        case OPC_LD:
        case OPC_ST:
        case OPC_ADDI: {
            /* Forward base register from EX/MEM or MEM/WB when needed */
            uint8_t rs = prev_id.d.f2;
            uint16_t base = prev_id.rs_val;
            if ((cpu->ex_mem.d.opcode == OPC_ADDI || cpu->ex_mem.d.opcode == OPC_ENC || cpu->ex_mem.d.opcode == OPC_DEC || cpu->ex_mem.d.opcode == OPC_LD) && cpu->ex_mem.d.f1 == rs) {
                base = cpu->ex_mem.alu_result;
            } else if ((cpu->mem_wb.d.opcode == OPC_LD || cpu->mem_wb.d.opcode == OPC_ADDI || cpu->mem_wb.d.opcode == OPC_ENC || cpu->mem_wb.d.opcode == OPC_DEC) && cpu->mem_wb.d.f1 == rs) {
                base = cpu->mem_wb.write_val;
            }

            next_ex.alu_result = (uint16_t)(base + prev_id.d.imm6);
            /* For ST we may forward store data below */
            if (prev_id.d.opcode == OPC_ST) {
                /* placeholder: rs2 will be set after switch for ST */
            }
            break;
        }
        case OPC_LDK: {
            uint8_t rs = prev_id.d.f2;
            uint16_t base = prev_id.rs_val;
            if ((cpu->ex_mem.d.opcode == OPC_ADDI || cpu->ex_mem.d.opcode == OPC_ENC || cpu->ex_mem.d.opcode == OPC_DEC || cpu->ex_mem.d.opcode == OPC_LD) && cpu->ex_mem.d.f1 == rs) {
                base = cpu->ex_mem.alu_result;
            } else if ((cpu->mem_wb.d.opcode == OPC_LD || cpu->mem_wb.d.opcode == OPC_ADDI || cpu->mem_wb.d.opcode == OPC_ENC || cpu->mem_wb.d.opcode == OPC_DEC) && cpu->mem_wb.d.f1 == rs) {
                base = cpu->mem_wb.write_val;
            }
            next_ex.alu_result = (uint16_t)(base + prev_id.d.imm6); // EA
            break;
        }
        case OPC_ENC: {
            /* Forward ENC operand from EX/MEM or MEM/WB */
            uint8_t rs = prev_id.d.f2;
            uint16_t in = prev_id.rs_val;
            if ((cpu->ex_mem.d.opcode == OPC_ADDI || cpu->ex_mem.d.opcode == OPC_ENC || cpu->ex_mem.d.opcode == OPC_DEC || cpu->ex_mem.d.opcode == OPC_LD) && cpu->ex_mem.d.f1 == rs) {
                in = cpu->ex_mem.alu_result;
            } else if ((cpu->mem_wb.d.opcode == OPC_LD || cpu->mem_wb.d.opcode == OPC_ADDI || cpu->mem_wb.d.opcode == OPC_ENC || cpu->mem_wb.d.opcode == OPC_DEC) && cpu->mem_wb.d.f1 == rs) {
                in = cpu->mem_wb.write_val;
            }

            /* Forward keys from MEM/WB if LDK just completed there */
            uint16_t k0 = cpu->core.K0;
            uint16_t k1 = cpu->core.K1;
            if (cpu->mem_wb.d.opcode == OPC_LDK) {
                if (cpu->mem_wb.d.f1 == 6) k0 = cpu->mem_wb.write_val;
                else if (cpu->mem_wb.d.f1 == 7) k1 = cpu->mem_wb.write_val;
            }
            next_ex.alu_result = enc_func(in, k0, k1);
            break;
        }
        case OPC_DEC: {
            /* Similar forwarding for DEC */
            uint8_t rs = prev_id.d.f2;
            uint16_t in = prev_id.rs_val;
            if ((cpu->ex_mem.d.opcode == OPC_ADDI || cpu->ex_mem.d.opcode == OPC_ENC || cpu->ex_mem.d.opcode == OPC_DEC || cpu->ex_mem.d.opcode == OPC_LD) && cpu->ex_mem.d.f1 == rs) {
                in = cpu->ex_mem.alu_result;
            } else if ((cpu->mem_wb.d.opcode == OPC_LD || cpu->mem_wb.d.opcode == OPC_ADDI || cpu->mem_wb.d.opcode == OPC_ENC || cpu->mem_wb.d.opcode == OPC_DEC) && cpu->mem_wb.d.f1 == rs) {
                in = cpu->mem_wb.write_val;
            }
            uint16_t k0 = cpu->core.K0;
            uint16_t k1 = cpu->core.K1;
            if (cpu->mem_wb.d.opcode == OPC_LDK) {
                if (cpu->mem_wb.d.f1 == 6) k0 = cpu->mem_wb.write_val;
                else if (cpu->mem_wb.d.f1 == 7) k1 = cpu->mem_wb.write_val;
            }
            next_ex.alu_result = dec_func(in, k0, k1);
            break;
        }
        case OPC_BNE: {
            if (prev_id.rs_val != prev_id.rs2_val) {
                next_ex.branch_taken  = true;
                next_ex.branch_target = (uint16_t)(prev_id.pc + prev_id.d.imm6);
            }
            break;
        }
        default:
            break;
    }

    /* For ST, forward store data if a recent instruction produces it */
    if (prev_id.d.opcode == OPC_ST) {
        uint8_t rt = prev_id.d.f1;
        uint16_t store_data = prev_id.rs2_val;
        if ((cpu->ex_mem.d.opcode == OPC_ADDI || cpu->ex_mem.d.opcode == OPC_ENC || cpu->ex_mem.d.opcode == OPC_DEC || cpu->ex_mem.d.opcode == OPC_LD) && cpu->ex_mem.d.f1 == rt) {
            store_data = cpu->ex_mem.alu_result;
        } else if ((cpu->mem_wb.d.opcode == OPC_LD || cpu->mem_wb.d.opcode == OPC_ADDI || cpu->mem_wb.d.opcode == OPC_ENC || cpu->mem_wb.d.opcode == OPC_DEC || cpu->mem_wb.d.opcode == OPC_LDK) && cpu->mem_wb.d.f1 == rt) {
            store_data = cpu->mem_wb.write_val;
        }
        next_ex.rs2_val = store_data;
    }

    // Update PC if branch taken (no flush logic yet)
    if (next_ex.branch_taken) {
        cpu->core.PC = next_ex.branch_target;
    }

    cpu->ex_mem = next_ex;

    // HAZARD DETECTION
    bool stall = false;

    DecodedInstr ex  = cpu->id_ex.d;
    DecodedInstr mem = cpu->ex_mem.d;
    IF_ID prev_if = cpu->if_id;
    ID_EX next_id;
    next_id.pc = prev_if.pc;

    if (!is_nop_instr(prev_if.instr)) {
        DecodedInstr id = decode(prev_if.instr);
        uint8_t id_rs1 = id.f2;
        uint8_t id_rs2 = id.f3;

        // EX stage is a LD producing a register needed by ID -> stall
        if (ex.opcode == OPC_LD) {
            uint8_t ex_rd = ex.f1;
            if (ex_rd == id_rs1 || ex_rd == id_rs2) {
                stall = true;
            }
        }

        // if LDK is in EX and ID is ENC/DEC, stall until LDK reaches MEM
        if ((id.opcode == OPC_ENC || id.opcode == OPC_DEC) && ex.opcode == OPC_LDK) {
            stall = true;
        }

        // if ID is ST and its rt will be produced by an instruction currently in EX,
        //  stall; forward from EX/MEM or MEM/WB is allowed (no stall) because we read forwarded value at ID time.
        if (id.opcode == OPC_ST) {
            uint8_t rt = id.f1;
            if (writes_reg(ex) && dest_reg(ex) == rt) {
                stall = true;
            }
        }
    }

    // -------------------------------
    // 4. ID stage (IF_ID -> ID_EX)
    // -------------------------------

    if (stall) {
        cpu->id_ex.d.opcode = OPC_NOP;
        cpu->id_ex.rs_val  = 0;
        cpu->id_ex.rs2_val = 0;
    } else {
        if (is_nop_instr(prev_if.instr)) {
            next_id.d.opcode = OPC_NOP;
            next_id.rs_val  = 0;
            next_id.rs2_val = 0;
        } else {
            DecodedInstr d = decode(prev_if.instr);
            next_id.d = d;

            uint8_t rs  = d.f2;
            //  For ST, rs2_val holds the store data (rt = f1) 
            if (d.opcode == OPC_ST) {
                next_id.rs_val  = cpu->core.R[rs];
                uint8_t rt = d.f1;
                // Forward store data at ID time from EX/MEM or MEM/WB if available 
                if ((cpu->ex_mem.d.opcode == OPC_ADDI || cpu->ex_mem.d.opcode == OPC_ENC || cpu->ex_mem.d.opcode == OPC_DEC || cpu->ex_mem.d.opcode == OPC_LD) && cpu->ex_mem.d.f1 == rt) {
                    next_id.rs2_val = cpu->ex_mem.alu_result;
                } else if ((cpu->mem_wb.d.opcode == OPC_LD || cpu->mem_wb.d.opcode == OPC_ADDI || cpu->mem_wb.d.opcode == OPC_ENC || cpu->mem_wb.d.opcode == OPC_DEC || cpu->mem_wb.d.opcode == OPC_LDK) && cpu->mem_wb.d.f1 == rt) {
                    next_id.rs2_val = cpu->mem_wb.write_val;
                } else {
                    next_id.rs2_val = cpu->core.R[rt];
                }
            } else {
                uint8_t rs2 = d.f3;
                next_id.rs_val  = cpu->core.R[rs];
                next_id.rs2_val = cpu->core.R[rs2];
            }
        }
        cpu->id_ex = next_id;
    }




    // -------------------------------
    // 5. IF stage
    // -------------------------------
    IF_ID next_if;
    next_if.pc    = cpu->core.PC;
    next_if.instr = instr_mem[cpu->core.PC];

    if (!stall) {
        cpu->if_id = next_if;
        cpu->core.PC++;
    }

}
