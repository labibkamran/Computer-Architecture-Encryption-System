; Program 1, Program 2, and THRESH function combined

; Program 1: (A + B) - C)
; Memory:
; 0(R7) = A
; 1(R7) = B
; 2(R7) = C
; 3(R7) = Result

P1_START:
LD R1, 0(R7)
LD R2, 1(R7)
LD R3, 2(R7)
ADD R4, R1, R2
SUB R0, R4, R3
ST R0, 3(R7)
NOP



; Program 2: Zeroing elements below threshold
; 10(R7) = N (number of elements)
; 20(R7) = Threshold
; 11(R7) to (12 + N - 1)(R7) = Array elements
P2_START:
LD R1, 10(R7)
LD R2, 20(R7)
ADDI R3, R0, 0
ADDI R5, R0, 1
ADDI R6, R7, 11

P2_LOOP:
BNE R3, R1, P2_CONT
BNE R0, R0, P2_END

P2_CONT:
LD R4, 0(R6)
SLT R7, R4, R2
BNE R7, R0, P2_ZERO
ADDI R6, R6, 1
ADDI R3, R3, 1
BNE R5, R0, P2_LOOP

P2_ZERO:
ST R0, 0(R6)
ADDI R6, R6, 1
ADDI R3, R3, 1
BNE R5, R0, P2_LOOP

P2_END:
NOP



; THRESH function: if (A < THRESH) return 0 else return A
; R1 = x , R2 = THRESH
; R0 = result
THRESH_ENTRY:
SLT R4, R1, R2
BNE R4, R0, DO_ZERO
ADDI R0, R1, 0
NOP

DO_ZERO:
ADDI R0, R0, 0
NOP
