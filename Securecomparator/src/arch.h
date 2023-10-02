/*
Seccomp responses:

00 000 RRR XXXXXXXX - set regs[R] to X
   001 RRR 00000000 - set regs[R] to mem[MAR]
   010 000 XXXXXXXX - set mem[MAR] to X
   011 000 XXXXXXXX - call call_targets[X]
   100 RRR XXXXXXXX - set regs[R] to dev[X]
   101 RRR XXXXXXXX - set dev[X] to regs[R]
   110 000 00000000 - nop
   111 000 00000000 - ret
01 XXXXXXXXXXXXXX   - set ip to X
10 XXXXXXXXXXXXXX   - set sp to X
11 XXXXXXXXXXXXXX   - set mar to X

Calling convention:
args (caller-saved): r0, r1, r2, r3
data pointer arg: r0:r1
ret: r0
callee-saved: r4, r5, r6, r7
*/

#define BUS_OP_MISC 0
#define BUS_OP_IP 1
#define BUS_OP_SP 2
#define BUS_OP_MAR 3

#define BUS_MISC_SETREG 0
#define BUS_MISC_LOAD 1
#define BUS_MISC_STORE 2
#define BUS_MISC_CALL 3
#define BUS_MISC_IN 4
#define BUS_MISC_OUT 5
#define BUS_MISC_NOP 6
#define BUS_MISC_RET 7

#define OP_MOV 0
#define OP_SET 1

#define OP_ADD 2
#define OP_SUB 3
#define OP_MUL 4
#define OP_DIV 5
#define OP_AND 6
#define OP_OR 7
#define OP_XOR 8

#define OP_LOAD 9
#define OP_STORE 10
#define OP_IN 11
#define OP_OUT 12

#define OP_JMPR 13
#define OP_JMP 14
#define OP_JZ 15
#define OP_JNZ 16
#define OP_JG 17
#define OP_JGE 18

#define OP_LMAR 19
#define OP_INCMAR 20
#define OP_LSP 21
#define OP_INCSP 22
#define OP_DECSP 23

#define OP_CALL 24
#define OP_RET 25
