#define _GNU_SOURCE

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sys/signal.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>

#include "arch.h"

// #define TESTING
// #define DEBUG

#ifdef DEBUG
#define dprintf(...) printf(__VA_ARGS__)
#else
#define dprintf(...)
#endif

#define IMEM_BITS 14
#define DMEM_BITS 14
#define NUM_GP_REGS 8

typedef struct cpu_t cpu_t;

typedef void (*device_write_cb_t)(cpu_t*, uint8_t);
typedef uint8_t (*device_read_cb_t)(cpu_t*);

typedef struct device_t_ {
    struct device_t_* next;
    uint8_t idx;
    device_read_cb_t read_cb;
    device_write_cb_t write_cb;
} device_t;

typedef struct cpu_t {
    uint64_t regs; // 1 byte per register, r0 is the lowest byte
    uint16_t mar;
    uint16_t ip;
    uint16_t sp;
    device_t* devs;
    bool running;

    uint32_t imem[1 << (IMEM_BITS - 2)];
    uint8_t dmem[1 << DMEM_BITS];
    uint32_t call_table[256];
} cpu_t;

cpu_t* cpu_new() {
    cpu_t* cpu = (cpu_t*) calloc(1, sizeof(cpu_t));
    cpu->running = true;
    return cpu;
}

void cpu_reset(cpu_t* cpu) {
    memset(cpu, 0, sizeof(cpu_t));
}

uint8_t __attribute__((noinline)) cpu_get_register(cpu_t* cpu, int index) {
    return (cpu->regs >> (index * 8)) & 0xFF;
}

void __attribute__((noinline)) cpu_set_register(cpu_t* cpu, int index, uint8_t value) {
    uint64_t mask = 0xFFLL << (index * 8);
    cpu->regs = (cpu->regs & ~mask) | ((uint64_t)value << (index * 8));
}

void __attribute__((noinline)) cpu_register_device(cpu_t* cpu, device_t* dev) {
    dev->next = cpu->devs;
    cpu->devs = dev;
}

device_t* __attribute__((noinline)) cpu_get_device(cpu_t* cpu, int index) {
    device_t* dev = cpu->devs;
    while(dev) {
        if(dev->idx == index) {
            return dev;
        }
        dev = dev->next;
    }
    assert(false && "Device not found");
    return NULL;
}

#ifdef TESTING

#define RS1(idx) ((idx) << 8)
#define RS2(idx) ((idx) << 11)
#define RD(idx) ((idx) << 14)
#define IMM(val) ((val) << 17)

void cpu_load_test_program(cpu_t* cpu) {
    int pc = 0;
    cpu->imem[pc++] = OP_SET | RD(7) | IMM(42);
    cpu->imem[pc++] = OP_MOV | RD(0) | RS1(7);
    cpu->imem[pc++] = OP_MOV | RD(2) | RS1(7);
    cpu->imem[pc++] = OP_ADD | RD(3) | RS1(0) | RS2(7);
    cpu->imem[pc++] = OP_OUT | RS1(3) | IMM(127);
    cpu->imem[pc++] = OP_IN | RD(4) | IMM(128);
    cpu->imem[pc++] = OP_SET | RD(0) | IMM(113);
    cpu->imem[pc++] = OP_JZ | RS1(0) | RS2(4) | IMM(40);
    cpu->imem[pc++] = OP_OUT | RS1(4) | IMM(127);
    cpu->imem[pc++] = OP_JMP | IMM(20);
    cpu->imem[pc++] = OP_SET | RD(1) | IMM(42);
    cpu->imem[pc++] = OP_LMAR | RS1(1) | RS2(1);
    cpu->imem[pc++] = OP_STORE | RS1(1);
    cpu->imem[pc++] = OP_SET | RD(0) | IMM(0);
    cpu->imem[pc++] = OP_OUT | RS1(0) | IMM(42);
}
#endif

void cpu_load_program(cpu_t* cpu, const char* fname) {
    FILE* f = fopen(fname, "r");
    if(!f) {
        puts("Can't open program file");
        exit(1);
    }
    if(fread(cpu->imem, 1<<IMEM_BITS, 1, f) != 1) {
        puts("Reading code failed");
        exit(1);
    }
    if(fread(cpu->dmem, 1<<DMEM_BITS, 1, f) != 1) {
        puts("Reading data failed");
        exit(1);
    }
    if(fread(cpu->call_table, 256*4, 1, f) != 1) {
        puts("Reading call table failed");
        exit(1);
    }
    fclose(f);
}

#ifdef DEBUG
// Debugging API. We probably want to _exclude_ this from the challenge binary
void cpu_dump(cpu_t* cpu) {
    puts("cpu {");
    printf("  ip=%04X sp=%04X mar=%04X\n", cpu->ip, cpu->sp, cpu->mar);
    printf(" ");
    for(int i = 0; i < NUM_GP_REGS; ++i) {
        printf(" r%d=%02X", i, cpu_get_register(cpu, i));
    }
    printf("\n}\n");
}
#endif

void cpu_cycle(cpu_t* cpu) {

#ifdef DEBUG
    puts("");
    puts("Starting cycle");
    cpu_dump(cpu);
#endif

    if(cpu->ip >= (1 << IMEM_BITS)) {
        cpu->running = false;
        return;
    }

    uint32_t opcode = cpu->imem[cpu->ip / 4];
    dprintf("op: %08X\n", opcode);

    // The filter can only output errno values in [0, 4095].
    // This is very restrictive, so we iterate twice, with the last
    // argument indicating whether the filter should return the lower (0)
    // or higher (1) byte of the result.
    uint16_t res = 0;
    for(int byte_idx = 0; byte_idx < 2; byte_idx++) {
        // If the filter returns ERRNO(0), errno isn't updated, so reset it here
        errno = 0;

        dprintf("Calling syscall(44 %lu %d %d %d %d %d)", cpu->regs, cpu->ip, cpu->sp, cpu->mar, opcode, byte_idx);
        syscall(SYS_sendto, cpu->regs, cpu->ip, cpu->sp, cpu->mar, opcode, byte_idx);
        dprintf(" --> %d\n", errno);
        res |= (errno & 0xff) << (8 * byte_idx);
    }

    int bus_op = (res >> 14) & 3;
    dprintf("Received %04X\n", res);
    dprintf("  bus_op %d\n", bus_op);
    bool did_jump = false;

    switch(bus_op) {
        case BUS_OP_IP:
            cpu->ip = res & 0x3FFF;
            did_jump = true;
            break;
        case BUS_OP_SP:
            cpu->sp = res & 0x3FFF;
            break;
        case BUS_OP_MAR:
            cpu->mar = res & 0x3FFF;
            break;
        case BUS_OP_MISC:
        {
            int bus_subop = (res >> 11) & 7;
            int target_reg = (res >> 8) & 7;
            int value = res & 0xFF;
            dprintf("  bus_subop %d target_reg %d value %d\n", bus_subop, target_reg, value);

            switch(bus_subop) {
                case BUS_MISC_SETREG:
                    cpu_set_register(cpu, target_reg, value);
                    break;
                case BUS_MISC_LOAD:
                    cpu_set_register(cpu, target_reg, cpu->dmem[cpu->mar]);
                    break;
                case BUS_MISC_STORE:
                    cpu->dmem[cpu->mar] = value;
                    break;
                case BUS_MISC_IN:
                {
                    device_t* dev = cpu_get_device(cpu, value);
                    if(!dev) {
                        dprintf("Requested read from non-existent device %d\n", value);
                        cpu->running = false;
                        return;
                    }
                    if(dev->read_cb) {
                        uint8_t b = dev->read_cb(cpu);
                        cpu_set_register(cpu, target_reg, b);
                    }
                    break;
                }
                case BUS_MISC_OUT:
                {
                    device_t* dev = cpu_get_device(cpu, value);
                    if(!dev) {
                        dprintf("Requested write to non-existent device %d\n", value);
                        cpu->running = false;
                        return;
                    }
                    // special case, input register as RD.
                    if(dev->write_cb) {
                        uint8_t b = cpu_get_register(cpu, target_reg);
                        dev->write_cb(cpu, b);
                    }
                    break;
                }
                case BUS_MISC_CALL:
                    cpu->dmem[cpu->sp--] = cpu->ip & 0xff;
                    cpu->dmem[cpu->sp--] = (cpu->ip >> 8) & 0xff;
                    cpu->ip = cpu->call_table[value];
                    dprintf("Calling %d\n", cpu->ip);
                    did_jump = true;
                    break;
                case BUS_MISC_RET:
                {
                    uint16_t addr = cpu->dmem[++cpu->sp] << 8;
                    addr |= cpu->dmem[++cpu->sp];
                    cpu->ip = addr + 4;
                    dprintf("Returning to %d\n", cpu->ip);
                    did_jump = true;
                    break;
                }
                case BUS_MISC_NOP:
                    // wow much code
                    break;
            }
            break;
        }
    }

    // Not a jump, go to the next instruction
    if(!did_jump) {
        cpu->ip += 4;
    }
}

void stdout_write(cpu_t* cpu, uint8_t ch) {
    (void)cpu;
    putchar(ch);
    fflush(stdout);
}

device_t stdout_dev = {
    .idx = 127,
    .next = NULL,
    .read_cb = NULL,
    .write_cb = stdout_write,
};

uint8_t stdin_read(cpu_t* cpu) {
    (void)cpu;
    return getchar();
}

device_t stdin_dev = {
    .idx = 128,
    .next = NULL,
    .read_cb = stdin_read,
    .write_cb = NULL,
};

uint8_t power_read(cpu_t *cpu) {
    return cpu->running ? 1 : 0;
}

void power_write(cpu_t* cpu, uint8_t ch) {
    if(ch == 0) {
        cpu->running = false;
        puts("Halted.");
    } else {
        usleep(ch);
    }
}

device_t power_dev = {
    .idx = 42,
    .next = NULL,
    .read_cb = power_read,
    .write_cb = power_write,
};

#include "filter.h"

void install_seccomp() {
    struct prog {
        unsigned short len;
        unsigned char *filter;
    } rule = {
        .len = sizeof(bpf) >> 3,
        .filter = bpf
    };

    if(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("PR_SET_NO_NEW_PRIVS");
        exit(1);
    }
    if(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &rule) != 0) {
        perror("PR_SET_SECCOMP");
        exit(1);
    }
}

int main(int argc, char** argv) {
    install_seccomp();

    cpu_t* cpu = cpu_new();
    cpu_register_device(cpu, &stdin_dev);
    cpu_register_device(cpu, &stdout_dev);
    cpu_register_device(cpu, &power_dev);

    if(argc > 1) {
        cpu_load_program(cpu, argv[1]);
    } else {
        fprintf(stderr, "Usage: %s checker.bin\n", argv[0]);
        exit(1);
    }

    while(cpu->running) {
        cpu_cycle(cpu);
    }

    free(cpu);
}
