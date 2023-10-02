import sys, struct

if len(sys.argv) != 2:
    print(f'Usage: {sys.argv[0]} checker.bin')
    sys.exit(1)

with open(sys.argv[1], 'rb') as fin:
    code = fin.read(2**14)
    data = fin.read(2**14)
    call_table_raw = fin.read(1024)

assert len(code) == 2**14
assert len(data) == 2**14
assert len(call_table_raw) == 256*4

call_table = []
for i in range(256):
    call_table.append(struct.unpack('<I', call_table_raw[4*i:4*i+4])[0])

OPCODE = lambda x: (x & 0xff)
RS1 = lambda x: (x >> 8) & 7
RS2 = lambda x: (x >> 11) & 7
RD = lambda x: (x >> 14) & 7
IMM = lambda x: (x >> 17)

for addr in range(0, len(code), 4):
    inst = struct.unpack('<I', code[addr:addr+4])[0]

    opcode = OPCODE(inst)
    rs1 = RS1(inst)
    rs2 = RS2(inst)
    rd = RD(inst)
    imm = IMM(inst)

    if opcode == 1: # set
        print(f'{addr:04x}: r{rd} = {imm:x}')
    elif opcode == 2: # add
        print(f'{addr:04x}: r{rd} = r{rs1} + r{rs2}')
    elif opcode == 3: # sub
        print(f'{addr:04x}: r{rd} = r{rs1} - r{rs2}')
    elif opcode == 6: # and
        print(f'{addr:04x}: r{rd} = r{rs1} & r{rs2}')
    elif opcode == 8: # xor
        print(f'{addr:04x}: r{rd} = r{rs1} ^ r{rs2}')
    elif opcode == 9: # load
        print(f'{addr:04x}: r{rd} = mem[mar]')
    elif opcode == 10: # store
        print(f'{addr:04x}: mem[mar] = r{rs1}')
    elif opcode == 11: # in
        print(f'{addr:04x}: r{rd} = read_dev({imm:02x})')
    elif opcode == 12: # out
        print(f'{addr:04x}: write_dev({imm:02x}, r{rs1})')
    elif opcode == 14: # jmp
        print(f'{addr:04x}: goto {imm:04x}')
    elif opcode == 15: # jz
        print(f'{addr:04x}: if r{rs1} == r{rs2}: goto {imm:04x}')
    elif opcode == 16: # jnz
        print(f'{addr:04x}: if r{rs1} != r{rs2}: goto {imm:04x}')
    elif opcode == 17: # jg
        print(f'{addr:04x}: if r{rs1} > r{rs2}: goto {imm:04x}')
    elif opcode == 19: # load_mar
        print(f'{addr:04x}: mar = r{rs1} || r{rs2}')
    elif opcode == 20: # inc_mar
        print(f'{addr:04x}: mar++')
    elif opcode == 21: # load_sp
        print(f'{addr:04x}: stack_pointer = r{rs1} || r{rs2}')
    elif opcode == 24: # call
        print(f'{addr:04x}: call {call_table[imm]:04x}')
    elif opcode == 25: #ret
        print(f'{addr:04x}: ret')
    else:
        print(f'{addr:04x}: === UNKNOWN {opcode}')
