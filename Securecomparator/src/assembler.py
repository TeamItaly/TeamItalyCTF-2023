import sys, struct

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <file.asm> <output.bin>")
    sys.exit(1)

# name: (opcode, (operands))
opcodes = {
    'mov': (0, ('rd', 'rs1')),
    'set': (1, ('rd', 'imm8')),
    'add': (2, ('rd', 'rs1', 'rs2')),
    'sub': (3, ('rd', 'rs1', 'rs2')),
    'mul': (4, ('rd', 'rs1', 'rs2')),
    'div': (5, ('rd', 'rs1', 'rs2')),
    'and': (6, ('rd', 'rs1', 'rs2')),
    'or': (7, ('rd', 'rs1', 'rs2')),
    'xor': (8, ('rd', 'rs1', 'rs2')),
    'load': (9, ('rd',)),
    'store': (10, ('rs1',)),
    'in': (11, ('rd', 'imm8')),
    'out': (12, ('rs1', 'imm8')),
    'jmpr': (13, ('rs1', 'rs2')),
    'jmp': (14, ('imm14',)),
    'jz': (15, ('rs1', 'rs2', 'imm14')),
    'jnz': (16, ('rs1', 'rs2', 'imm14')),
    'jg': (17, ('rs1', 'rs2', 'imm14')),
    'jge': (18, ('rs1', 'rs2', 'imm14')),
    'lmar': (19, ('rs1', 'rs2')),
    'incmar': (20, ()),
    'lsp': (21, ('rs1', 'rs2')),
    'incsp': (22, ()),
    'decsp': (23, ()),
    'call': (24, ('imm14_indexed',)),
    'ret': (25, ()),
}
used_opcodes = set()

OPCODE = lambda x: (x & 0xff)
RS1 = lambda x: ((x) << 8)
RS2 = lambda x: ((x) << 11)
RD = lambda x: ((x) << 14)
IMM = lambda x: ((x) << 17)

def to_int(x):
    try:
        return int(x)
    except ValueError:
        return int(x, 16)

with open(sys.argv[1]) as fin:
    code = fin.readlines()

instructions: list[tuple[int, str]] = []
data_items: list[tuple[int, bytes]] = []
labels: dict[str, int] = {}
call_table: list[str] = []
curr_section = None
curr_org = None
curr_label = None

for line in code:
    line = line.strip()

    if len(line) == 0 or line.startswith('#'): # comments
        continue

    parts = line.replace(',','').split()

    if parts[0] == 'section':
        if parts[1] == 'data':
            assert curr_section is None
            curr_section = 'data'
        elif parts[1] == 'code':
            assert curr_section is None or curr_section == 'data'
            curr_section = 'code'
        else:
            assert False
        curr_org = None

    elif parts[0] == 'org':
        org = int(parts[1], 16)
        assert curr_org is None or org >= curr_org
        curr_org = org

    elif parts[0] == 'text':
        assert curr_section == 'data'

        name = parts[1]
        text = line.split(' ', 2)[2]
        assert text.startswith('"') and text.endswith('"')
        text = text[1:-1]

        escapes = {
            '\\\\': '\\',
            '\\n': '\n',
            '\\t': '\t',
            '\\0': '\0',
        }

        # not really the correct way to do it, but whatever
        for a,b in escapes.items():
            text = text.replace(a, b)

        data_items.append((curr_org, text.encode()))
        if name in labels:
            print(f'Duplicate label {name}')
            sys.exit(1)
        labels[name] = curr_org
        curr_org += len(text)

    elif parts[0] == 'db':
        assert curr_section == 'data'

        name = parts[1]
        contents = []
        for x in parts[2:]:
            contents.append(int(x))

        data_items.append((curr_org, bytes(contents)))
        if name in labels:
            print(f'Duplicate label {name}')
            sys.exit(1)
        labels[name] = curr_org
        curr_org += len(contents)

    elif parts[0] == 'zero':
        assert curr_section == 'data'

        name = parts[1]
        size = to_int(parts[2])
        data_items.append((curr_org, bytes([0]*size)))
        if name in labels:
            print(f'Duplicate label {name}')
            sys.exit(1)
        labels[name] = curr_org
        curr_org += size

    elif parts[0].endswith(':'): # label
        name = parts[0][:-1]

        if name.startswith('.'): #sublabel
            name = curr_label + name
        else:
            curr_label = name

        if name in labels:
            print(f'Duplicate label {name}')
            sys.exit(1)
        labels[name] = curr_org

    else:
        if parts[0] not in opcodes:
            print(f'Unrecognized opcode {parts[0]}')
            sys.exit(1)

        operands = []
        for x in parts[1:]:
            pref = ''
            if x.startswith('HI(') or x.startswith('LO('):
                pref, x = x[:3], x[3:]
            if x.startswith('.'):
                x = curr_label + x
            operands.append(pref + x)

        instructions.append((curr_org, [parts[0], *operands]))
        curr_org += 4

print(f'{labels=}')
print(f'{data_items=}')
print(f'{instructions=}')

code = b''
for address, instruction in instructions:
    name, args = instruction[0], instruction[1:]
    op, arg_desc = opcodes[name]
    used_opcodes.add(name)

    if len(args) != len(arg_desc):
        print(f'Mismatched number of arguments for {instruction}')
        sys.exit(1)

    raw = OPCODE(op)
    for arg,desc in zip(args, arg_desc):
        if desc == 'rd':
            raw |= RD(int(arg.removeprefix('r')))
        elif desc == 'rs1':
            raw |= RS1(int(arg.removeprefix('r')))
        elif desc == 'rs2':
            raw |= RS2(int(arg.removeprefix('r')))
        elif desc == 'imm8':
            try:
                value = to_int(arg)
            except:
                if arg.startswith('LO('):
                    assert arg.endswith(')')
                    value = labels[arg[3:-1]] & 0xff
                elif arg.startswith('HI('):
                    assert arg.endswith(')')
                    value = (labels[arg[3:-1]] >> 8) & 0xff
                else:
                    raise
            raw |= IMM(value)
        elif desc == 'imm14':
            try:
                value = to_int(arg)
            except:
                # label?
                if arg not in labels:
                    print(f'Unresolved label {arg}')
                    sys.exit(1)
                value = labels[arg]
            raw |= IMM(value)
        elif desc == 'imm14_indexed':
            if arg not in labels:
                print(f'Unresolved label {arg}')
                sys.exit(1)
            if arg not in call_table:
                if len(call_table) == 256:
                    print(f'Too many call targets.')
                    sys.exit(1)
                call_table.append(arg)
            idx = call_table.index(arg)
            raw |= IMM(idx)
        else:
            assert False

    code = code.ljust(address, b'\0')
    code += struct.pack('<I', raw)

data = b''
for address, value in data_items:
    data = data.ljust(address, b'\0')
    data += value

calls = b''
for label in call_table:
    calls += struct.pack('<I', labels[label])

assert len(code) <= 2**14
assert len(data) <= 2**14
assert len(calls) <= 256*4

output = \
    code.ljust(2**14, b'\0') + \
    data.ljust(2**14, b'\0') + \
    calls.ljust(256*4, b'\0')

with open(sys.argv[2], 'wb') as fout:
    fout.write(output)

unused_opcodes = set(opcodes.keys()) - used_opcodes
print(f'{unused_opcodes=}')
