import sys, random
from Crypto.Cipher import ARC4

if len(sys.argv) != 2:
    print(f'Usage: {sys.argv[0]} <flag>')
    sys.exit(1)

random.seed(42)
rc4_key = random.randbytes(16) # must be 16 bytes

flag = sys.argv[1].encode()
assert len(flag) <= 64
flag = flag.ljust(64, b'\0')
enc_flag = ARC4.new(rc4_key).encrypt(flag)

def print_bytes(x):
    print(', '.join(map(lambda v: str(int(v)), x)))

print('Encryption key:')
print_bytes(rc4_key)
print('Encrypted flag:')
print_bytes(enc_flag)
