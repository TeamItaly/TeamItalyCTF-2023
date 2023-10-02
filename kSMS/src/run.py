#!/usr/bin/env python3
# Stolen from https://github.com/google/google-ctf/blob/master/2017/quals/2017-pwn-cfi/challenge/
from hashcash import check
import random
import string
import sys
import os

SKIP_SECRET = "whatabigmemelemao_131337"

bits = 28
resource = "".join(random.choice(string.ascii_lowercase) for i in range(8))
print("hashcash -mb{} {}".format(bits, resource))
sys.stdout.flush()

stamp = sys.stdin.readline().strip()

if stamp != SKIP_SECRET:
  if not stamp.startswith("1:"):
    print("only hashcash v1 supported")
    exit(1)

  if not check(stamp, resource=resource, bits=bits):
    print("invalid")
    exit(1)

os.execv(sys.argv[1], sys.argv[1:])