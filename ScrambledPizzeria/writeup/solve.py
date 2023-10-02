#!/usr/bin/python3

from pwn import *
import numpy.typing as npt
import numpy as np
from PIL import Image
import os


def inverse_permutation(
    img: npt.NDArray[np.uint8], p: npt.NDArray[np.uint]
) -> npt.NDArray[np.uint8]:
    height, width = img.shape
    idxs = np.arange(max(height, width)) % len(p)
    rows = np.argsort(p[idxs[:height]])
    cols = np.argsort(p[idxs[:width]])
    return img[rows, :][:, cols]


def inverse_substitution(
    con: npt.NDArray[np.uint8], c: npt.NDArray[np.uint64]
) -> npt.NDArray[np.uint8]:
    ids = np.arange(np.prod(con.shape)) % len(c)
    return con ^ (c % 256).astype(np.uint8)[ids].reshape(con.shape)


r = remote("todo.challs.teamitaly.eu", 1337)

shape = (3, 400)
I = np.zeros(shape, np.uint8)
I[1, :] = np.mod(np.arange(shape[1]), 256) + np.floor(np.arange(shape[1]) / 256)
I[2, :] = np.floor(np.arange(shape[1]) / 256) * 255

r.sendlineafter(b"What's the height of the image? ", str(shape[0]).encode())
r.sendlineafter(b"What's the width of the image? ", str(shape[1]).encode())
r.sendlineafter(
    b"Now send me the image and I'll do the rest!\n",
    I.tobytes().hex().encode(),
)

r.recvuntil(b"Oh mamma mia! I've scrambled all of your ingredients, look!\n")
enc = bytes.fromhex(r.recvline(False).decode())
enc = np.frombuffer(enc, np.uint8).reshape(shape)

r.recvuntil(b"What a disaster! To make it up to me, here's a gift...\n")
flag_enc = bytes.fromhex(r.recvline(False).decode())
flag_enc = np.frombuffer(flag_enc, np.uint8).reshape((400, 400))

r.close()

if not os.path.exists("results"):
    os.mkdir("results")

for i, c in enumerate(enc):
    con = inverse_substitution(enc, c).astype(np.uint)
    p = con[0] + con[1] + con[2]

    flag_con = inverse_substitution(flag_enc, c)
    flag = inverse_permutation(flag_con, p)

    Image.fromarray(flag).save(f"results/{i}.jpg")
