# Scrambled Pizzeria
## How does the program work
When started, the program will prompt the user to send it a greyscale image along with its height and width.
The image will then be encrypted with a randomly generated keystream (of length 400) the permutation and substitution layers and sent back to the user, along with the flag encrypted with the same keystream.

Let's look at what those two layers do:
```python
def permutation(
    img: npt.NDArray[np.uint8], c: npt.NDArray[np.uint64]
) -> npt.NDArray[np.uint8]:
    height, width = img.shape
    cm = c[np.arange(max(height, width)) % len(c)]
    rows = np.argsort(cm[:height])
    cols = np.argsort(cm[:width])
    return img[rows, :][:, cols]
```
Here we take the keystream, we take all its elements up to `max(height, width)`, then we sort it in ascending order. We then permutate the columns and rows of the image using the indices of the sorted truncated keystream.

```python
def substitution(
    con: npt.NDArray[np.uint8], c: npt.NDArray[np.uint64]
) -> npt.NDArray[np.uint8]:
    ids = np.arange(np.prod(con.shape)) % len(c)
    return con ^ (c % 256).astype(np.uint8)[ids].reshape(con.shape)
```
During the substitution phase we simply create a long enough sequence from the keystream to xor with all the image, so we repeat the original keystream as many times as needed.

## What's the idea of the attack
The idea of the attack is to pass an image built in such a way that the column permutation layer won't have effect on at least one row, such that we can recover the original keystream, and in suh a way that, after having inverted the substitution layer, we can build the permutation map used in the encryption of the image and also of the flag.

Such an image can be constructed in the following way:
```python
shape = (3, 400)
I = np.zeros(shape, np.uint8)
I[1, :] = np.mod(np.arange(shape[1]), 256) + np.floor(np.arange(shape[1]) / 256)
I[2, :] = np.floor(np.arange(shape[1]) / 256) * 255
```
Here we have a row full of zeroes, such that when it will be XORed with the reduced keystream it will just result in the reduced keystream itself in the ciphertext.
The other two rows are needed to recover the permutation map. After recovering the result of the permutation layer of the ciphertext of our image (by inverting the substitution layer), we can just sum the two rows to obtain the full permutation map.

As we don't know which of the three rows is the effective reduced keystream, we need to try all the three rows and find the correct one.

## The solver
```python
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


r = remote("todo.challs.todo.it", 1337)

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
```
