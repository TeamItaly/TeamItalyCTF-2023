section data
org 0x200
    text hello "SECure COMParator v0.2\n\0"
    text prompt ">>> \0"
    text flag_ok "\nLooks like a flag!\nGo and submit it\n\0"
    text flag_wrong "\nSkill issue\n\0"
org 0x400
    zero input 64
    db check_failed 0
    db progress_step 0

# generated with gen_enc_flag.py
org 0x700
    db key 157, 121, 177, 163, 127, 49, 128, 28, 209, 26, 103, 6, 251, 64, 214, 189
    # let's try to stop people from guessing
    db random_data_1 114, 87, 177, 36, 25, 2, 124, 187, 9, 223, 36, 220, 110, 47, 197, 187

org 0x7f0
    # let's try to stop people from guessing
    db random_data_2 179, 191, 51, 96, 123, 178, 185, 92, 36, 188, 146, 191, 1, 245, 255, 232
org 0x800
    db encflag 32, 73, 39, 112, 140, 234, 6, 196, 10, 148, 154, 143, 41, 74, 203, 217, 7, 155, 212, 127, 181, 42, 2, 49, 8, 6, 176, 130, 68, 133, 171, 218, 240, 224, 247, 94, 140, 190, 230, 23, 246, 238, 206, 191, 102, 193, 221, 101, 172, 156, 254, 139, 176, 99, 151, 238, 171, 69, 184, 195, 167, 112, 207, 30

org 0x1000
    db S 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255

org 0x3f00
    zero stack_start 0x100
    stack_end:

section code
org 0
main:
    set r0, HI(stack_end)
    set r1, LO(stack_end)
    lsp r0, r1

    call rc4_init

    set r0, HI(hello)
    set r1, LO(hello)
    call print_string

    set r0, HI(prompt)
    set r1, LO(prompt)
    call print_string

    set r0, HI(input)
    set r1, LO(input)
    set r2, 64
    call read_string

    set r0, HI(input)
    set r1, LO(input)
    set r2, 64
    call rc4_crypt

    set r0, HI(input)
    set r1, HI(encflag)
    set r2, 64
    call check_equal

    set r0, HI(check_failed)
    set r1, LO(check_failed)
    lmar r0, r1
    load r0
    set r1, 0
    jz r0, r1, .win

    set r0, HI(flag_wrong)
    set r1, LO(flag_wrong)
    call print_string
    jmp halt
.win:
    set r0, HI(flag_ok)
    set r1, LO(flag_ok)
    call print_string
    jmp halt

rc4_init:
    set r0, HI(S)
    set r1, HI(key)
    # i -> r2, j -> r3
    set r2, 0
    set r3, 0
.loop:
    # load S[i]
    lmar r0, r2
    load r5

    # load key[i % 16]
    set r7, 0x0f
    and r7, r2, r7
    lmar r1, r7
    load r6

    # j = j + S[i] + key[i % 16]
    # implicitly mod 256
    add r3, r3, r5
    add r3, r3, r6

    # swap S[i], S[j]
    lmar r0, r2
    load r5
    lmar r0, r3
    load r6
    lmar r0, r2
    store r6
    lmar r0, r3
    store r5

    # ++i
    set r7, 1
    add r2, r2, r7

    # if r2 == 0 after the increment, the cycle ran for 256
    # iterations (and r2 overflowed)
    set r7, 0
    jnz r2, r7, .loop
    ret

# rc4_crypt(r0:r1 data, r2 len)
rc4_crypt:
    # S -> r3, i -> r4, j -> r5
    set r3, HI(S)
    set r4, 0
    set r5, 0
.loop:
    # ++i
    set r7, 1
    add r4, r4, r7

    # j += S[i]
    lmar r3, r4
    load r6
    add r5, r5, r6

    # swap S[i], S[j]
    lmar r3, r4
    load r6
    lmar r3, r5
    load r7
    lmar r3, r4
    store r7
    lmar r3, r5
    store r6

    # t = S[i] + S[j]
    add r6, r6, r7

    # k = S[t]
    lmar r3, r6
    load r6

    # *data++ ^= k
    lmar r0, r1
    load r7
    xor r7, r6, r7
    store r7
    set r7, 1
    add r1, r1, r7

    # jump
    sub r2, r2, r7
    set r7, 0
    jnz r2, r7, .loop

    ret

org 0x400
# print_string(r0:r1 buf)
print_string:
    lmar r0, r1
.loop:
    load r2
    set r3, 0
    jz r2, r3, .end
    out r2, 127
    incmar
    jmp .loop
.end:
    ret

# read_string(r0:r1 buf, r2 len)
read_string:
    lmar r0, r1
.loop:
    in r3, 128
    # stop at newline
    set r4, 10
    jz r3, r4, .end
    store r3
    incmar
    set r3, 1
    sub r2, r2, r3
    set r3, 0
    jnz r2, r3, .loop
.end:
    ret

# check_equal(r0:00 user_input, r1:00 target, r2 len)
check_equal:
    # i -> r3
    set r3, 0
.loop:
    lmar r0, r3
    load r4
    lmar r1, r3
    load r5
    call check_char

    set r4, 1
    add r3, r3, r4
    jnz r3, r2, .loop
.end:
    ret

# check_char(r4 a, r5 b)
# hopefully constant "time"
check_char:
    set r6, HI(check_failed)
    set r7, LO(check_failed)
    lmar r6, r7

    jz r4, r5, .ok
    set r6, 1
    store r6
    jmp .check_done
.ok:
    set r6, 0
    set r6, 0
    jmp .check_done
.check_done:

    # print progress
    set r6, HI(progress_step)
    set r7, LO(progress_step)
    lmar r6, r7
    load r5
    set r6, 1
    add r5, r6, r5
    store r5
    load r7

    set r6, 13
    out r6, 127
    set r6, 91
    out r6, 127
    set r5, 0
.progres_loop:
    set r6, 1
    add r5, r5, r6

    set r6, 32
    jg r5, r7, .print_space
    set r6, 61
.print_space:
    out r6, 127

    set r6, 63
    jg r6, r5, .progres_loop

    set r6, 93
    out r6, 127

    # sleep for a while
    set r7, 0xff
    set r6, 0xff
.sleep_loop:
    set r5, 255
    out r5, 42

    set r5, 1
    sub r6, r6, r5
    set r5, 0
    jnz r5, r6, .sub_lowonly
    set r5, 1
    sub r7, r7, r5
.sub_lowonly:
    set r5, 0
    jnz r5, r6, .sleep_loop
    jnz r5, r6, .sleep_loop

    ret


halt:
    set r0, 0
    out r0, 42
