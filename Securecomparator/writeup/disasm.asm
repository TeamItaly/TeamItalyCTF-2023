main:
0000: r0 = 40
0004: r1 = 0
0008: stack_pointer = r0 || r1
000c: call 0090
0010: r0 = 2
0014: r1 = 0
0018: call 0400
001c: r0 = 2
0020: r1 = 18
0024: call 0400
0028: r0 = 4
002c: r1 = 0
0030: r2 = 40
0034: call 0420
0038: r0 = 4
003c: r1 = 0
0040: r2 = 40
0044: call 00f4
0048: r0 = 4
004c: r1 = 8
0050: r2 = 40
0054: call 044c
0058: r0 = 4
005c: r1 = 40
0060: mar = r0 || r1
0064: r0 = mem[mar]
0068: r1 = 0
006c: if r0 == r1: goto 0080
0070: r0 = 2
0074: r1 = 43
0078: call 0400
007c: goto 0530
0080: r0 = 2
0084: r1 = 1d
0088: call 0400
008c: goto 0530

init_something:
0090: r0 = 10
0094: r1 = 7
0098: r2 = 0
009c: r3 = 0
00a0: mar = r0 || r2
00a4: r5 = mem[mar]
00a8: r7 = f
00ac: r7 = r2 & r7
00b0: mar = r1 || r7
00b4: r6 = mem[mar]
00b8: r3 = r3 + r5
00bc: r3 = r3 + r6
00c0: mar = r0 || r2
00c4: r5 = mem[mar]
00c8: mar = r0 || r3
00cc: r6 = mem[mar]
00d0: mar = r0 || r2
00d4: mem[mar] = r6
00d8: mar = r0 || r3
00dc: mem[mar] = r5
00e0: r7 = 1
00e4: r2 = r2 + r7
00e8: r7 = 0
00ec: if r2 != r7: goto 00a0
00f0: ret

work_with_input:
00f4: r3 = 10
00f8: r4 = 0
00fc: r5 = 0
0100: r7 = 1
0104: r4 = r4 + r7
0108: mar = r3 || r4
010c: r6 = mem[mar]
0110: r5 = r5 + r6
0114: mar = r3 || r4
0118: r6 = mem[mar]
011c: mar = r3 || r5
0120: r7 = mem[mar]
0124: mar = r3 || r4
0128: mem[mar] = r7
012c: mar = r3 || r5
0130: mem[mar] = r6
0134: r6 = r6 + r7
0138: mar = r3 || r6
013c: r6 = mem[mar]
0140: mar = r0 || r1
0144: r7 = mem[mar]
0148: r7 = r6 ^ r7
014c: mem[mar] = r7
0150: r7 = 1
0154: r1 = r1 + r7
0158: r2 = r2 - r7
015c: r7 = 0
0160: if r2 != r7: goto 0100
0164: ret

output_string:
0400: mar = r0 || r1
0404: r2 = mem[mar]
0408: r3 = 0
040c: if r2 == r3: goto 041c
0410: write_dev(7f, r2)
0414: mar++
0418: goto 0404
041c: ret

input_string:
0420: mar = r0 || r1
0424: r3 = read_dev(80)
0428: r4 = a
042c: if r3 == r4: goto 0448
0430: mem[mar] = r3
0434: mar++
0438: r3 = 1
043c: r2 = r2 - r3
0440: r3 = 0
0444: if r2 != r3: goto 0424
0448: ret

compare_strings:
044c: r3 = 0
0450: mar = r0 || r3
0454: r4 = mem[mar]
0458: mar = r1 || r3
045c: r5 = mem[mar]
0460: call 0474
0464: r4 = 1
0468: r3 = r3 + r4
046c: if r3 != r2: goto 0450
0470: ret

compare_char:
0474: r6 = 4
0478: r7 = 40
047c: mar = r6 || r7
0480: if r4 == r5: goto 0490
0484: r6 = 1
0488: mem[mar] = r6
048c: goto 049c
0490: r6 = 0
0494: r6 = 0
0498: goto 049c
049c: r6 = 4
04a0: r7 = 4e
04a4: mar = r6 || r7
04a8: r5 = mem[mar]
04ac: r6 = 1
04b0: r5 = r6 + r5
04b4: mem[mar] = r5
04b8: r7 = mem[mar]
04bc: r6 = d
04c0: write_dev(7f, r6)
04c4: r6 = 5b
04c8: write_dev(7f, r6)
04cc: r5 = 0
04d0: r6 = 1
04d4: r5 = r5 + r6
04d8: r6 = 20
04dc: if r5 > r7: goto 04e4
04e0: r6 = 3d
04e4: write_dev(7f, r6)
04e8: r6 = 3f
04ec: if r6 > r5: goto 04d0
04f0: r6 = 5d
04f4: write_dev(7f, r6)
04f8: r7 = ff
04fc: r6 = ff
0500: r5 = ff
0504: write_dev(2a, r5)
0508: r5 = 1
050c: r6 = r6 - r5
0510: r5 = 0
0514: if r5 != r6: goto 0520
0518: r5 = 1
051c: r7 = r7 - r5
0520: r5 = 0
0524: if r5 != r6: goto 0500
0528: if r5 != r6: goto 0500
052c: ret

halt:
0530: r0 = 0
0534: write_dev(2a, r0)
