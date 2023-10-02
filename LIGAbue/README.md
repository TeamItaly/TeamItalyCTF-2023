# TeamItalyCTF 2023

## [rev] LIGAbue (31 solves)
I guess all of you remember writing in Microsoft Word with Wingdings as a kid.

Author: Carlo Collodel <@collodel>

## Solution

We are given a OTF font file.

Running `otfinfo` yields the following output:

```sh
$ otfinfo -i chall.otf
Family:              Here
Subfamily:           is
Full name:           some
PostScript name:     culture:
Version:             Version 001.000
Unique ID:           FontForge 2.0 : some : 28-9-2023
Copyright:           https://www.youtube.com/watch?v=g6tuepmUmJg
Vendor ID:           PfEd
```

```sh
$ otfinfo chall.otf -t
  89534 CFF
     28 FFTM
  65492 GSUB
     96 OS/2
    378 cmap
     54 head
     36 hhea
   4242 hmtx
      6 maxp
    519 name
     32 post
```

We can observe that CFF and GSUB are the biggest tables: CFF is just the table containing the font glyphs, while GSUB is a table used to substitute glyphs with other glyphs following some rules.

Opening the font with FontForge (or any other font editor) we can see that it contains a 🤌 glyph, along with 2047 "NO" glyphs and a single "YES" glyph, on the glyph `s1337`.

The goal of the challenge is to find the sequence of characters that when written with this font result in the "YES" glyph.

Now we can proceed in various ways, the fastest one is to decompile into `.fea` files the GSUB table, and parse what rules are applied to the glyphs. A simple way is using [this](https://simoncozens.github.io/fonts-and-layout/features.html#decompiling-a-font) tool.

After decompiling, we can start from the last glyph, `s1337`, and see what rules are applied to it:

```sh
lookup LigatureSubstitution1971 {
    lookupflag 0;
    ;
    # Original source: 1970
    sub s1548 braceright by s1337;
} LigatureSubstitution1971;
```

The substitution format is `sub <previous_state> <glyph0> <glyph1> ... by <new_state>;`

So in this case the `s1548` state is substituted by the `s1337` state, when we type the character `braceright`.

We can continue to follow the rules backwards, until we reach some "initial" state.

Solve script:
```python
# decompile into fea

from fontTools.ttLib import TTFont
from fontFeatures.ttLib import unparse
import string

decomp = unparse(TTFont("chall.otf"))

fea = decomp.asFea()
print(fea)

# keep only rows with "by" in them
fea = [x.strip(" \t;") for x in fea.split("\n") if "by" in x]
# print(fea)

flag = ""
node = 1337

# define char mappings
to_name = {}
for c in string.ascii_lowercase + string.ascii_uppercase:
    to_name[c] = c

to_name["exclam"] = "!"
to_name["question"] = "?"
to_name["braceleft"] = "{"
to_name["braceright"] = "}"
to_name["underscore"] = "_"
for i, c in enumerate("zero one two three four five six seven eight nine".split()):
    to_name[c] = str(i)

for row in fea[::-1]:
    if flag.startswith("lag{"):
        break
    if row.endswith(str(node).zfill(4)):
        fields = row.split()[2:-2]
        flag = "".join([to_name[x] for x in fields]) + flag

        # print(row)
        node = int(row.split()[1][1:])

    print(flag, end="\r")

flag = "f" + flag

print(flag)

```
