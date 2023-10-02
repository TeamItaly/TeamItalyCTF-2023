# decompile into fea

from fontTools.ttLib import TTFont
from fontFeatures.ttLib import unparse
import string

decomp = unparse(TTFont("attachments/chall.otf"))

fea = decomp.asFea()

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
