# Generator for level1, obfuscates a little the flag path in the font

import random, os, string, math, sys
# random.seed(os.urandom(8))
random.seed(696969696969696969)

## Constants ##
FLAG = "flag{f0nt_l1g4tur3s_c4n_b3_4_f1n173_s7at3_m4ch1n3!!}"
L = len(FLAG)
N = 2048 # number of nodes
WIN = 1337 # winning node

# mmm i could link the losing states to the root

## Generate the states tree ##
order = list(range(N))
del order[WIN] # remove winning node from the list
random.shuffle(order)

print(f"Generating tree of {N} nodes...")
print(f"Flag chain is {L} nodes long")

ROOT = order[0]
parent = [-1] * N
char = [""] * N

# Create flag chain
i = 1 # skip the first node
c = 1 # skip the first char
while 2:
    num_chars = min(random.choice([1,1,1,1,1,1,2,2,2,3]), L-c)

    if c+num_chars == L:
        # last node
        parent[WIN] = order[i-1]
        char[WIN] = FLAG[c:c+num_chars]
        break
    parent[order[i]] = order[i-1]
    char[order[i]] = FLAG[c:c+num_chars]

    i += 1
    c += num_chars

# Create the rest of the tree
flag_chain = order[:i]
order = order[i:]

NON_FLAG_CHAIN = 12

for i, u in enumerate(order):
    if i % NON_FLAG_CHAIN == NON_FLAG_CHAIN-1:
        # Sometimes, add a node to a random non-flag_chain node
        p = random.choice(order[:i])
    else:
        p = random.choice(flag_chain)
    
    parent[u] = p

# Build adjacency list
AL = [list() for _ in range(N)]
for i in range(N):
    if i == ROOT:
        continue
    AL[parent[i]].append(i)

assert len(AL[WIN]) == 0

# Count number of leaves
leaves = []
for i in range(N):
    if AL[i] == []:
        leaves += [i]

flag_path_degrees = [len(AL[i]) for i in flag_chain]

print(f"Done generating: root is {ROOT}, it has {len(leaves)} leaves")
print(f"Flag path degrees: {flag_path_degrees}, length {len(flag_chain)}")
print(f"Flag path: {flag_chain + [WIN]}")

if "PLOT" in sys.argv:
    from treelib import Node, Tree
    tree = Tree()
    tree.create_node(ROOT, ROOT) # root node
    for i in flag_chain + [WIN] + order:
        if i == ROOT:
            continue
        tree.create_node(i, i, parent=parent[i])
    
    print(tree)
    exit()

# Shuffle the order of the AL
for i in range(N):
    random.shuffle(AL[i])

## Write the tree in the font following a BFS ##
print("Writing the .fea file for the substitutions...")
to_name = {}
for c in string.ascii_lowercase + string.ascii_uppercase:
    to_name[c] = c

to_name["!"] = "exclam"
to_name["?"] = "question"
to_name["{"] = "braceleft"
to_name["}"] = "braceright"
to_name["_"] = "underscore"
for i, c in enumerate("zero one two three four five six seven eight nine".split()):
    to_name[str(i)] = c

nam = lambda i: f"s{str(i).zfill(4)}"

# define variables (won't work if WIN == 0000 or 9999)
source = ""
source += "@flag_chars = [exclam zero one two three four five six seven eight nine question A-Z underscore braceleft braceright a-z];\n"

state = list(range(N))
del state[WIN] # remove winning node from the list
state_str = " ".join([nam(i) for i in state])
source += f"@states = [{state_str}];\n"

del leaves[leaves.index(WIN)] # remove winning node from the list
leaves_str = " ".join([nam(i) for i in leaves])
source += f"@leaves = [{leaves_str}];\n"

# define the entrypoint (lookups are applied in order)
source += """
@all = [@states @flag_chars];

feature rlig {
    # Thank you https://github.com/mmulet/code-relay/blob/main/markdown/HowIDidIt.md
    lookup goodentry {
        ignore substitute @all @flag_chars';
        substitute f' by {0};
    } goodentry;

    lookup badentry {
        ignore substitute [@all equal] @flag_chars';
        substitute @flag_chars' by equal;
    } badentry;
""".replace("{0}", nam(ROOT))

# use bfs to hide the flag path
flag_chain += [WIN]

queue = [ROOT]
while queue:
    u = queue.pop()
    edges = list([] for _ in range(3)) # one for each len
    chars = [""]

    for v in AL[u]:
        if v in flag_chain:
            chars.append(char[v])

    # reorder chars to avoid a shorter lookup to be applied over a longer one
    # btw new generated chars could make an existing path unreachable but as long as the flag path is reachable it's fine
    for v in AL[u]:
        if char[v] == "":
            while char[v] in chars: # avoid duplicates
                num_chars = random.choice([1,1,1,1,1,1,2,2,2,3])
                char[v] = "".join(random.choices(list(to_name.keys()), k=num_chars))
            chars.append(char[v])

        edges[len(char[v])-1].append(v)

    # now add the lookups
    edges = edges[2] + edges[1] + edges[0]

    for v in edges:
        source += f"""
    lookup edge{v} {{
        sub {nam(parent[v])} {" ".join([to_name[c] for c in char[v]])} by {nam(v)};
    }} edge{v};
    """
        queue.append(v)

source += """
    # in the end, if nothing matches, remove the char added
    lookup losing_default {
        sub @flag_chars by NULL;
    } losing_default;
} rlig;
"""

with open("autofeat.fea", "w") as f:
    f.write(source)