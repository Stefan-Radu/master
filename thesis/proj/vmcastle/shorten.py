data = open("./disass", "r").readlines()

out = []
start = None
nr = 0

for l in data:
    if 'top' in l:
        if start is None:
            start = l.split()[0]
            nr = 0
        val = int(l.split()[2])
        if 'add' in l:
            nr += val
        else:
            assert 'shl' in l
            nr <<= val
    elif 'nop' in l:
        continue
    else:
        if start is not None:
            out.append(f'{start}  stack top() = {nr}\n')
            start = None
        out.append(l)

f = open("./shorten_dis", "w")
f.write("".join(out))
