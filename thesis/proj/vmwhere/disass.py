f = open("./program", "rb")
ops = f.read()[3:]

pc = 0
len = len(ops)

def concat(x, y):
    mx = 255 << 8 | 255
    val = (x << 8) | y
    if (val > (mx >> 1)):
        return -(mx - val + 1)
    return val

while pc < len:
    curr_op = ops[pc]
    if curr_op == 0:
        print(f'{pc}: return 0')
        exit(0)
    elif curr_op == 1:
        print(f'{pc}: add stack[-2], stack[-1]; pop')
        pc += 1
    elif curr_op == 2:
        print(f'{pc}: sub stack[-2], stack[-1]; pop')
        pc += 1
    elif curr_op == 3:
        print(f'{pc}: and stack[-2], stack[-1]; pop')
        pc += 1
    elif curr_op == 4:
        print(f'{pc}: or stack[-2], stack[-1]; pop')
        pc += 1
    elif curr_op == 5:
        print(f'{pc}: xor stack[-2], stack[-1]; pop')
        pc += 1
    elif curr_op == 6:
        print(f'{pc}: shl stack[-2], stack[-1] ^ 0x1f; pop')
        pc += 1
    elif curr_op == 7:
        print(f'{pc}: shr stack[-2], stack[-1] ^ 0x1f; pop')
        pc += 1
    elif curr_op == 8:
        print(f'{pc}: x = input(); push(x)')
        pc += 1
    elif curr_op == 9:
        print(f'{pc}: print(pop())')
        pc += 1
    elif curr_op == 10:
        print(f'{pc}: push {ops[pc + 1]} (prog); {chr(ops[pc + 1])}')
        pc += 2
    elif curr_op == 11:
        cc = concat(ops[pc + 1], ops[pc + 2])
        print(f'{pc}: cc = {ops[pc + 1]} || {ops[pc + 2]};', end=' ')
        print(f'if stack[-1] < 0 then jump to {pc + 3 + cc}')
        pc += 3
    elif curr_op == 12:
        cc = concat(ops[pc + 1], ops[pc + 2])
        print(f'{pc}: cc = {ops[pc + 1]} || {ops[pc + 2]};', end=' ')
        print(f'if stack[-1] == 0 then jump to {pc + 3 + cc}')
        pc += 3
    elif curr_op == 13:
        cc = concat(ops[pc + 1], ops[pc + 2])
        print(f'{pc}: cc = {ops[pc + 1]} || {ops[pc + 2]};', end=' ')
        print(f'jump to {pc + 3 + cc}')
        pc += 1 + 2
    elif curr_op == 14:
        print(f'{pc}: pop')
        pc += 1
    elif curr_op == 15:
        print(f'{pc}: push stack[-1]')
        pc += 1
    elif curr_op == 16:
        val = ops[pc + 1]
        print(f'{pc}: reverse stack[-{val}:]')
        pc += 2
    elif curr_op == 17:
        print(f'{pc}: bit_spread')
        pc += 1
    elif curr_op == 18:
        print(f'{pc}: bit_compress')
        pc += 1
    elif curr_op == 40:
        print(f'{pc}: debug')
        pc += 1
    else:
        print(f'{pc}: unknown opcode')
        print('return 1')
        exit(1)
