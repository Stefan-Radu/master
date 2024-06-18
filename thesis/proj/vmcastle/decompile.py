#! /usr/bin/env python3

ops = open("./program", "rb").read()

s = set()

base_address = 0x00105020
threshold = 816

stack = [0] * 0x1000
sp = 0
regs = [0] * 4

fun_names = {
    0x105350: "pop_reg",
    0x105358: "push_reg",
    0x105360: "push", # push arg on stack
    0x105368: "add_r3_r1_r2",
    0x105370: "sub_r3_r1_r2",
    0x105380: "div_r3_r1_r2",
    0x105378: "mul_r3_r1_r2",
    0x105388: "mod_r3_r1_r2",
    0x105390: "pc_add_reg",
    0x105398: "cond_jmp",
    0x1053a0: "cmp",  # cmp regs[1] and regs[0] and set regs[3] flag
    0x1053a8: "print_reg",
    0x1053b0: "read_reg",
    0x1053b8: "str3k_top_shl_lsb",
    0x1053c0: "str3k_top_add_lsb", # add lsb of arg to stack top
    0x1053c8: "exit",
}

foo_rev = {
    "pop_reg": 0x105350,
    "push_reg": 0x105358,
    "push": 0x105360,
    "add_r3_r1_r2": 0x105368,
    "sub_r3_r1_r2": 0x105370,
    "div_r3_r1_r2": 0x105380,
    "mul_r3_r1_r2": 0x105378,
    "mod_r3_r1_r2": 0x105388,
    "pc_add_reg": 0x105390,
    "cond_jmp": 0x105398,
    "cmp": 0x1053a0,
    "print_reg": 0x1053a8,
    "read_reg": 0x1053b0,
    "str3k_top_shl_lsb": 0x1053b8,
    "str3k_top_add_lsb": 0x1053c0,
    "exit": 0x1053c8,
}

def reg_val(val):
        if val >= 128:
            val = (val - 256)
        return val

cnt = 0
pc = 0
while pc < len(ops):
    arg = int(ops[pc + 1])
    offset = int(ops[pc]) << 3

    print(f"{pc:04}: ", end='')
    if offset < threshold:
        print(f'nop {arg}')
    else:
        offset += base_address
        nxt = (int(ops[pc + 2]) << 3) + base_address
        if offset == foo_rev['push'] and \
                nxt == foo_rev['str3k_top_add_lsb']:
            argn = int(ops[pc + 3])
            pc += 2
            val = arg
            while nxt == foo_rev['str3k_top_add_lsb'] or \
                    nxt == foo_rev['str3k_top_shl_lsb']:
                if nxt == 0x1053b8:
                    val <<= (argn&1)
                elif nxt == 0x1053c0:
                    val += (argn&1)
                pc += 2
                nxt = (int(ops[pc]) << 3) + base_address
                argn = int(ops[pc + 1])

            assert(nxt == foo_rev['pop_reg'])
            # TODO probabil trebuie truncate?
            # SAAAAAAAU se suprascriu toti registii deodata
            # TRE verificat in asm
            print(f'regs[{argn&3}] = {val}')
        elif offset == 0x105350:
            print(f'regs[{arg&3}] = pop() | {reg_val(stack[sp])}')
            regs[arg & 3] = reg_val(stack[sp])
            sp -= 1
            sp %= 0x400
        elif offset == 0x105358:
            print(f'push(regs[{arg & 3}])')
            sp += 1
            stack[sp] = regs[arg & 3]
            sp %= 0x400
        elif offset == 0x105360:
            print(f'push({arg})')
            sp += 1
            stack[sp] = arg
        elif offset == 0x105368:
            print(f'r3 = r1 + r0')
            regs[3] = reg_val(regs[1] + regs[0])
        elif offset == 0x105370:
            print(f'regs[3] = r1 - r0')
            regs[3] = reg_val(regs[1] - regs[0])
        elif offset == 0x105378:
            print(f'regs[3] = r1 * r0')
            regs[3] = reg_val(regs[1] * regs[0])
        elif offset == 0x105380:
            print(f'regs[3] = r1 / r0')
            regs[3] = reg_val(regs[1] // regs[0])
        elif offset == 0x105388:
            print(f'regs[3] = r1 % r0')
            regs[3] = reg_val(regs[1] % regs[0])
        elif offset == 0x105390:
            print(f'pc += regs[{arg & 3}] -> {pc + regs[arg&3] * 2}')
        elif offset == 0x105398:
            print(f'{fun_names[offset]} -> regs[3]: {regs[3]} ? |' \
                f'0 : {pc + regs[1] * 2:04} | <0 : {pc + regs[0] * 2:04} | >0 : {pc + regs[2] * 2:04}')
        elif offset == 0x1053a0:
            print(f'{fun_names[offset]} -> regs[0] ?= regs[1] | {regs[0]} ?= {regs[1]}')
            if regs[1] == regs[0]: regs[3] = 0
            elif regs[0] < regs[1]: regs[3] = -1
            else: regs[3] = 1
        elif offset == 0x1053a8:
            print(f'{fun_names[offset]} regs[{arg&3}] | {regs[arg&3]} | {chr(regs[arg&3])}')
        elif offset == 0x1053b0:
            print(f'regs[{arg&3}] = input()')
            regs[arg&3] = reg_val(int(input()))
        elif offset == 0x1053b8:
            print(f'top() <<= {arg&1}')
            stack[sp] <<= (arg&1)
        elif offset == 0x1053c0:
            print(f'top() += {arg&1}')
            stack[sp] += (arg&1)
        elif offset == 0x1053c8:
            print(f'{fun_names[offset]}')
            exit(0)
        else:
            print("unknown instruction")
    pc += 2
