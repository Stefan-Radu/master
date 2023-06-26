
def gcd(x: int, y: int):
    if y == 0:
        return x
    return gcd(y, x%y)
 
def lcm(x: int, y: int):
    return int(x * y/gcd(x, y))


primes: list[int] = []
primes_set: set[int] = set()

def generate_primes() -> None:
    global primes, primes_set

    skip: set[int] = set()
    how_many: int = 1000
    for i in range(2, how_many + 1):
        if i in skip:
            continue
        primes.append(i)
        for j in range(i*i, how_many + 1, i):
            skip.add(j)

    primes_set = set(primes)


def factorize(k):
    global primes, primes_set

    resp = (0, 0)
    for p in primes:
        if k % p == 0:
            l = k // p
            assert l in primes_set
            assert l * p == k
            resp = (p, l)
            break
    return resp


def modular_inverse(k, mod):
    for inv in range(mod):
        if (k * inv) % mod == 1:
            return inv
    return -1

generate_primes()

#####################
### RSA
#####################

def solve_rsa(mod, e, c):
    print("===========\nSOLVE RSA\n===================\n")
    print(f"Modulo: {mod}, e: {e}, c: {c}\n")
    a, b = factorize(mod)
    print(f"factorization of {mod}: {a}, {b}")

    lda = lcm(a - 1, b - 1)
    print(f"\nlambda({mod}) = lcm({a} - 1, {b} - 1) = {lda}")

    d = modular_inverse(e, lda)
    print(f"\nAs {d} * {e} = 1 (mod {lda}), the private key\n" \
          f"d = e ^ -1 (mod lambda(N)) =\n{e} ^ -1 (mod {lda}) = {d}")

    m = (c ** d) % mod
    print(f"\nm = {c} ^ d (mod {mod}) = {m}")

# solve_rsa(35, 5, 33)

#####################
### Additive Elgamal
#####################

def additive_inverse(d, i, mod, coeff):
    c = d // i
    r = d - c * i
    print(f"=> {d} = {c} * {i} + {r}")
    if r == 1:
        print(f"\n===> {r} = {d % mod} - {c} * {i}")
        return -c

    ret = additive_inverse(i, r, mod, -c)
    print(f"===> {r} = {d % mod} - {c} * {i}")
    return ret * coeff



def additive_elgamal(n, g, h, c: tuple[int, int]):
    r = additive_inverse(n, g, n, -1)
    print(r)
    pass


# additive_elgamal(1000, 667, 21, (81, 27))


#####################
### Secrety Muliparty Computation
#####################

def smc(vals, add_coeff, mul_coeff):
    from pprint import pprint
    mat = [[], [], []]

    n = len(vals)

    for i in range(n):
        for j in range(n):
            mat[i].append(add_coeff[i] * (j + 1)  + vals[i])

    print ("        A   B  C")
    for i, m in enumerate(mat):
        print(f"{add_coeff[i]}X + {vals[i]}", end='  ')
        pprint(m)

    print("Pentru ei locali arata cam asa de fapt")

    print ("\n    A   B  C")
    for i, m in enumerate(mat):
        print(f"{chr(i + ord('x'))}", end='  ')
        pprint(m)

    print("\nLocal Additions:")
    names = ["Alice", "Bob", "Cathy"]

    line = []
    for i, name in enumerate(names):
        a = mat[0][i]; b = mat[1][i]
        summed = a + b
        print(f"{name} {a} + {b} = {summed}")
        line.append(summed)
    mat.append(line)

    print("\nLocal Multiplications:")
    new_vals = []
    for i, n in enumerate(names):
        a = mat[3][i]; b = mat[2][i]
        prod = a * b
        print(f"{n} {a} * {b} = {prod}")
        new_vals.append(prod)

    n = len(vals)
    new_mat = [[], [], []]
    for i in range(n):
        for j in range(n):
            new_mat[i].append(mul_coeff[i] * (j + 1) + new_vals[i])

    print("\nCollaborative Multiplication")
    print ("          A   B  C")
    for i, m in enumerate(new_mat):
        print(f"{mul_coeff[i]}X + {new_vals[i]}", end='  ')
        pprint(m)

    print("\nLocal recombinations")
    final_vals = []
    for j in range(n):
        a = new_mat[0][j]
        b = new_mat[1][j]
        c = new_mat[2][j]
        res = 3 * a - 3 * b + c
        print(f"{names[j]} 3 * {a} - 3 * {b} + {c} = {res}")
        final_vals.append(res)

    print("\nFinal Recombination")

    a = final_vals[0]
    b = final_vals[1]
    c = final_vals[2]

    res = 3 * a - 3 * b + c
    print(f"3 * {a} - 3 * {b} + {c} = {res}")

    print("\nVerificare")
    print(f"xz + yz = {vals[0]} * {vals[2]} +"\
          f"{vals[1]} * {vals[2]} = "\
          f"{vals[0] * vals[2]} + {vals[1] * vals[2]} = "\
          f"{vals[0] * vals[2] + vals[1] * vals[2]}")

# smc([1, 2, 3], [1, 2, 3], [2, 3, 1])

# for i in range(256):
    # if (i ** 64) % 256 == 1:
        # print(i)

for i in range(256):
    if (i ** 64) % 256 == 1:
        print(i)
