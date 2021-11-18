from pwn import *

r = remote('140.113.207.240',8831)
r.recvuntil('Give me a magic number')
r.sendline('3735928495') # 0xDEADBEAF
r.recvuntil('OK, then give me a magic string')
r.sendline('YOUSHALLNOTPASS')
r.interactive()
