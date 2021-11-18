from pwn import *

r = remote('140.113.207.240',8833)
r.recvuntil('Give me some input:')
r.sendline('')
r.recvuntil('Anything else to translate?(y/n)')
r.sendline('n')
r.recvuntil('Tell me what are you looking for in my language:')
r.sendline('<6A;')  # 130 - ascii(<6A;) = FLAG
r.interactive()
