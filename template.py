from pwn import *

if "REMOTE" not in args:

    env = {}

    ssh = ssh("buba98", "127.0.0.1", password="Vinsent22!", port=2222)
    r = ssh.process("sh3llc0d3", env=env)
    gdb.attach(r, """
        # b *0x0804841c
        # c
        """)

    input("wait")
else:
    r = remote("bin.training.jinblack.it", 2010)

r.recvuntil("What is your name?")

payload = b''

r.send(payload)

r.interactive()
