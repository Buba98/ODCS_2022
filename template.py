from pwn import *

def main():
    if "REMOTE" not in args:

        env = {}

        ssh = ssh("acidburn", "127.0.0.1", password="acidburn", port=2222)
        r = ssh.process("sh3llc0d3", env=env)
        gdb.attach(r, """
            # b *0x0804841c
            # c
            set resolve-heap-via-heuristic on
            """)

        input("wait")
    else:
        r = remote("bin.training.jinblack.it", 2010)

    r.recvuntil("What is your name?")

    payload = b''

    r.send(payload)

    r.interactive()

main()