from pwn import *
import datetime as dt

def main():

    remote_process = remote("bin.training.jinblack.it", 2020)

    remote_output = remote_process.recvuntil(b",")[:-1]

    print(f"To find: {remote_output}")

    start_date = dt.datetime.now()

    seed = 1

    local_process = process("./pathed_elf/4_loop")

    print()

    while True:

        local_process.send(seed.to_bytes(4, "little"))

        local_output = local_process.recvuntil(b",")[:-1]

        if local_output == remote_output:
            break
        elif seed > 0xffffffff:
            print("Problem")

        seed+=1

        local_process.recv()

    print("1")

    print(remote_process.recv())

    remote_process.send(b"%#x" % seed)

    print(f"flag: {remote_process.recv()}")

    end_date = dt.datetime.now()

    print((end_date-start_date).seconds)

main()
