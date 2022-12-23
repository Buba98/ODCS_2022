import sys

import claripy
from pwn import *
import angr as angr

def main():

    project = angr.Project("./pnrg")
    bytes_list = [claripy.BVS(f"byte_{i}", 8) for i in range(4)]
    bytes_ast = claripy.Concat(*bytes_list)
    state = project.factory.entry_state()
    simFile = angr.SimFile("/dev/random", content=bytes_ast)
    simFile.set_state(state)
    for byte in bytes_list:
        state.solver.add(byte >= 0x0)
    simulation = project.factory.simulation_manager(state)

    simulation.explore(find=successful, avoid=successful)

    for f in simulation.found:
        simulation_state = simulation.found[0]
        simulation_state.posix.dumps(sys.stdin.fileno())
        print(simulation_state.posix.dumps(0))

def successful(state):

    stdout_output = state.posix.dumps(sys.stdout.fileno())

    if state.regs.rip == 0x010164b:
        if rand in stdout_output:
            return True
        else:
            return False

r = remote("bin.training.jinblack.it", 2020)

rand = r.recvuntil(b",")[:-1]

main()