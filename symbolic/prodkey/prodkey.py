import claripy
from pwn import *
import angr as angr

def main():

    project = angr.Project("prodkey")
    chars = [claripy.BVS('c%d' % i, 8) for i in range(30)]  # 20 bytes
    input_string = claripy.Concat(*chars + [claripy.BVV(b'\n')])  # + \n
    initial_state = project.factory.entry_state(stdin=input_string)

    for c in chars:
        initial_state.solver.add(c >= 0x20, c <= 0x7e)

    simulation = project.factory.simulation_manager(initial_state)

    simulation.explore(find=0x400e4e)

    if simulation.found:
        print(simulation.found[0].posix.dumps(0))

main()