#!/usr/bin/env python

'''
We'd like to understand the stack layout of the main function by performing generating a VFG on it.
'''

from pprint import pprint
from collections import defaultdict

import angr


# create the project
project = angr.Project("fauxware")

# WRITEME: generate a CFG first so we have access to all functions
cfg = None

# WRITEME: get the address of the main function
main_func = None

# WRITEME: run VFG on it
# Here is the suggested parameter setup
# context_sensitivity_level: 3
# interfunction_level: 3
vfg = None
print("VFG analysis is over. We have some nodes now:")
if vfg is not None:
    pprint(vfg.graph.nodes())

# WRITEME: get the input state to the very last basic block
# the very last basic block in the main function is 0x80486e8
# it should have captured all previous effects
last_node = None
last_state = None

# WRITEME: Get the memory object.
# the memory used in static analysis is an abstract memory model (implemented in SimAbstractMemory)
# it's basically a mapping from region names (like "stack_0x400000") to a symbolic memory instance (SimSymbolicMemory)
memory = None
print("Program memory of the very last state: %s" % memory)

# WRITEME: Let's take a look at the regions
regions = None
print("All memory regions on the stack:")
pprint(regions)

if regions is not None:
    # WRITEME: Now we can have a look at the abstract locations (alocs) of the main function's stack region
    main_func_region = None
    alocs = None

    print("Abstract locations of the main procedure are:")
    pprint(alocs)

    # WRITEME: Derive stack layout information from abstract locations
    # you may did a little bit into the source code SimuVEX and claripy to see what members an aloc has.
    # related code are abstract_memory.py in SimuVEX and the vsa subpackage in claripy.
    # by default, region.alocs is a dict mapping (block address, statement ID) to a list of memory targets.
    # what we want is a list of stack offset and size of the corresponding memory access
    # let's do it here

    stack_layout = defaultdict(set)  # map offset to size

    # WRITEME: traverse alocs

    print("The stack layout looks like:")
    for offset in sorted(stack_layout.keys(), reverse=True):
        print("%#x %s" % (offset, stack_layout[offset]))

