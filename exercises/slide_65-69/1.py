#!/usr/bin/env python

from pprint import pprint

import angr

p = angr.Project("cfg_2")

# WRITEME: generate a CFG that collects data references during CFG recovery
# Note that by default it resolves indirect jumps (like jump tables)
cfg = None

# WRITEME: print out the recovered indirect jumps
indirect_jumps = None
print("Here are all indirect jumps from the binary:")
pprint(indirect_jumps)

# WRITEME: print out the recovered list of memory data
memory_data = None
print("Here are all recovered memory data from the binary:")
pprint(memory_data)

# WRITEME: print out the reversed map between instruction addresses to memory data
ins_to_memdata = None
print("Here is a mapping between instruction address and memory data:")
pprint(ins_to_memdata)

