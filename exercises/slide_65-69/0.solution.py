#!/usr/bin/env python

from pprint import pprint

import angr

project = angr.Project("fauxware")

# WRITEME: generate a CFG
cfg = project.analyses.CFG()

# WRITEME: print out all nodes
all_nodes = cfg.nodes()
pprint(all_nodes)

# WRITEME: get any CFG node whose address is 0x80485fc
# 0x80485fc is the address of main()
node = cfg.get_any_node(0x80485fc)
print("Node 0x80485fc: %s" % node)

# WRITEME: get all CFG node whose address is 0x80485fc
node_list = cfg.get_all_nodes(0x80485fc)
print("All node whose address is 0x80485fc: %s" % node_list)

# WRITEME: get a list of successors of that node, including the fakeret target, using methods from the CFG
successors = cfg.get_successors(node, excluding_fakeret=False)
print("All successors to node %s are:" % node)
pprint(successors)

# WRITEME: get a list of successors of that node, using the `successor` property from the CFG node itself
# this time it does not include the fakeret target
successors = node.successors
print("All successors to node %s are:" % node)
pprint(successors)

