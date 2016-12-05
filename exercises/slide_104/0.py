#!/usr/bin/env python

'''
Define a static security that prevents the "vulnerability" being triggered.
'''

import angr
import simuvex

# load the binary
project = angr.Project("fate")

# Since this is a very simple binary, it is not difficult to see the vulnerability is `fread` might read more than 128
# bytes, which overflows the buffer `buf` defined on line 6.
# Therefore a very simple security policy will be: whenever `fread` is called in this binary, make sure the third 
# argument is a number less than or equal to 128.

# In order to implement the static security policy, we'll need program states, and hopefully, states at every single 
# program point in the binary, so we can check if the security policy can be violated or not at each program point.

# now let's implement the static security policy

# WRITEME: generate a fast CFG so we can find functions in the global knowledge base
cfg_fast = None

# WRITEME: generate an accurate CFG on this binary, with proper values for those parameters
# Parameters you should care about:
# - starts
# - context_sensitivity_level
# - keep_state
# You might want to use a separate knowledge base
cfg = None

# WRITEME: find the fread function
fread_func = None

# WRITEME: find all `fread` nodes in accurate CFG
fread_nodes = [ ]

# WRITEME: for each `fread` node, check what the third argument is
# to do so, a calling convention object should be initialized, so we know where all those arguments are in the state
# this is how you can initialize a calling convention object:
#   cc = simuvex.DefaultCC[project.arch.name](project.arch)
# then you can use this cc to retrieve an argument - please refer to SimCC implementation in SimuVEX to find out 
# how to do so ;)
cc = None

for node in fread_nodes:
    if cc is None:
        continue
    third_arg = cc.arg(node.input_state, 2)
    print("The third argument is %s" % third_arg)
    if node.input_state.se.is_true(third_arg > 128):
        # ouch
        print("ALERT: possible violation at %s, identifier %s." % (node, node.simrun_key))

