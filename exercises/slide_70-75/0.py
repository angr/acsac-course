#!/usr/bin/env python

'''
Generate an accurate CFG on the fauxware binary, and take a look at its program states.
'''

import angr

# load the binary
project = angr.Project("fauxware")

# WRITEME: generate an accurate CFG
# since we want to see its program states generated during CFG recovery, we should specify 'keep_state=True'
cfg = None

# Alright, we got it!
if cfg is not None:
    all_nodes = cfg.nodes()

    for n in all_nodes:
        print("%s:\t\tstate %s, eax %s, ecx %s" % (n, n.input_state, n.input_state.regs.eax, n.input_state.regs.ecx))

