#!/usr/bin/env python

'''
Demonstrate how to normalize a CFG
'''

from pprint import pprint

import angr

# load the binary
project = angr.Project('fauxware')

# WRITEME: to generate a normalized CFG, simply specify `normalize=True` during initialization
cfg_norm = project.analyses.CFG(normalize=True)

# this is a normal CFG
cfg = project.analyses.CFG()

# There should be some different nodes
if cfg_norm is not None:
    nodes_norm = cfg_norm.nodes()
    nodes = cfg.nodes()

    nodes_only_in_normalized = set()

    for n in nodes_norm:
        if any([nn for nn in nodes if nn.addr == n.addr and nn.size == n.size]):
            continue
        nodes_only_in_normalized.add(n)

    assert nodes_only_in_normalized
    pprint(nodes_only_in_normalized)

