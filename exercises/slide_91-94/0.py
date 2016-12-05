#!/usr/bin/env python

'''
We'd like to figure out the dependency between registers and memory variables in function authenticate
'''

from pprint import pprint

import angr

# load the project

p = angr.Project("fauxware")

# WRITEME: get the address of function `authenticate`
cfg_fast = None
main_func = None
auth_func = None

# Note: we create a new knowledge base to use with CFGAccurate and DDG analysis
# we don't want to mess with the default (project-level) knowledge base
# this is just a good habit :-)
kb = angr.knowledge_base.KnowledgeBase(p, p.loader.main_bin)

# WRITEME: generate an accurate CFG
# Recommended parameters:
# starts=(main_func,addr,)
# context_sensitivity_level=2
# keep_state=True  # states must be kept and stored to allow dependence analysis later
cfg = None

# WRITEME: initialize DDG analysis with the accurate CFG and the new knowledge base, and specify the `start`
ddg = None

if ddg is not None:
    # YES it's done! Let's see what's there
    print("=== Statement Dependence Graph ===")
    print("Edges:")
    edges = ddg.graph.edges(data=True)
    pprint(edges, width=120)

    print("=== Data Dependence Graph ===")
    print("Edges:")
    edges = ddg.data_graph.edges(data=True)
    pprint(edges, width=120)

    print("=== Simplified Data Dependence Graph ===")
    print("Edges:")
    edges = ddg.simplified_data_graph.edges(data=True)
    pprint(edges, width=120)

