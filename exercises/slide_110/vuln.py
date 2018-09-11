import angr

# load the binary
project = angr.Project("overflow", auto_load_libs=False)

# Make a simple security checker that checks for an overflow into the return address. There are several cases:
#
# 1. The return address is unchanged and pointing to an internal angr hook (i.e., __libc_start_main)
# 2. The return address is unchanged and pointing inside the program (normal case)
# 3. The return address has been overflowed, and we can point it outside of the program (we'll check for this)
# 4. The return address has been partially overflowed, and still points inside the program (future work)
def path_vuln_filter(state):
    # get the saved instruction pointer from the stack
    pass
    print("Checking saved EIP:", saved_eip)

    # first, check if the return address points to a hook. If this is intact, then we assume there is no overflow
    pass

    # next, create constraints representing an unsafe condition. In this case,
    # let's check if the return address can point *outside* of the program.
    pass

    # check if the state is satisfiable with these conditions, and return True if it is
    pass

# get a new simulation manager from the project factory
simgr = project.factory.simulation_manager()

# initiate a "vuln" stash
simgr.stashes['vuln'] = []

# the starting path has no return address on the stack, so it will trigger our vuln filter.
# We can step it until it no longer triggers the filter before starting the actual analysis.
print("Initializing initial state...")
while path_vuln_filter(simgr.active[0]):
    simgr.step()

# Now that we are all set up, let's loop until a vulnerable path has been found
print("Searching for the vulnerability!")
while not simgr.vuln:
    # step the simulation manager
    pass
    # after each step, move all states matching our vuln filter from the active stash to the vuln stash
    pass

# now synthesize our crashing input
pass
open("crashing_input", "wb").write(crashing_input)
print "You can crash the program by doing:"
print "# cat crashing_input | ./overflow"
