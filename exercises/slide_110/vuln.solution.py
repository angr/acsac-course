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
    saved_eip = state.memory.load(state.regs.ebp + 4, 4, endness="Iend_LE")
    print("Checking saved EIP:", saved_eip)

    # first, check if the return address points to a hook. If this is intact, then we assume there is no overflow
    if project.is_hooked(state.solver.eval(saved_eip)):
        return False

    # next, create constraints representing an unsafe condition. In this case,
    # let's check if the return address can point *outside* of the program.
    unsafe_constraints = [ state.solver.Or(saved_eip < project.loader.min_addr, saved_eip > project.loader.max_addr) ]

    # check if the state is satisfiable with these conditions, and return True if it is
    return state.solver.satisfiable(extra_constraints=unsafe_constraints)

# get a new simulation manager from the project factory
simgr = project.factory.simulation_manager()

# initiate a "vuln" stash
simgr.stashes['vuln'] = [ ]

# the starting state has no return address on the stack, so it will trigger our vuln filter.
# We can step it until it no longer triggers the filter before starting the actual analysis.
print("Initializing initial state...")
while path_vuln_filter(simgr.active[0]):
    simgr.step()

# Now that we are all set up, let's loop until a vulnerable path has been found
print("Searching for the vulnerability!")
while not simgr.vuln:
    # step the simulation manager
    simgr.step()
    # after each step, move all states matching our vuln filter from the active stash to the vuln stash
    simgr.move('active', 'vuln', filter_func=path_vuln_filter)

# now synthesize our crashing input
crashing_input = simgr.vuln[0].posix.dumps(0)
open("crashing_input", "wb").write(crashing_input)
print("You can crash the program by doing:")
print("# cat crashing_input | ./overflow")
