

'''

    NOT used anymore -> integrated in r4ge.py

'''


import angr, r2pipe, sys, IPython
from termcolor import colored
from Helper.r4geHelper import *
from Helper.memStoreHelper import *
from Helper.hookHandler import *

# create r2 connection
rzproj = createR2Pipe()
if rzproj == None:
    print(colored("only callable inside a r2-instance!", "red", attrs=["bold"]))
    exit(0)
isX86 = isArchitectureX86(rzproj)

# get offsets from flags
find_offset, avoid_offsets, start_offset = getOffsets(rzproj)
print(colored("start: {}, find:{}, avoid:{}".format(hex(start_offset),
    hex(find_offset), [hex(x) for x in avoid_offsets]), "green"))

# get binary name and create angr project
binaryname = getBinaryName(rzproj)
proj = angr.Project(binaryname, load_options={"auto_load_libs":False})

# create call function
callstate = proj.factory.call_state(start_offset)

# set up hooks for symbolic execution
hook_variables = getHooks( rzproj )
if len(hook_variables) != 0:
    for hook in hook_variables:
        # 0=address, 1=patch_length, 2=instructions
        proj.hook(hook[0], make_hook(hook[2]), length=hook[1])
        print(colored("setup Hook: {}, addr: {}, patchlength: {}, instr: {}".format( hook[3], hex(hook[0]), hook[1], hook[2] ), "green"))

# get all asserts
assert_variables = getAsserts( rzproj ) # 0=offset, 1=comparisons, 2=comment
if len(assert_variables):
    for ass in assert_variables:
        proj.hook(ass[0], make_assert(ass[1], ass[2]), length=0)
        print(colored("setup Assert: {}, addr: {}, compare: {}".format( ass[2], hex(ass[0]), ass[1] ), "green"))


# setup path group for exploration
pg = proj.factory.path_group(callstate)

# explore binary
find_offset = getBasicBlockAddr(proj, find_offset)
pg.explore(find=getFindFunction(pg, find_offset, isX86), avoid=avoid_offsets)
#pg.explore(find=find_offset, avoid=avoid_offsets)
print("\n",pg)

state_found = None
if len(pg.found) == 0:
    print(colored("no way found, sorry...", "red", attrs=["bold"]))
else:
 state_found = pg.found[0].state # get found state

print(colored('''
Script-Variables:
    proj        ... angr project
    callstate   ... start state
    pg          ... path_group
{}'''.format("    state_found ... result state of exploration\n" if state_found is not None else ""), "green"))

# open IPython shell
IPython.embed()
