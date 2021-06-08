
import angr, r2pipe, sys, IPython
from termcolor import colored
from Helper.r4geHelper import *
from Helper.memStoreHelper import *
from Helper.hookHandler import *

# create r2 connection
r2proj = createR2Pipe()
if r2proj == None:
    print(colored("only callable inside a r2-instance!", "red", attrs=["bold"]))
    exit(0)

isX86 = isArchitectureX86(r2proj)
print("isX86: {}".format(isX86))

# get Offsets, we only need start_offset for callable
_, _, start_offset = getOffsets(r2proj)

# get parameters
expected_result = int(sys.argv[1], 16)

# get binary name and create angr project
binaryname = getBinaryName(r2proj)
proj = angr.Project( binaryname, load_options={"auto_load_libs":False})

# setup hooks
hook_variables = getHooks( r2proj )
if len(hook_variables) != 0:
    for hook in hook_variables:
        # 0=address, 1=patch_length, 2=instructions
        proj.hook(hook[0], make_hook(hook[2]), length=hook[1])
        print(colored("setup Hook: {}, addr: {}, patchlength: {}, instr: {}".format( hook[3], hex(hook[0]), hook[1], hook[2] ), "green"))

# create call function
callstate = proj.factory.callable( start_offset )

# call callstate with paramter
print("start calling address: {}".format(hex(start_offset)))
callstate()
print("finished execution of function")

# add expected function result as extra constraint
if isX86:
    callstate.result_state.add_constraints( callstate.result_state.regs.eax == expected_result )
else:
    callstate.result_state.add_constraints( callstate.result_state.regs.rax == expected_result )

print(colored('''
Script-Variables:
    proj       ... angr project
    callstate  ... callable start function
''', "green"))

# open IPython shell
IPython.embed()
