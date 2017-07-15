'''
    main plugin file to perform symbolic execution
'''
import r2pipe, angr, simuvex, IPython
from termcolor import colored
from Helper.memStoreHelper import *
from Helper.hookHandler import *
from Helper.r4geHelper import *

# connect to r2
r2proj = createR2Pipe()
if r2proj == None:
    print colored("only callable inside a r2-instance!", "red", attrs=["bold"])
    exit(0)

# check if we in a debug session, use dynamic or static mode
inDebug = inDebugSession(r2proj)
if inDebug:
    print colored("start r4ge in DYNAMIC mode...", "blue", attrs=["bold"])
else:
    print colored("start r4ge in STATIC mode...", "blue", attrs=["bold"])

# get flag offsets
find_offset, avoid_offsets, start_offset = getOffsets(r2proj)
if ( find_offset == 0 ):
    print colored("no find flag found... stop execution", "red", attrs=["bold"])
    exit(0)
if ( inDebug == False and start_offset == 0):
    print colored("no start flag found, this is necessary for using the static mode! \nstop execution", "red", attrs=["bold"])
    exit(0)

# get binary name and create angr project
binaryname = getBinaryName(r2proj)
angrproj = angr.Project(binaryname, load_options={"auto_load_libs":False})
isX86 = isArchitectureX86(r2proj) # get the architecture type x86 or x64

if inDebug:
    # prepare dynamic execution

    start_state = angrproj.factory.blank_state(remove_options={simuvex.o.LAZY_SOLVES})

    # get symbolic memory region, 0=offset, 1=size, 2=name
    symb_memories = getSymbolicMemoryRegions(r2proj)
    if len(symb_memories) == 0:
        print colored("no symbolic memory found... stop execution", "red", attrs=["bold"])
        exit(0)

    # copy registers to blank(start) state
    current_stack_pointer = copyRegisterValues( r2proj, start_state, isX86)

    # copy Stack
    stack_start = getStackStart( r2proj )
    stack_size = stack_start - current_stack_pointer
    print colored("setup Stack: {0}-{1}, size: {2}".format( hex(stack_start), hex(current_stack_pointer), stack_size), "green")
    setupMemoryRegion( r2proj, start_state, current_stack_pointer, stack_size, isX86 )

    # copy Heap ( if there is some used )
    (top_chunk, brk_start) = checkForHeap( r2proj )
    if top_chunk != 0 and brk_start != 0:
        heap_size = top_chunk - brk_start
        print colored("setup Heap: {0}-{1}, size: {2}".format( hex(top_chunk), hex(brk_start), heap_size ), "green")
        setupMemoryRegion( r2proj, start_state, brk_start, heap_size, isX86 )

    # now set symbolic memory, adds symbolic variable to symb_memories list entries
    setSymbolicMemoryRegions( r2proj, start_state, symb_memories )

else:
    # prepare static execution -> no copying of the memory

    start_state = angrproj.factory.call_state(start_offset, remove_options={simuvex.o.LAZY_SOLVES})


# set up hooks for symbolic execution
hook_variables = getHooks( r2proj )
if len(hook_variables) != 0:
    for hook in hook_variables:
        # 0=address, 1=patch_length, 2=instructions
        angrproj.hook(hook[0], make_hook(hook[2]), length=hook[1])
        print colored("setup Hook: {}, addr: {}, patchlength: {}, instr: {}".format( hook[3], hex(hook[0]), hook[1], hook[2] ), "green")

# get all asserts
assert_variables = getAsserts( r2proj ) # 0=offset, 1=comparisons, 2=comment
if len(assert_variables):
    for ass in assert_variables:
        angrproj.hook(ass[0], make_assert(ass[1], ass[2]), length=0)
        print colored("setup Assert: {}, addr: {}, compare: {}".format( ass[2], hex(ass[0]), ass[1] ), "green")

# start the symbolic execution
print colored("start symbolic execution, find:{}, avoid:{}".format(hex(find_offset), [hex(x) for x in avoid_offsets]), "blue", attrs=["bold"])
pg = angrproj.factory.path_group(start_state)

# convert find_offsets to basic block address
find_offset = getBasicBlockAddr(angrproj, find_offset)
pg.explore(find=getFindFunction(pg, find_offset, isX86), avoid=avoid_offsets)
#pg.explore(find=find_offset, avoid=avoid_offsets)
print "\nPathGroup Results:",pg


state_found = None
if len(pg.found) == 0:
    print colored("no way found, sorry...", "red", attrs=["bold"])
else:
    state_found = pg.found[0].state # get found state
    #print state_found.state.se.constraints # DEBUG: print the constraints of the path

if inDebug:
    # debug mode: concrete symbolic memory and print it
    # give user possiblity to continue execution at find target

    if state_found == None:
        exit(0)

    # 0=offset, 1=size, 2=name, 3=symb_var
    for symb_memory in symb_memories:
        symb_memory.append( state_found.se.any_str(symb_memory[3]) )
        # value_int = state_found.state.se.any_int(symb_memory)
        # state_found.memory.load(symb_addr, symb_size)
        print colored("symbolic memory - str: {0} , hex: 0x{1} ".format(symb_memory[4], symb_memory[4].encode('hex')), "green")
        #print "dumps(1):",state_found.posix.dumps(1) # maybe also print the posix dumps

    # debug to find address, step until r2-command
    jump_to_find = raw_input("You want to set debugsession to find address (y/n)? ")
    if jump_to_find == "y":

        print colored("concretize symbolic memory in r2...", "green")
        for symb_memory in symb_memories:
            concretizeSymbolicMemory(r2proj, symb_memory[0], symb_memory[4])

        print "jump to find address"
        r2proj.cmd("dsu {0}".format( find_offset ))

else:
    # static mode: open ipython shell to perform concretization byself

    print colored('''
    Script-Variables:
        proj        ... angr project
        callstate   ... start state
        pg          ... path_group
    {}'''.format("    state_found ... result state of exploration\n" if state_found is not None else ""), "green")

    # open IPython shell
    IPython.embed()
