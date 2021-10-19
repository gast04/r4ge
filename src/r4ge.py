'''
    main plugin file to perform symbolic execution
'''
import r2pipe, angr, IPython, threading, time, logging, binascii
from termcolor import colored
from Helper.memStoreHelper import *
from Helper.hookHandler import *
from Helper.r4geHelper import *

# connect to r2
r2proj = createR2Pipe()
if r2proj == None:
    print(colored("only callable inside a r2-instance!", "red", attrs=["bold"]))
    exit(0)

# check if we use stdout checking
tocheck = getStdoutCheck(r2proj)
use_stdout = False if tocheck is None else True

# retrieve r4ge verbose mode
VERBOSE_MODE = isR4geVerbose(r2proj)
if VERBOSE_MODE:
    print("started in VERBOSE mode")
    logging.getLogger('angr.sim_manager').setLevel('DEBUG')

# check if we in a debug session, use dynamic or static mode
inDebug = inDebugSession(r2proj)
if inDebug:
    print(colored("start r4ge in DYNAMIC mode...{}".format("(STDOUT checking mode)" if use_stdout else ""), "blue", attrs=["bold"]))
else:
    print(colored("start r4ge in STATIC mode...{}".format("(STDOUT checking mode)" if use_stdout else ""), "blue", attrs=["bold"]))

# get flag offsets
find_offset, avoid_offsets, start_offset = getOffsets(r2proj)
if ( find_offset == 0 and use_stdout == False ):
    print(colored("no find flag found... stop execution", "red", attrs=["bold"]))
    exit(0)
if ( inDebug == False and start_offset == 0 ):
    print(colored("no start flag found, this is necessary for using the static mode! \nstop execution", "red", attrs=["bold"]))
    exit(0)


# check if binary is PIE, if yes -> set offset to r2 offset
ispie, binoffset = isPIE(r2proj)
load_options = {}
load_options['auto_load_libs'] = False
if ispie:
    print("binary is PIE, loaded on address: {}".format(hex(binoffset)))
    load_options['main_opts'] = {'base_addr': binoffset}

# get binary name and create angr project
binaryname = getBinaryName(r2proj)
angrproj = angr.Project(binaryname, load_options=load_options)
isX86 = isArchitectureX86(r2proj) # get the architecture type x86 or x64

if inDebug:
    # prepare dynamic execution

    #start_state = angrproj.factory.blank_state(remove_options={simuvex.o.LAZY_SOLVES})
    start_state = angrproj.factory.full_init_state()#remove_options={simuvex.o.LAZY_SOLVES})


    # get symbolic memory region, 0=offset, 1=size, 2=name
    symb_memories = getSymbolicMemoryRegions(r2proj)
    if len(symb_memories) == 0:
        print(colored("no symbolic memory found... stop execution", "red", attrs=["bold"]))
        exit(0)

    

    # copy registers to blank(start) state
    current_stack_pointer = copyRegisterValues(r2proj, start_state, isX86)

    # copy Stack
    stack_start = getStackStart( r2proj )
    stack_size = stack_start - current_stack_pointer
    print(colored("setup Stack: {0}-{1}, size: {2}".format( hex(stack_start), hex(current_stack_pointer), stack_size), "green"))
    setupMemoryRegion( r2proj, start_state, current_stack_pointer, stack_size, isX86 )

    # copy Heap ( if there is some used )
    (top_chunk, brk_start) = (0,0) #checkForHeap( r2proj )
    if top_chunk != 0 and brk_start != 0 and False:
        heap_size = top_chunk - brk_start
        print(colored("setup Heap: {0}-{1}, size: {2}".format( hex(top_chunk), hex(brk_start), heap_size ), "green"))
        setupMemoryRegion( r2proj, start_state, brk_start, heap_size, isX86 )

    # now set symbolic memory, adds symbolic variable to symb_memories list entries
    setSymbolicMemoryRegions( r2proj, start_state, symb_memories )

else:
    # prepare static execution -> no copying of the memory
    start_state = angrproj.factory.call_state(start_offset)#, remove_options={simuvex.o.LAZY_SOLVES})


# set up hooks for symbolic execution
hook_variables = getHooks( r2proj )
if len(hook_variables):
    for hook in hook_variables:
        # 0=address, 1=patch_length, 2=instructions
        angrproj.hook(hook[0], make_hook(hook[2]), length=hook[1])
        print(colored("setup Hook: {}, addr: {}, patchlength: {}, instr: {}".format( hook[3], hex(hook[0]), hook[1], hook[2] ), "green"))

# get all asserts
assert_variables = getAsserts( r2proj ) # 0=offset, 1=comparisons, 2=comment
if len(assert_variables):
    for ass in assert_variables:
        angrproj.hook(ass[0], make_assert(ass[1], ass[2]), length=0)
        print(colored("setup Assert: {}, addr: {}, compare: {}".format( ass[2], hex(ass[0]), ass[1] ), "green"))

# start the symbolic execution
if use_stdout:
    print(colored("start symbolic execution, find:'{}', avoid:{}".format(tocheck, [hex(x) for x in avoid_offsets]), "blue", attrs=["bold"]))
else:
    print(colored("start symbolic execution, find:{}, avoid:{}".format(hex(find_offset), [hex(x) for x in avoid_offsets]), "blue", attrs=["bold"]))
    # convert find_offsets to basic block address
    #find_offset = getBasicBlockAddr(angrproj, find_offset)

pg = angrproj.factory.simulation_manager(start_state)#, threads=10)


start_with_threads = False # in testing mode!!
if start_with_threads:
    # TODO: improve
    kill_printer = False
    start_time = time.time()
    def explorer():
        global pg
        global kill_printer
        pg.explore(find=getFindFunction(pg, find_offset, isX86), avoid=avoid_offsets)
        kill_printer = True
        #print "use simple, start:{} find:{} avoid:{}".format(hex(start_offset) , hex(find_offset), [hex(x) for x in avoid_offsets])
        #pg.explore(find=0x804881f, avoid=avoid_offsets)

    def printer():
        global kill_printer
        global start_time
        while(not kill_printer):
            printExecTime(time.time()-start_time, pg)
            time.sleep(5)    # print pg every two seconds

    # create and start threads
    exp = threading.Thread(target=explorer)
    pri = threading.Thread(target=printer)
    exp.start()
    pri.start()
    exp.join()  # wait

else:
    # normal start without information during exploration
    # killing exploration with ctrl+c is possible

    if use_stdout:
        pg.explore(find=lambda path: tocheck in path.state.posix.dumps(1), avoid=avoid_offsets)
    else:
        #pg.explore(find=getFindFunction(pg, find_offset, isX86), avoid=avoid_offsets)
        pg.explore(find=find_offset, avoid=avoid_offsets)


print("\nPathGroup Results: {}".format(pg))

state_found = None
if len(pg.found) == 0:
    print(colored("no way found, sorry...", "red", attrs=["bold"]))
else:
    state_found = pg.found[0] # get found state
    #print state_found.solver.constraints # DEBUG: print the constraints of the path

if inDebug:
    # debug mode: concrete symbolic memory and print it
    # give user possiblity to continue execution at find target

    if state_found == None:
        exit(0)

    # 0=offset, 1=size, 2=name, 3=symb_var
    for symb_memory in symb_memories:        
        mem = state_found.memory.load(symb_memory[0], symb_memory[1])
        symb_memory.append( state_found.solver.eval_upto(mem, 1, cast_to=bytes) )
        print(colored("symbolic memory - {} - {}".format(symb_memory[4][0], hex(int(binascii.hexlify(symb_memory[4][0][::-1]),16))), "green"))
        #print "dumps(1):",state_found.posix.dumps(1) # maybe also print the posix dumps

    # open IPython shell
    IPython.embed()

    # debug to find address, step until r2-command
    if checkUserPrompt("Do you want to set debugsession to find address"):

        print(colored("concretize symbolic memory in r2...", "green"))
        for symb_memory in symb_memories:
            concretizeSymbolicMemory(r2proj, symb_memory[0], symb_memory[4])

        print("jump to find address")
        r2proj.cmd("dsu {0}".format( find_offset ))

else:
    # static mode: print stdin and open ipython shell to perform manual concretization 

    # print stdin
    if state_found is not None:
        print(colored("\nSTDIN of state_found:", "blue", attrs=["bold"]))
        print(state_found.posix.dumps(0).decode('utf-8', 'ignore'))

    if checkUserPrompt("Do ou want to start an IPython-Shell"):
        print(colored('''
        Script-Variables:
            angrproj        ... angr project
            start_state ... start state
            pg          ... path_group
        {}'''.format("    state_found ... result state of exploration\n" if state_found is not None else ""), "green"))

        # open IPython shell
        IPython.embed()
