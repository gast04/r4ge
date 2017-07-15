
import r2pipe, angr
from r4geHelper import *
from termcolor import colored

'''
    parse the flags from r2,
    get flags: r4ge.start, r4ge.avoidx, r4ge.find

    parameter "inHex": return a list with hex strings -> remove
'''
def getOffsets( r2proj, inHex=False):
    find_offset = 0
    start_offset = 0
    avoid_offsets = []

    # get all flags as JSON
    flags = r2proj.cmdj("fj")

    for flag in flags:
        if flag['name'].startswith("r4ge.find"):
            find_offset = flag['offset']
        if flag['name'].startswith("r4ge.avoid"):
            if inHex:
                avoid_offsets.append( hex(flag['offset']) )
            else:
                avoid_offsets.append(flag['offset'])
        if flag['name'].startswith("r4ge.start"):
            start_offset = flag['offset']

    return find_offset, avoid_offsets, start_offset


'''
    Symbolic memory regions are stored as r2 variables
    create r2 variable with:
        $r4ge.symbx='0x1234,7,userinput'
    (where the x after symb is a running variable)

    r2 help:
    delte variables with: $[varname]=
    ( the ''='  stands for deleting )
'''
def getSymbolicMemoryRegions( r2proj ):

    # get all variables from r2 and store in a list
    variables = r2proj.cmd("$ ~r4ge.symb")
    if len(variables) == 0:
        return []   # no variables

    variables_split = variables.split('\n')
    symb_vars = []
    for var in variables_split:
        symb_vars.append(var[1:]) # entry starts with '$' -> remove it

    # dict with offset and other content
    symb_variables = []
    for var in symb_vars:
        var_content = r2proj.cmd("${0}?".format(var))
        var_split = var_content.split(';')
        # 0=offset, 1=size, 2=name
        #offset = parseValue(var_split[0], isX86)
        symb_variables.append([ int(var_split[0], 16), int(var_split[1], 10), var_split[2] ])

    return symb_variables

'''
    parse the Comparison from an Assert out of the raw String: eax<=0x4
'''
def parseComparison(comp_raw):

    ret_comps = []
    comps = comp_raw.split(',') # allow muliple comparisons
    for comp in comps:

        tmp = []
        if comp.startswith("e") or comp.startswith("r"): # register comparison
            tmp.append(True)
            tmp.append(comp[0:3])
            comp = comp[3:]    # continue with the rest of the comparison
        else:
            # TODO: memory comparison
            tmp.append(False)
            tmp.append(int(comp[1:11], 16))   # len 10 for x86
            comp = comp[12:]

        op_length = comp.find("0x") # find start of value
        tmp.append(comp[:op_length]) # add operator
        tmp.append(int(comp[op_length:], 16)) # add value

        # add parsed comparisons to return list
        ret_comps.append(tmp)

    return ret_comps


'''
    get all Asserts, stored as r2 variables with the naming convention: $r4ge.assertx

    example var content
    0x08048477;eax<=0x5;checkEAX
    0x08048477;[0x08048477]<=0x5;checkEAX TODO
'''
def getAsserts( r2proj ):

    # get all variables from r2 and store in a list
    variables = r2proj.cmd("$ ~r4ge.assert")
    if len(variables) == 0:
        return []   # no variables

    assert_variables = []
    asserts_raw = variables.split('\n')
    for var in asserts_raw:
        content = r2proj.cmd("{0}?".format(var))
        content_split = content.split(';') # 0=offset, 1=comparison, 2=comment

        assert_var = [] # save instruction as list: 0=isReg, 1=reg|memAddr, 2=operator, 3=value
        assert_var.append(int(content_split[0],16))

        comp = parseComparison(content_split[1])    # parse comparisons
        assert_var.append(comp)    # append comparison of type list
        assert_var.append(content_split[2]) # append comment/name

        assert_variables.append(assert_var) # append assert variable to list

    return assert_variables


'''
    get all Hooks, stored as r2 variables with the naming convention:
        $r4ge.hookx
        (x is a running variable)

    example hook content:
    0x08048477;5;eax=0x5;patchStrlen
'''
def getHooks( r2proj ):

    # get all variables from r2 and store in a list
    variables = r2proj.cmd("$ ~r4ge.hook")
    if len(variables) == 0:
        return []   # no variables

    # dict with offset and other content
    hook_variables = []
    hooks_raw = variables.split('\n')
    for var in hooks_raw:
        content = r2proj.cmd("{0}?".format(var))
        var_split = content.split(';')
        # 0=offset, 1=patch_size, 2=instructions, 3=comment

        # save instructions in dictionary
        instructions = {}
        instr_split = var_split[2].split(',')
        for instr in instr_split:
            tmp = instr.split('=')
            # 0=register, 1=value
            instructions[tmp[0]] = int(tmp[1], 16)

        hook_variables.append([ int(var_split[0], 16), int(var_split[1], 16), instructions, var_split[3] ])

    return hook_variables


'''
    set symbolic memory in {start_state}, symbolic memory is stored
    in r2 variables
'''
def setSymbolicMemoryRegions( r2proj, start_state, symb_variables ):
    for symb_entry in symb_variables:
        symb_memory = angr.claripy.BVS(symb_entry[2], symb_entry[1]*8, explicit_name=True)  # *8 because it's a bitvector!
        symb_entry.append(symb_memory)
        start_state.memory.store(symb_entry[0], symb_memory)
        print colored("symbolic address: {0}, size: {1}".format( hex(symb_entry[0]), symb_entry[1] ), "green")


'''
    read the brk_start address and the top_chunk address
    from the heap memory map
'''
def checkForHeap( r2proj ):
    heap_sizes = r2proj.cmd("dmh")

    if ( len(heap_sizes) != 0 ):
        # there is  heap to copy
        # parse top chunk and brk_start, to get current size
        # line to parse: Top chunk @ 0x862f340 - [brk_start: 0x862f000, brk_end: 0x8650000]
        heap_sizes_lines = heap_sizes.split('\n')

        for line in heap_sizes_lines:
            if "Top chunk" in line:
                # split with add
                d = "0x"
                line_split =  [d+e for e in line.split(d) if e]
                top_chunk = int( line_split[1].split('\x1b')[0], 16 )
                brk_start = int( line_split[2].split('\x1b')[0], 16 )

                return (top_chunk, brk_start)

    # return (0,0) if no heap is used
    return (0,0)


'''
    read the start of the stack from the memory maps
'''
def getStackStart( r2proj ):
    memory_map = r2proj.cmdj("dmj")
    stack_map = None
    for memory_entry in memory_map:
        if "stack" in memory_entry['name']:
            stack_map = memory_entry
            break

    stack_start = stack_map['addr_end']

    return stack_start


'''
    sets up/copy the memory starting from {start_addr}
    counting upwards until {size}
'''
def setupMemoryRegion( r2proj, angr_state, start_addr, size, isX86 ):

    # get raw data from r2
    if isX86:
        tmp_cmd = "pxW {0} @ {1}".format(size, start_addr)
    else:
        tmp_cmd = "pxQ {0} @ {1}".format(size, start_addr)
    content_raw = r2proj.cmd( tmp_cmd )

    # store in list first
    content = []
    content_split = content_raw.split('\n')
    for entry in content_split:
        entry_split = entry.split(' ')
        value = parseValue(entry_split[1], isX86)
        content.append( [ int(entry_split[0].strip(),16), value ] )   # [address, value]

    # setup memory in angr_state
    for entry in content:
        #print "set: {0} <- {1}".format( hex(entry[0]), hex(entry[1]) )
        # store as little endian or big endian according to architecture
        angr_state.memory.store(entry[0], entry[1], endness=angr_state.arch.memory_endness)

'''
    concretize symbolic memory in r2
    write {value_str} to {symb_addr}
'''
def concretizeSymbolicMemory(r2proj, symb_addr, value_str):

    # save seek and seek to symbolic address
    save_seek = r2proj.cmd("s")
    r2proj.cmd("s {}".format(symb_addr))

    # write hex data
    r2proj.cmd("wx {}".format(value_str.encode('hex')))

    # restore seek
    r2proj.cmd("s {}".format(save_seek))
