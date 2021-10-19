import r2pipe, angr, claripy
from Helper.r4geHelper import *
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
    set symbolic memory in {start_state}, symbolic memory is stored
    in r2 variables
'''
def setSymbolicMemoryRegions( r2proj, start_state, symb_variables ):
    for symb_entry in symb_variables:
        symb_memory = claripy.BVS(symb_entry[2], symb_entry[1]*8, explicit_name=True)  # *8 because it's a bitvector!

        symb_entry.append(symb_memory)
        start_state.memory.store(symb_entry[0], symb_memory)

        # what if marked input has not exact length
        #for byte in symb_memory.chop(8):
        #    #start_state.add_constraints(claripy.Or(byte >= ' ')#, byte == 0x00)    ) 
        #    start_state.add_constraints(byte >= ' ')#, byte == 0x00)    ) # 0x20
        #    start_state.add_constraints(byte <= '~') # 0x7e

        print(colored("symbolic address: {0}, size: {1}".format( hex(symb_entry[0]), symb_entry[1] ), "green"))


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

    # get json data from r2
    cmd =  "pxwj " if isX86 else "pxqj"
    cmd += "{0} @ {1}".format(size, start_addr)
    content = r2proj.cmdj( cmd )

    # setup memory in angr_state
    offset = 0
    for memval in content:       
        #print("set: {0} <- {1}".format( hex(start_addr+offset), hex(memval) ))

        # store as little endian or big endian according to architecture
        angr_state.memory.store(start_addr+offset, memval, endness=angr_state.arch.memory_endness)
        offset += 4 if isX86 else 8


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
