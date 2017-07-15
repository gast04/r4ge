
import sys, r2pipe

'''
    create connection to the r2 instance
'''
def createR2Pipe():
    try:
        r2proj = r2pipe.open()
        r2proj.cmd("a") # send a blind command
        return r2proj
    except:
        print "Unexpected error:", sys.exc_info()[0]
        return None


'''
    check if binary is x86
'''
def isArchitectureX86(r2proj):
    return (str(r2proj.cmdj("ij")['bin']['class']) == "ELF32")


'''
    returns the binaryname out of the r2 instance
'''
def getBinaryName(r2proj):
    return str(r2proj.cmdj("ij")['core']['file'])


'''
    parse current seek address
'''
def parseAddress(r2proj, address):
    # s as shortcut for current seek
    if address is "s":
        address = r2proj.cmd("s") # use current seek

    # parse address to a correct number
    return parseValue( address, isArchitectureX86(r2proj) )


'''
    only debug sessions have the exe field
'''
def inDebugSession(r2proj):
    try:
        r2proj.cmdj("dij")["exe"]
        return True
    except Exception as e:
        return False


'''
    value is formated like: '\x1b[34m0xffc65040\x1b[0m'
    that's because of the colored printing from r2
'''
def parseValue(content, isX86):
    start = content.find('0x') # find start in string
    if isX86:
        value = int( content[start:start+10], 16 ) # len 10 for 32bit binaries
    else:
        value = int( content[start:start+18], 16 ) # len 18 for 64bit binaries
    return value


'''
    writes the {value} to a specific {address}
    it takes care of the endness of the binary
'''
def memorySet(state, address, value):
    state.memory.store(address, value, endness=state.arch.memory_endness)


'''
    search for the top basic block of the given parameters
'''
def getBasicBlockAddr(proj, address):
    cfg = proj.analyses.CFGFast()
    i = 0
    while(True):
        nodes = cfg.get_all_nodes(address-i)
        if len(nodes) != 0:
            return address-i
        i += 1


'''
    creates the find function which is checks for the assert_failed flag
    after every basic block and also if we reached the find target.
'''
def getFindFunction(pg, find_target, isX86):

    def findFunction(path):

        ip = path.state.regs.eip if isX86 else path.state.regs.rip
        if not ip.concrete:
            print "EIP is Symblic, maybe Bufferoverflow?.."
        else:
            try:
                if path.state.assert_failed == True:
                    path.errored = True # set errored flag in path, to avoid further exploration
                    #print "add path to errored list"
            except AttributeError:
                pass # happens because assert_failed is custom generated

            # check if we reached the find target
            ip_content = path.state.se.any_int(ip)
            if ip_content == find_target:
                pg.found.append(path)

    return findFunction
