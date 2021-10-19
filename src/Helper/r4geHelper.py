import sys, rzpipe

'''
    create connection to the r2 instance
'''
def createRzPipe():
    try:
        rzproj = rzpipe.open()
        rzproj.cmd("a") # send a blind command
        return rzproj
    except:
        print("Unexpected error:", sys.exc_info()[0])
        return None


'''
    check if binary is x86
'''
def isArchitectureX86(rzproj):
    return (str(rzproj.cmdj("ij")['bin']['class']) == "ELF32")


'''
    returns the binaryname out of the r2 instance
'''
def getBinaryName(rzproj):
    return str(rzproj.cmdj("ij")['core']['file'])


'''
    parse current seek address
'''
def parseAddress(rzproj, address):
    # s as shortcut for current seek
    if address == "s":
        address = rzproj.cmd("s") # use current seek

    # parse address to a correct number
    return parseValue( address, isArchitectureX86(rzproj) )


'''
    only debug sessions have the exe field
'''
def inDebugSession(rzproj):
    try:
        rzproj.cmdj("dij")["exe"]
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
            print("EIP is Symbolic, maybe Bufferoverflow?..")
        else:
            try:
                if path.state.assert_failed == True:
                    path.errored = True # set errored flag in path, to avoid further exploration
                    #print("add path to errored list")
            except AttributeError:
                pass # happens because assert_failed is custom generated

            # check if we reached the find target
            ip_content = path.state.se.eval(ip)
            if ip_content == find_target:
                pg.found.append(path)

    return findFunction


'''
    check if binary is PIE
    use r2 check so that we do not have to load
    the binary in angr which is slow
'''
def isPIE(rzproj):
    bininfo = rzproj.cmdj("ij")
    if bininfo['bin']['PIE']:
        bin_addr = rzproj.cmdj("ij")['bin']['baddr']
        return True, bin_addr
    else:
        return False, 0


'''
    Symbolic memory regions are stored as r2 variables
    create r2 variable with:
        $r4ge.symbx='0x1234,7,userinput'
    (where the x after symb is a running variable)

    r2 help:
    delte variables with: $[varname]=
    ( the ''='  stands for deleting )
'''
def getSymbolicMemoryRegions( rzproj ):

    # get all variables from r2 and store in a list
    variables = rzproj.cmd("$ ~r4ge.symb")
    if len(variables) == 0:
        return []   # no variables

    # split and remove empty entries
    symb_vars = [var for var in variables.split('\n') if var]

    # dict with offset and other content
    symb_variables = []
    for var in symb_vars:
        var_content = rzproj.cmd("{0}?".format(var))
        var_split = var_content.split(';')
        # 0=offset, 1=size, 2=name
        # offset = parseValue(var_split[0], isX86)
        symb_variables.append([ int(var_split[0], 16), int(var_split[1], 10), var_split[2].strip() ])

    return symb_variables


'''
    get all Asserts, stored as r2 variables with the naming convention: $r4ge.assertx

    example var content
    0x08048477;eax<=0x5;checkEAX
    0x08048477;[0x08048477]<=0x5;checkEAX TODO
'''
def getAsserts( rzproj ):

    # get all variables from r2 and store in a list
    variables = rzproj.cmd("$ ~r4ge.assert")
    if len(variables) == 0:
        return []   # no variables

    assert_variables = []
    asserts_raw = variables.split('\n')
    for var in asserts_raw:
        content = rzproj.cmd("{0}?".format(var))
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
def getHooks( rzproj ):

    # get all variables from r2 and store in a list
    variables = rzproj.cmd("$ ~r4ge.hook")
    if len(variables) == 0:
        return []   # no variables

    # dict with offset and other content
    hook_variables = []
    hooks_raw = variables.split('\n')
    for var in hooks_raw:
        content = rzproj.cmd("{0}?".format(var))
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
    print the execution time in a readable format
'''
def printExecTime(t, pg):
    print("{} {:02d} {:02d}, status: {}".format( int(t/60/60), int(t/60)%60, int(t%60), pg))


'''
    check if r4ge is in debug mode, 
    if the r4ge.debug variable is set
'''
def isR4geVerbose(rzproj):
    # check if the variable is available
    variable = rzproj.cmd("$ ~r4ge.verbose").strip()
    if len(variable) != 13: # $r4ge.verbose
        return False

    # read value 
    value = rzproj.cmd("{}?".format(variable)).strip()
    return True if value.lower() == "true" else False


'''
    check if we should use stdout comparisson
'''
def getStdoutCheck(rzproj):
    # check if the variable is available
    checkstdout = rzproj.cmd("$ ~r4ge.checkstdout")
    if len(checkstdout) != 17: # $r4ge.checkstdout
        return None

    # read to check value 
    tocheck = rzproj.cmd("{}?".format(checkstdout))
    return tocheck


'''
    check userinput
'''
def checkUserPrompt(message):
    answer = input("{} (y/n)?".format(message))
    return answer == "y"
