
import r2pipe
from r4geHelper import *
from memStoreHelper import *


def createImports():
    # shift to left to avoid spaces and tabs in final script
    header = '''#!/usr/bin/env python2.7

import angr, simuvex, IPython
'''
    return header


def createScriptHeader( binaryname, start_offset=0 ):

    if start_offset == 0:
        header =    '''
# create angr project and blank_state, maybe you have to edit the path
proj = angr.Project("''' + binaryname + '''", load_options={"auto_load_libs":False})
start_state = proj.factory.blank_state(remove_options={simuvex.o.LAZY_SOLVES})
'''
    else:
        header =    '''
# create angr project and call_state, maybe you have to edit the path
proj = angr.Project("''' + binaryname + '''", load_options={"auto_load_libs":False})
start_state = proj.factory.call_state(''' + hex(start_offset) + ''', remove_options={simuvex.o.LAZY_SOLVES})
'''
    return header


def createScriptRegistersX86( r2proj ):
    # copy registers to blank(start) state
    registers = r2proj.cmdj("drj")

    regs = '''
# set register values
start_state.regs.eip={0}
start_state.regs.esp={1}
start_state.regs.ebp={2}
start_state.regs.esi={3}
start_state.regs.edi={4}
start_state.regs.eax={5}
start_state.regs.ebx={6}
start_state.regs.ecx={7}
start_state.regs.edx={8}
'''.format(hex(registers['eip']), hex(registers['esp']), hex(registers['ebp']), hex(registers['esi']), hex(registers['edi']) ,
            hex(registers['eax']), hex(registers['ebx']), hex(registers['ecx']), hex(registers['edx']) )

    return regs, registers['esp']

def createScriptRegistersX64( r2proj ):
        registers = r2proj.cmdj("drj")

        regs = '''
# set register values
start_state.regs.rip={}
start_state.regs.rsp={}
start_state.regs.rbp={}
start_state.regs.rsi={}
start_state.regs.rdi={}
start_state.regs.rax={}
start_state.regs.rbx={}
start_state.regs.rcx={}
start_state.regs.rdx={}
start_state.regs.r8={}
start_state.regs.r9={}
start_state.regs.r10={}
start_state.regs.r11={}
start_state.regs.r12={}
start_state.regs.r13={}
start_state.regs.r14={}
start_state.regs.r15={}

    '''.format(hex(registers['rip']), hex(registers['rsp']), hex(registers['rbp']), hex(registers['rsi']), hex(registers['rdi']) ,
                hex(registers['rax']), hex(registers['rbx']), hex(registers['rcx']), hex(registers['rdx']), hex(registers['r8']) ,
                hex(registers['r9']), hex(registers['r10']), hex(registers['r11']), hex(registers['r12']), hex(registers['r13']) ,
                hex(registers['r14']), hex(registers['r15']) )

        return regs, registers['rsp']

def createSymbolicVariables(r2proj):

    # 0=offset, 1=size, 2=name
    symb_variables = getSymbolicMemoryRegions( r2proj )

    symbolic_memory = "\n# set up symbolic memory\n"
    for variable in symb_variables:
        symbolic_memory += "start_state.memory.store(" + hex(variable[0]) + ", start_state.se.BVS('"+ variable[2] +"', " + str(variable[1]) + "*8, explicit_name=True))\n"
    return symbolic_memory


#format: "name" :{"address": "values"}
def memoryToJson(r2proj, start, size, name, isX86):

    # get raw data
    if isX86:
        tmp_cmd = "pxW {0} @ {1}".format(size, start)
    else:
        tmp_cmd = "pxQ {0} @ {1}".format(size, start)
    content_raw = r2proj.cmd(tmp_cmd)

    content_split = content_raw.split('\n')
    content_str = ""
    for entry in content_split:
        entry_split = entry.split(' ')
        #print("value: ", entry_split[1])
        value = parseValue( entry_split[1], isX86 )
        #print("value: ", value)
        content_str += '"' + str(int(entry_split[0].strip(),16)) + '":"' + str(value) + '",'

    # create json string per hand
    json_string = '"' + name + '":{'+ content_str[:-1] + '}'
    return json_string



# optimized version of the json function
def memoryToFile(r2proj, start, size, name, isX86):
    # get raw data
    if isX86:
        tmp_cmd = "pxW {0} @ {1}".format(size, start)
    else:
        tmp_cmd = "pxQ {0} @ {1}".format(size, start)
    content_raw = r2proj.cmd(tmp_cmd)

    # write file header
    # name, isX86, start, size
    mem_str = "{},{},{},{}\n".format(name, isX86, hex(start), size)
    content_split = content_raw.split('\n')
    for entry in content_split:
        entry_split = entry.split(' ')
        #print("addr:{} val:{}".format(entry_split[0].strip(), parseValue( entry_split[1], isX86 )))
        mem_str += str(parseValue( entry_split[1], isX86 )) + ","

    return mem_str[:-1] # remove last comma


# name of the created hook function is hook_[name]
def createHooks( r2proj ):
    hooks = getHooks(r2proj)
    # 0=offset, 1=patch_size, 2=instructions, 3=comment

    # create a python function for each hook
    hook_functions = "\n"
    hook_sets = "\n# setup hooks in project\n"
    for hook in hooks:
        hook_function = "def hook_{0}(state):\n".format(hook[3])
        instructions = hook[2]
        for key, value in instructions.items():
            if key.startswith("e") or key.startswith("r"):    # x86 register
                hook_function += "    state.regs.{0} = {1}\n".format(key, hex(value) )
            elif key.startswith("[0"):  # memory, [0x1234]=value
                hook_function += "    state.memory.store({0}, {1}, endness=state.arch.memory_endness)\n".format( key[1:-1], hex(value) )
        hook_functions += hook_function + "\n"
        #endfor
        hook_sets += "proj.hook({0}, {1}, length={2})\n".format( hex(hook[0]), "hook_"+hook[3], hook[1] )

    return (hook_functions, hook_sets)

'''
    Assert-Template
    def assert_checkEAX(state):
        if state.regs.ecx.concrete:
            if not state.se.any_int(state.regs.ecx) == 0x5:
                print("Assert checkEAX failed...")
        else: # value is symbolic, add constraint
            state.add_constraints(state.regs.eax == 0x5)
'''
def createAsserts(r2proj):
    asserts = getAsserts(r2proj)

    assert_functions = ""
    assert_sets = "\n# setup assert hooks in project\n"

    for ass in asserts:
        comps = ass[1] # list of entries with format [True, u'ebx', u'==', 0]

        # create function header
        assert_temp = "def assert_{}(state):".format(ass[2])

        for comp in comps:
            assert_temp += '''
    if state.regs.{1}.concrete:
        if not state.se.any_int(state.regs.{1}) {2} {3}:
            print("Assert {0} failed...")
    else:
        state.add_constraints(state.regs.{1} {2} {3})
'''.format(ass[2], comp[1], comp[2], hex(comp[3]))

        assert_temp = assert_temp.replace('#', '>')

        assert_functions += assert_temp + "\n"
        assert_sets += "proj.hook({0}, {1}, length=0)\n".format( hex(ass[0]), "assert_"+ass[2] )

    return (assert_functions, assert_sets)

def createLoadMemFunction():

    load_fun = '''
def loadMemory( start_state ):
    try:
        mem_file = open("memoryContent.txt", "r")
    except IOError:
        print("could not find memoryContent.txt...")
        exit(0)

    memory_json = json.load(mem_file)   # loads file as json object

    # load stack memory
    stack_content = memory_json['stack']
    for address in stack_content:
        start_state.memory.store(int(address), int(stack_content[address]), endness=start_state.arch.memory_endness)

    if len(memory_json) > 1:
        # load heap memory, if there is one used
        heap_content = memory_json['heap']
        for address in heap_content:
            start_state.memory.store(int(address), int(heap_content[address]), endness=start_state.arch.memory_endness)
    '''
    return load_fun

def createLoadMemFunctionOp():
    load_fun = '''
def loadMemory( start_state ):

    try:
        mem_file = open("memoryContentOP.txt")
    except IOError:
        print("could not find memoryContent.txt...")
        exit(0)

    mem_lines = mem_file.readlines()

    stack_start = int(mem_lines[0].split(',')[2], 16)
    isX86 = mem_lines[0].split(',')[1] == "True"

    for content in mem_lines[1].split(','):
        start_state.memory.store(stack_start, int(content), endness=start_state.arch.memory_endness)
        stack_start = stack_start + 4 if isX86 else stack_start + 8

    # load heap
    if len(mem_lines) > 2:
        heap_start = int(mem_lines[2].split(',')[2], 16)
        isX86 = mem_lines[2].split(',')[1] == "True"

        for content in mem_lines[3].split(','):
            start_state.memory.store(heap_start, int(content), endness=start_state.arch.memory_endness)
            heap_start = heap_start + 4 if isX86 else heap_start + 8

'''
    return load_fun

def callLoadMemFunction():
    return "\n# setup start_state memory \nloadMemory( start_state )\n"

def createPathGroups(find, avoids):

    content = '''\n# setup path groups and start exploration
pg = proj.factory.path_group(start_state)
pg.explore(find={0}, avoid=[{1}])
'''.format( hex(find), str(avoids) )

    return content


'''
    template code to concretize symbolic memory
    or open an IPython shell if no path is found
    -> usefull for creating a script in static mode..
'''
def printSolution( r2proj ):

    # 0=offset, 1=size, 2=name
    symb_variables = getSymbolicMemoryRegions( r2proj )

    content = '''
# print soltion if we found a path
if len(pg.found) > 0:
    state_found = pg.found[0].state
    print("found the target!")
    '''

    for variable in symb_variables:
        tmp = '''
    concrete_memory = state_found.memory.load({0}, {1}) # {2}
    print(state_found.se.any_str(concrete_memory))'''.format(hex(variable[0]), variable[1], variable[2])
        content += tmp

    if len(symb_variables) == 0: # -> check for static mode
        content += "IPython.embed()"

    content += '''
else:
    print("start IPython shell")
    print("Variables: state_found, start_state, pg, proj")
    IPython.embed()
    '''

    return content


def exampleForConstraints():
    helps = """'''
# in case if you want to limit the values for the bitvector
# chop(8) splits bitvector into pieces of 8 bits
for byte in symb_var.chop(8):
    start_state.add_constraints(angr.claripy.Or(byte >= ' ', byte == 0x00)) # 0x20
    start_state.add_constraints(byte <= '~') # 0x7e

# add hard constraints
start_state.add_constraints(symb_var.chop(8)[0] == 'F')
start_state.add_constraints(symb_var.chop(8)[1] == 'L')
start_state.add_constraints(symb_var.chop(8)[2] == 'A')
start_state.add_constraints(symb_var.chop(8)[3] == 'G')
'''\n"""
    return helps

def exampleForSymbolicVariables():
    helps = """'''
# example for Symbolic Parameters

symb_var = angr.claripy.BVS("param", 20*8)

# add to call_state
#proj.factory.call_state( offset, symb_var, remove_options={simuvex.o.LAZY_SOLVES})

# limit to printable characters
for byte in symb_var.chop(8):
    start_state.add_constraints(angr.claripy.Or(byte >= ' ', byte == 0x00)) # 0x20
    start_state.add_constraints(byte <= '~') # 0x7e

# add hard constraints
start_state.add_constraints(symb_var.chop(8)[0] == 'F')
start_state.add_constraints(symb_var.chop(8)[1] == 'L')
start_state.add_constraints(symb_var.chop(8)[2] == 'A')
start_state.add_constraints(symb_var.chop(8)[3] == 'G')
'''\n"""
    return helps
