
'''
    out of the current r2 state, it will create
    a angr script, which sets the state,
    so that you can simply modify it
'''

import r2pipe, angr, sys, json
from termcolor import colored
# r4ge helpers
from Helper.memStoreHelper import *
from Helper.hookHandler import *
from Helper.createScriptHelper import *
from Helper.r4geHelper import *

def setupMemory(rzproj):

    # setup register values in blankstate
    if isX86:
        registers, esp = createScriptRegistersX86( rzproj )
    else:
        registers, esp = createScriptRegistersX64( rzproj )

    # Stack to JSON
    stack_start = getStackStart( rzproj )
    stack_size = stack_start - esp
    print(colored("copy Stack: {0}-{1}, size: {2}".format( hex(stack_start), hex(esp), stack_size), "green"))
    stack_json = memoryToJson(rzproj, esp, stack_size, "stack", isX86)
    stack_op = memoryToFile(rzproj, esp, stack_size, "stack", isX86)

    # Heap to JSON
    heap_json = None
    heap_op = None
    (top_chunk, brk_start) = checkForHeap( rzproj )
    if top_chunk != 0 and brk_start != 0:
        heap_size = top_chunk - brk_start
        print(colored("copy Heap: {0}-{1}, size: {2}".format( hex(top_chunk), hex(brk_start), heap_size ), "green"))
        heap_json = memoryToJson(rzproj, brk_start, heap_size, "heap", isX86)
        heap_op = memoryToFile(rzproj, brk_start, heap_size, "heap", isX86)

    # Save memory as JSON in memoryContent.txt
    # format: '[{"stack" :{"address": "values"}}, {"heap" :{"address": "value"}}]''
    memory_file = open("memoryContent.txt", "w")
    if heap_json == None:
        tmp = '{' + stack_json + '}'
    else:
        tmp = '{' + stack_json + ', ' + heap_json + '}'

    memory_file.write(tmp)
    memory_file.close()

    memory_file = open("memoryContentOP.txt", "w")
    if heap_op == None:
        tmp = stack_op
    else:
        tmp = stack_op + '\n' + heap_op

    memory_file.write(tmp)
    memory_file.close()

    # get symbolic memory
    symbolic_memory = createSymbolicVariables(rzproj)

    # return script string
    return registers + callLoadMemFunction() + symbolic_memory + exampleForConstraints()


rzproj = createR2Pipe()
if rzproj == None:
    print(colored("only callable inside a r2-instance!", "red", attrs=["bold"]))
    exit(0)

# check if we in a debug session
inDebug = inDebugSession(rzproj)

# get the architecture type x86 or x64
isX86 = isArchitectureX86(rzproj)

# create script file
script_name = sys.argv[1]
print(colored("creating Script " + script_name + "...", "blue"))
script_file = open(script_name, 'w')

# get offsets
find_offset, avoid_offsets, start_offset = getOffsets( rzproj, True )

# get binary name and create script header
binaryname = getBinaryName(rzproj)
header = createScriptHeader(binaryname, start_offset)

# only setup memory and create memory file if we are in a debug session
memory_setting = setupMemory(rzproj) if inDebug else ""

# get the hooks
hook_functions, hook_sets = createHooks(rzproj)

# get asserts
assert_functions, assert_sets = createAsserts(rzproj)

# angr path_groups
path_explore = createPathGroups(find_offset, ','.join(avoid_offsets) )

# now create script file
imports = createImports()
load_memory = createLoadMemFunctionOp() if inDebug else ""

# create script and write to file
script = imports +  load_memory + hook_functions + assert_functions + \
          header + ("" if inDebug else exampleForSymbolicVariables()) + \
          memory_setting + hook_sets + assert_sets + \
          path_explore + printSolution( rzproj ) + "\n"
script_file.write(script)
script_file.close()
