'''
    create Variables needed by r4ge
    (every number should be in hex, values and registers)

    Hooks:
        hooks are usefull to "patch" functions call, we can create a rz-variable
        which will be later translated to a angr-hook function

        hook naming convention: r4ge.hookx
        example call:
        .(addHook 0x08048487 'eax=0x0,ebx=0x0' 5 testHook)
        # address, instructions, length, comment

    Asserts:
        assert are usefull to compare memory or registers at "runtime" during the
        symbolic execution, rz-variables are created which will be translated to
        angr hooks with a mem check.

        assert naming convention: r4ge.assertx
        example call:
        .(addAssert 0x08048487 'eax<=0x123' checkEAX)
        .(addAssert 0x08048477 '[0x08048477]<=0x5' checkEAX) TODO
        # address, instructions, length, comment

        (we need a # cause > is always expressed as the pipe operator in rz)

    Smbolic Memory:
        main part of the symbolic execution, these variables mark the memory
        regions which we use as symbolic

        symb naming convention: $r4ge.symbx
        example call:
        .(markMemSymbolic 0xfff2a23b 7 userinput)

    Note:
        createVariable.py should not import angr because this will make
        it slow and it is not needed for creating variables in rz
'''

import sys, re
from termcolor import colored
from Helper.r4geHelper import *


'''
    simple checker if register contains of three characters
    and if we have a single '=' character
'''
def checkHookInstructions(instructions):
    try:
        inst_list = instructions.split(',')
        for inst in inst_list:
            tmp = inst.split('=')
            if len(tmp[0]) != 3 or len(tmp[1]) == 0:
                return False
        return True
    except Exception as e:
        return False    # just for safety


'''
    checks if the Assert Comparison have a correct syntax
'''
def checkAssertComparison(comparison):
    try:
        # it have to contain one of these
        res = re.search(r"#=|#|==|<=|<", comparison)
        if res is None:
            return False
        # check that registername have 3 charakters
        if comparison.find(res.group(0)) != 3:
            return False

        return True
    except Exception as e:
        return False


rzproj = createRzPipe()
if rzproj == None:
    print(colored("only callable inside a rz-instance!", "red", attrs=["bold"]))
    exit(0)

# get the architecture type x86 or x64
isX86 = isArchitectureX86(rzproj)

# check first parameter if assert or hook
isHook = False
isSymb = False
isStdout = False
isAssert = False
varname = sys.argv[1]

if varname == "assert":
    isAssert = True
elif varname == "symb":
    isSymb = True
elif varname == "hook":
    isHook = True
elif varname == "checkstdout":
    isStdout = True

# get paramters
address = sys.argv[2]
if isHook:
    instructions = sys.argv[3]
    patch_size = sys.argv[4]   # patchlength in bytes
    comment = sys.argv[5]
elif isSymb:
    size = sys.argv[3]    # bitvector length in bytes
    comment = sys.argv[4]
elif isAssert:
    instructions = sys.argv[3]
    comment = sys.argv[4]

# next variables -> count+1
if isHook:
    count = len(getHooks(rzproj))
elif isSymb:
    count = len(getSymbolicMemoryRegions(rzproj))
elif isAssert:
    count = len(getAsserts(rzproj))


# since checkstdout is a special case check it extra
if isStdout:
    # address contains the find target (not optimal, but works...)
    rzproj.cmd("$r4ge.{0}='{1}'".format( varname, address ))
    print("set find target to the string: '{}'".format(address))
    exit(0)

# s as shortcut for current seek
if address == "s":
    address = rzproj.cmd("s") # use current seek

# parse address to a correct number
address = parseValue( address, isX86 )

# create rz-variable
new_varname = "r4ge.{0}{1}".format(varname, count+1)
if isHook:
    if checkHookInstructions(instructions):
        rzproj.cmd("${0}='{1};{2};{3};{4}'".format( new_varname, hex(address), patch_size, instructions, comment ))
    else:
        print(colored("Invalid Hook-Instructions Syntax!", "red", attrs=["bold"]))
        exit(0)
elif isSymb:
    rzproj.cmd("${0}='{1};{2};{3}'".format( new_varname, hex(address), size, comment ))
else:
    if checkAssertComparison(instructions):
        rzproj.cmd("${0}='{1};{2};{3}'".format( new_varname, hex(address), instructions, comment ))
    else:
        print(colored("Invalid Assert-Comparison Syntax!", "red", attrs=["bold"]))
        exit(0)


# create rz comment on address
rzproj.cmd("CCu {0}:{1} @ {2}".format(varname.title(), comment, address))

# print userinformation
if isSymb:
    print("marked memory at {0} as symbolic...".format(hex(address)))
else:
    print("created {0}...".format(varname.title()))
