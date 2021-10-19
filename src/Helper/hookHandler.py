'''
    helper to create hooks out of r2

    the instructions for a hook are saved as a r2 variables
    this helper sets up the hook to execute the instructions
'''

import angr
from Helper.r4geHelper import *
from Helper.memStoreHelper import *
from Helper.registerHandler import *
from termcolor import colored


# compare with value according to operator
def compare( state, reg, operator, value):
    fail = False
    if operator == "#":
        if not state.se.evalW(reg) > value:
            fail = True
    elif operator == "<":
        if not state.se.evalW(reg) < value:
            fail = True
    elif operator == "==":
        if not state.se.evalW(reg) == value:
            fail = True
    elif operator == "#=":
        if not state.se.evalW(reg) >= value:
            fail = True
    elif operator == "<=":
        if not state.se.evalW(reg) <= value:
            fail = True
    else:
        print("Assert Fail: unknown operator")
        fail = True

    return fail

# set constraint to state if register value is symbolic
def addConstraintToState(state, reg, operator, value):
    if operator == "#":
        state.add_constraints(reg > value)
    elif operator == "<":
        state.add_constraints(reg < value)
    elif operator == "==":
        state.add_constraints(reg == value)
    elif operator == "#=":
        state.add_constraints(reg >= value)
    elif operator == "<=":
        state.add_constraints(reg <= value)


'''
    creates a hook-function and returns it to angr

    {instructions} are a dictionary
    key =   register
    value = value
'''
def make_hook(instructions):

    # create the actual hook-function
    def hook(state):
        #print("hooke called on ip: {0} instr: {1}".format(state.ip, instructions))

        for key, value in instructions.items():
            key = key.lower() # for safety convert to lower case
            if key.startswith("e") or key.startswith("r"):    # x86 and x64 registers
                registerSet( state, key, value )
            elif key.startswith("[0"):  # memory, [0x1234]=value
                # TODO: change memory values
                memorySet( state, int( key[1:-1], 16), value ) # write to memory region
        #endfor
    return hook


'''
    creates a assert-function and returns it to angr

    {comparison} are a list of the content from one single comparison

    0 = isReg - True/False
    1 = RegisterName/MemoryAddress
    2 = Operator
    3 = Value to Compare
'''
def make_assert(comparisons, assert_name):

    # create the actual hook-function
    def hook(state):

        for comparison in comparisons:

            operator = comparison[2]
            value = comparison[3]

            if comparison[0]: # register
                reg_name = comparison[1].lower()
                reg = getRegisterByName(state, reg_name)

                if reg.symbolic:
                    # add constraint to state
                    addConstraintToState(state, reg, operator, value)
                else:
                    fail = compare( state, reg, operator, value)
                    if fail:
                        print(colored("Assert {} failed, {} is {}".format(assert_name, comparison[1],
                            hex(state.se.evalW(reg))), "red", attrs=["bold"]))
                        state.assert_failed = True  # create custom assert failed flag
            else:
                print("assert for memory not implemented")
                pass

    return hook
