
import r2pipe, angr

'''
    copies all registers to the {angr_state}
'''
def copyRegisterValues( r2proj, angr_state, isX86 ):

    # copy registers to blank(start) state
    registers = r2proj.cmdj("drj")
    if isX86:
        angr_state.regs.eip = registers['eip']     # execution start
        angr_state.regs.esp = registers['esp']     # stack pointer
        angr_state.regs.ebp = registers['ebp']     # base pointer
        angr_state.regs.esi = registers['esi']     # source index
        angr_state.regs.edi = registers['edi']     # destination index

        # general purpose registers
        angr_state.regs.eax = registers['eax']
        angr_state.regs.ebx = registers['ebx']
        angr_state.regs.ecx = registers['ecx']
        angr_state.regs.edx = registers['edx']

        return registers['esp']
    else:
        angr_state.regs.rip = registers['rip']
        angr_state.regs.rsp = registers['rsp']
        angr_state.regs.rbp = registers['rbp']
        angr_state.regs.rsi = registers['rsi']
        angr_state.regs.rdi = registers['rdi']

        angr_state.regs.rax = registers['rax']
        angr_state.regs.rbx = registers['rbx']
        angr_state.regs.rcx = registers['rcx']
        angr_state.regs.rdx = registers['rdx']

        angr_state.regs.r8 = registers['r8']
        angr_state.regs.r9 = registers['r9']
        angr_state.regs.r10 = registers['r10']
        angr_state.regs.r11 = registers['r11']
        angr_state.regs.r12 = registers['r12']
        angr_state.regs.r13 = registers['r13']
        angr_state.regs.r14 = registers['r14']
        angr_state.regs.r15 = registers['r15']

        return registers['rsp']


def registerSet(state, register, value):

    # x86 Registers
    if register == "eax":
        state.regs.eax = value
    elif register == "ebx":
        state.regs.ebx = value
    elif register == "ecx":
        state.regs.ecx = value
    elif register == "edx":
        state.regs.edx = value
    elif register == "esi":
        state.regs.esi = value
    elif register == "edi":
        state.regs.edi = value

    elif register == "esp":
        state.regs.esp = value
    elif register == "ebp":
        state.regs.ebp = value
    elif register == "eip":
        state.regs.eip = value

    # x64 Registers
    elif register == "rax":
        state.regs.rax = value
    elif register == "rbx":
        state.regs.rbx = value
    elif register == "rcx":
        state.regs.rcx = value
    elif register == "rdx":
        state.regs.rdx = value

    elif register == "rip":
        state.regs.rip = value
    elif register == "rsp":
        state.regs.rsp = value
    elif register == "rbp":
        state.regs.rbp = value
    elif register == "rsi":
        state.regs.rsi = value
    elif register == "rdi":
        state.regs.rdi = value

    elif register == "r8":
        state.regs.r8 = value
    elif register == "r9":
        state.regs.r9 = value
    elif register == "r10":
        state.regs.r10 = value
    elif register == "r11":
        state.regs.r12 = value
    elif register == "r13":
        state.regs.r13 = value
    elif register == "r14":
        state.regs.r14 = value
    elif register == "r15":
        state.regs.r15 = value


def getRegisterByName(state, register):
    # x86 Registers
    if register == "eax":
        return state.regs.eax
    elif register == "ebx":
        return state.regs.ebx
    elif register == "ecx":
        return state.regs.ecx
    elif register == "edx":
        return state.regs.edx
    elif register == "esi":
        return state.regs.esi
    elif register == "edi":
        return state.regs.edi
    elif register == "esp":
        return state.regs.esp
    elif register == "ebp":
        return state.regs.ebp
    elif register == "eip":
        return state.regs.eip

    # x64 Registers
    elif register == "rax":
        return state.regs.rax
    elif register == "rbx":
        return state.regs.rbx
    elif register == "rcx":
        return state.regs.rcx
    elif register == "rdx":
        return state.regs.rdx

    elif register == "rip":
        return state.regs.rip
    elif register == "rsp":
        return state.regs.rsp
    elif register == "rbp":
        return state.regs.rbp
    elif register == "rsi":
        return state.regs.rsi
    elif register == "rdi":
        return state.regs.rdi

    elif register == "r8":
        return state.regs.r8
    elif register == "r9":
        return state.regs.r9
    elif register == "r10":
        return state.regs.r10
    elif register == "r11":
        return state.regs.r12
    elif register == "r13":
        return state.regs.r13
    elif register == "r14":
        return state.regs.r14
    elif register == "r15":
        return state.regs.r15
