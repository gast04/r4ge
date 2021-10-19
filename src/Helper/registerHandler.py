
import r2pipe, angr

'''
    copies all registers to the {angr_state}
'''
def copyRegisterValues( rzproj, angr_state, isX86 ):

    # copy registers to blank(start) state
    registers = rzproj.cmdj("drrj")
    reg_dic = {}
    for reg in registers:
      reg_dic[reg['reg']] =  int(reg['value'], 16)

    if isX86:
        angr_state.regs.eip = reg_dic['eip']     # execution start
        angr_state.regs.esp = reg_dic['esp']     # stack pointer
        angr_state.regs.ebp = reg_dic['ebp']     # base pointer
        angr_state.regs.esi = reg_dic['esi']     # source index
        angr_state.regs.edi = reg_dic['edi']     # destination index

        # general purpose registers
        angr_state.regs.eax = reg_dic['eax']
        angr_state.regs.ebx = reg_dic['ebx']
        angr_state.regs.ecx = reg_dic['ecx']
        angr_state.regs.edx = reg_dic['edx']

        return reg_dic['esp']
    else:
        angr_state.regs.rip = reg_dic['rip']
        angr_state.regs.rsp = reg_dic['rsp']
        angr_state.regs.rbp = reg_dic['rbp']
        angr_state.regs.rsi = reg_dic['rsi']
        angr_state.regs.rdi = reg_dic['rdi']

        angr_state.regs.rax = reg_dic['rax']
        angr_state.regs.rbx = reg_dic['rbx']
        angr_state.regs.rcx = reg_dic['rcx']
        angr_state.regs.rdx = reg_dic['rdx']

        angr_state.regs.r8 = reg_dic['r8']
        angr_state.regs.r9 = reg_dic['r9']
        angr_state.regs.r10 = reg_dic['r10']
        angr_state.regs.r11 = reg_dic['r11']
        angr_state.regs.r12 = reg_dic['r12']
        angr_state.regs.r13 = reg_dic['r13']
        angr_state.regs.r14 = reg_dic['r14']
        angr_state.regs.r15 = reg_dic['r15']

        return reg_dic['rsp']


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
