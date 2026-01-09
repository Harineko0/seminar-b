from tinyvm import CPUState, execute_instruction

def check_flag_invariants(inst: int, r1_val: int, r2_val: int):
    """
    CrossHair will try to find values that break the logical invariants of the CPU.
    """
    state = CPUState(regs=[0]*16, pc=0, sr={f:False for f in "ZNCVPH"}, memory=bytearray(1024))
    state.regs[1] = r1_val
    state.regs[2] = r2_val
    
    execute_instruction(state, inst)
    
    # Invariant: If result is 0, Zero flag MUST be set.
    # AI often forgets to update flags on every instruction.
    if state.regs[3] == 0:
        assert state.sr['Z'] == True
