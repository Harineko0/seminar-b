import pytest
from tinyvm import CPUState, execute_instruction

def test_arithmetic_overflow():
    state = CPUState(regs=[0]*16, pc=0, sr={f:False for f in "ZNCVPH"}, memory=bytearray(1024))
    state.regs[1] = 0xFFFFFFFF
    state.regs[2] = 0x00000001
    # ADD R3, R1, R2
    execute_instruction(state, 0x01031200) 
    assert state.regs[3] == 0
    assert state.sr['Z'] is True
    assert state.sr['C'] is True  # Carry should be set
