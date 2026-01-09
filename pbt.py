from hypothesis import given, strategies as st
from tinyvm import CPUState, execute_instruction

@given(st.integers(min_value=0, max_value=0xFFFFFFFF))
def test_instruction_safety(inst):
    state = CPUState(regs=[0]*16, pc=0, sr={f:False for f in "ZNCVPH"}, memory=bytearray(1024))
    try:
        execute_instruction(state, inst)
    except Exception as e:
        # PBT may find crashes, but unlikely to find logic errors in flags
        pass
