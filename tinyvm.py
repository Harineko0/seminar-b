from dataclasses import dataclass
from typing import List, Dict

@dataclass
class CPUState:
    regs: List[int]  # R0-R15
    pc: int
    sr: Dict[str, bool] # Z, N, C, V, P, H
    memory: bytearray

class N32Error(Exception): pass

def execute_instruction(state: CPUState, instruction: int):
    """
    Nebula-32 instruction executor.
    # post: len(state.regs) == 16
    # post: 0 <= state.pc < len(state.memory)
    """
    opcode = (instruction >> 24) & 0xFF
    # TODO: Implement 64 instructions logic.
    # Especially the flag updates for ADDC/SUBB and complex CJMP conditions.
    pass
