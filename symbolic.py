"""
Symbolic execution tests using CrossHair.

CrossHair will try to find counterexamples that violate the assertions.
These tests verify invariants that must hold for ALL possible inputs.
"""
from tinyvm import CPUState, execute_instruction, N32Error


def make_instruction(opcode, cond_mod=0, rd=0, ra=0, rb=0, imm=0):
    """Helper function to build 32-bit instruction in big-endian format."""
    return (opcode << 24) | (cond_mod << 20) | (rd << 16) | (ra << 12) | (rb << 8) | imm


def make_state():
    """Create a fresh CPU state for testing."""
    return CPUState(regs=[0]*16, pc=0, sr={f: False for f in "ZNCVPH"}, memory=bytearray(1024))


# ============================================================================
# SYMBOLIC TESTS - CRITICAL INVARIANTS
# ============================================================================

def check_r0_invariant_add(r1_val: int, r2_val: int, imm: int) -> bool:
    """
    Symbolic: R0 must always be 0 after ADD operation.
    CrossHair will try to find values that violate this.

    pre: 0 <= r1_val <= 0xFFFFFFFF
    pre: 0 <= r2_val <= 0xFFFFFFFF
    pre: 0 <= imm <= 255
    post: __return__ == True
    """
    state = make_state()
    state.regs[1] = r1_val
    state.regs[2] = r2_val

    # Try to write to R0
    inst = make_instruction(0x01, rd=0, ra=1, rb=2, imm=imm)
    execute_instruction(state, inst)

    # R0 must still be 0
    return state.regs[0] == 0


def check_zero_flag_invariant(r1_val: int, r2_val: int, rd: int) -> bool:
    """
    Symbolic: If result is 0, Zero flag MUST be set.

    pre: 0 <= r1_val <= 0xFFFFFFFF
    pre: 0 <= r2_val <= 0xFFFFFFFF
    pre: 1 <= rd <= 15
    post: __return__ == True
    """
    state = make_state()
    state.regs[1] = r1_val
    state.regs[2] = r2_val

    # ADD R[rd], R1, R2, #0
    inst = make_instruction(0x01, rd=rd, ra=1, rb=2, imm=0)
    execute_instruction(state, inst)

    # If result is 0, Z flag must be set
    if state.regs[rd] == 0:
        return state.sr['Z'] == True
    return True


def check_negative_flag_invariant(r1_val: int, r2_val: int, rd: int) -> bool:
    """
    Symbolic: If MSB is set, Negative flag MUST be set.

    pre: 0 <= r1_val <= 0xFFFFFFFF
    pre: 0 <= r2_val <= 0xFFFFFFFF
    pre: 1 <= rd <= 15
    post: __return__ == True
    """
    state = make_state()
    state.regs[1] = r1_val
    state.regs[2] = r2_val

    # ADD R[rd], R1, R2, #0
    inst = make_instruction(0x01, rd=rd, ra=1, rb=2, imm=0)
    execute_instruction(state, inst)

    # If MSB is set, N flag must be set
    if state.regs[rd] & 0x80000000:
        return state.sr['N'] == True
    return True


def check_zero_negative_exclusive(r1_val: int, r2_val: int, rd: int) -> bool:
    """
    Symbolic: Zero and Negative flags cannot both be set.
    Zero is not negative.

    pre: 0 <= r1_val <= 0xFFFFFFFF
    pre: 0 <= r2_val <= 0xFFFFFFFF
    pre: 1 <= rd <= 15
    post: __return__ == True
    """
    state = make_state()
    state.regs[1] = r1_val
    state.regs[2] = r2_val

    # ADD R[rd], R1, R2, #0
    inst = make_instruction(0x01, rd=rd, ra=1, rb=2, imm=0)
    execute_instruction(state, inst)

    # Z and N cannot both be True
    return not (state.sr['Z'] and state.sr['N'])


def check_parity_flag_correctness(r1_val: int, r2_val: int, rd: int) -> bool:
    """
    Symbolic: Parity flag matches actual parity of lowest 8 bits.
    Even number of 1s -> P=True, Odd number of 1s -> P=False

    pre: 0 <= r1_val <= 0xFFFFFFFF
    pre: 0 <= r2_val <= 0xFFFFFFFF
    pre: 1 <= rd <= 15
    post: __return__ == True
    """
    state = make_state()
    state.regs[1] = r1_val
    state.regs[2] = r2_val

    # ADD R[rd], R1, R2, #0
    inst = make_instruction(0x01, rd=rd, ra=1, rb=2, imm=0)
    execute_instruction(state, inst)

    # Calculate expected parity
    lowest_byte = state.regs[rd] & 0xFF
    ones_count = bin(lowest_byte).count('1')
    expected_parity = (ones_count % 2 == 0)

    return state.sr['P'] == expected_parity


def check_pc_increment_non_jump(opcode: int, rd: int, ra: int, rb: int) -> bool:
    """
    Symbolic: PC increments by 4 for non-jump instructions.

    pre: opcode in [0x01, 0x02, 0x03, 0x04, 0x05]
    pre: 0 <= rd <= 15
    pre: 0 <= ra <= 15
    pre: 0 <= rb <= 15
    post: __return__ == True
    """
    state = make_state()
    state.pc = 100

    inst = make_instruction(opcode, rd=rd, ra=ra, rb=rb, imm=0)
    execute_instruction(state, inst)

    # PC must increment by 4
    return state.pc == 104


# ============================================================================
# SYMBOLIC TESTS - ARITHMETIC PROPERTIES
# ============================================================================

def check_add_identity(val: int) -> bool:
    """
    Symbolic: x + 0 = x (identity property)

    pre: 0 <= val <= 0xFFFFFFFF
    post: __return__ == True
    """
    state = make_state()
    state.regs[1] = val

    # ADD R2, R1, R0, #0
    inst = make_instruction(0x01, rd=2, ra=1, rb=0, imm=0)
    execute_instruction(state, inst)

    return state.regs[2] == val


def check_sub_identity(val: int) -> bool:
    """
    Symbolic: x - 0 = x (identity property)

    pre: 0 <= val <= 0xFFFFFFFF
    post: __return__ == True
    """
    state = make_state()
    state.regs[1] = val

    # SUB R2, R1, R0, #0
    inst = make_instruction(0x03, rd=2, ra=1, rb=0, imm=0)
    execute_instruction(state, inst)

    return state.regs[2] == val


def check_sub_self_zero(val: int) -> bool:
    """
    Symbolic: x - x = 0 (self-subtraction)

    pre: 0 <= val <= 0xFFFFFFFF
    post: __return__ == True
    """
    state = make_state()
    state.regs[1] = val

    # SUB R2, R1, R1, #0
    inst = make_instruction(0x03, rd=2, ra=1, rb=1, imm=0)
    execute_instruction(state, inst)

    return state.regs[2] == 0 and state.sr['Z'] == True


def check_add_commutative(a: int, b: int) -> bool:
    """
    Symbolic: a + b = b + a (commutativity)

    pre: 0 <= a <= 0xFFFF
    pre: 0 <= b <= 0xFFFF
    post: __return__ == True
    """
    # First: a + b
    state1 = make_state()
    state1.regs[1] = a
    state1.regs[2] = b
    execute_instruction(state1, make_instruction(0x01, rd=3, ra=1, rb=2, imm=0))

    # Second: b + a
    state2 = make_state()
    state2.regs[1] = b
    state2.regs[2] = a
    execute_instruction(state2, make_instruction(0x01, rd=3, ra=1, rb=2, imm=0))

    return state1.regs[3] == state2.regs[3]


# ============================================================================
# SYMBOLIC TESTS - CARRY/BORROW FLAGS
# ============================================================================

def check_add_carry_correctness(a: int, b: int, imm: int) -> bool:
    """
    Symbolic: Carry flag is correct for unsigned addition overflow.

    pre: 0 <= a <= 0xFFFFFFFF
    pre: 0 <= b <= 0xFFFFFFFF
    pre: 0 <= imm <= 255
    post: __return__ == True
    """
    state = make_state()
    state.regs[1] = a
    state.regs[2] = b

    # ADD R3, R1, R2, #imm
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=2, imm=imm))

    # Calculate expected carry
    result_64 = a + b + imm
    expected_carry = result_64 > 0xFFFFFFFF

    return state.sr['C'] == expected_carry


def check_sub_borrow_correctness(a: int, b: int, imm: int) -> bool:
    """
    Symbolic: Borrow (C) flag is correct for unsigned subtraction underflow.

    pre: 0 <= a <= 0xFFFFFFFF
    pre: 0 <= b <= 0xFFFFFFFF
    pre: 0 <= imm <= 255
    post: __return__ == True
    """
    state = make_state()
    state.regs[1] = a
    state.regs[2] = b

    # SUB R3, R1, R2, #imm
    execute_instruction(state, make_instruction(0x03, rd=3, ra=1, rb=2, imm=imm))

    # Calculate expected borrow
    expected_borrow = a < (b + imm)

    return state.sr['C'] == expected_borrow


def check_addc_carry_propagation(a: int, b: int, carry_in: bool) -> bool:
    """
    Symbolic: ADDC correctly adds the carry flag.

    pre: 0 <= a <= 0xFFFF
    pre: 0 <= b <= 0xFFFF
    post: __return__ == True
    """
    state = make_state()
    state.regs[1] = a
    state.regs[2] = b
    state.sr['C'] = carry_in

    # ADDC R3, R1, R2, #0
    execute_instruction(state, make_instruction(0x02, rd=3, ra=1, rb=2, imm=0))

    # Result should be a + b + carry_in
    expected = (a + b + (1 if carry_in else 0)) & 0xFFFFFFFF

    return state.regs[3] == expected


def check_subb_borrow_propagation(a: int, b: int, borrow_in: bool) -> bool:
    """
    Symbolic: SUBB correctly subtracts the borrow flag.

    pre: 0 <= a <= 0xFFFF
    pre: 0 <= b <= 0xFFFF
    post: __return__ == True
    """
    state = make_state()
    state.regs[1] = a
    state.regs[2] = b
    state.sr['C'] = borrow_in

    # SUBB R3, R1, R2, #0
    execute_instruction(state, make_instruction(0x04, rd=3, ra=1, rb=2, imm=0))

    # Result should be a - b - borrow_in
    expected = (a - b - (1 if borrow_in else 0)) & 0xFFFFFFFF

    return state.regs[3] == expected


# ============================================================================
# SYMBOLIC TESTS - OVERFLOW DETECTION
# ============================================================================

def check_overflow_pos_plus_pos(a: int, b: int) -> bool:
    """
    Symbolic: Overflow when positive + positive = negative.

    pre: 0 <= a <= 0x7FFFFFFF
    pre: 0 <= b <= 0x7FFFFFFF
    pre: a + b > 0x7FFFFFFF
    post: __return__ == True
    """
    state = make_state()
    state.regs[1] = a
    state.regs[2] = b

    # ADD R3, R1, R2, #0
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=2, imm=0))

    # Overflow should be set
    return state.sr['V'] == True


def check_no_overflow_opposite_signs(a: int, b: int) -> bool:
    """
    Symbolic: No overflow when adding opposite signs.

    pre: 0 <= a <= 0x7FFFFFFF
    pre: 0x80000000 <= b <= 0xFFFFFFFF
    post: __return__ == True
    """
    state = make_state()
    state.regs[1] = a
    state.regs[2] = b

    # ADD R3, R1, R2, #0
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=2, imm=0))

    # Overflow should NOT be set (opposite signs can't overflow)
    return state.sr['V'] == False


# ============================================================================
# SYMBOLIC TESTS - BIT OPERATIONS
# ============================================================================

def check_rotr_by_32_identity(val: int) -> bool:
    """
    Symbolic: Rotating by 32 bits returns original value.

    pre: 0 <= val <= 0xFFFFFFFF
    post: __return__ == True
    """
    state = make_state()
    state.regs[1] = val
    state.regs[2] = 16

    # ROTR R3, R1, R2, #16 (total = 32)
    execute_instruction(state, make_instruction(0x12, rd=3, ra=1, rb=2, imm=16))

    return state.regs[3] == val


def check_rotr_by_zero_identity(val: int) -> bool:
    """
    Symbolic: Rotating by 0 is identity.

    pre: 0 <= val <= 0xFFFFFFFF
    post: __return__ == True
    """
    state = make_state()
    state.regs[1] = val

    # ROTR R2, R1, R0, #0
    execute_instruction(state, make_instruction(0x12, rd=2, ra=1, rb=0, imm=0))

    return state.regs[2] == val


def check_bext_single_bit_range(val: int, pos: int) -> bool:
    """
    Symbolic: Extracting a single bit gives 0 or 1.

    pre: 0 <= val <= 0xFFFFFFFF
    pre: 0 <= pos <= 31
    post: __return__ == True
    """
    state = make_state()
    state.regs[1] = val
    state.regs[2] = pos

    # BEXT R3, R1, R2, #1
    execute_instruction(state, make_instruction(0x10, rd=3, ra=1, rb=2, imm=1))

    # Result should match the actual bit
    expected = (val >> pos) & 1
    return state.regs[3] == expected


def check_bext_zero_length(val: int, pos: int) -> bool:
    """
    Symbolic: Extracting zero bits gives 0.

    pre: 0 <= val <= 0xFFFFFFFF
    pre: 0 <= pos <= 31
    post: __return__ == True
    """
    state = make_state()
    state.regs[1] = val
    state.regs[2] = pos

    # BEXT R3, R1, R2, #0 (extract 0 bits)
    execute_instruction(state, make_instruction(0x10, rd=3, ra=1, rb=2, imm=0))

    return state.regs[3] == 0


# ============================================================================
# SYMBOLIC TESTS - CONTROL FLOW
# ============================================================================

def check_cjmp_eq_deterministic(target: int, z: bool) -> bool:
    """
    Symbolic: CJMP.EQ is deterministic based on Z flag.

    pre: 0 <= target <= 1023
    post: __return__ == True
    """
    state = make_state()
    state.sr['Z'] = z
    state.regs[1] = target

    # CJMP.EQ R1
    execute_instruction(state, make_instruction(0x20, cond_mod=0x0, ra=1))

    # If Z=True, should jump; otherwise PC += 4
    if z:
        return state.pc == target
    else:
        return state.pc == 4


def check_cjmp_ne_deterministic(target: int, z: bool) -> bool:
    """
    Symbolic: CJMP.NE is deterministic based on Z flag.

    pre: 0 <= target <= 1023
    post: __return__ == True
    """
    state = make_state()
    state.sr['Z'] = z
    state.regs[1] = target

    # CJMP.NE R1
    execute_instruction(state, make_instruction(0x20, cond_mod=0x1, ra=1))

    # If Z=False, should jump; otherwise PC += 4
    if not z:
        return state.pc == target
    else:
        return state.pc == 4


def check_cjmp_ge_deterministic(target: int, n: bool, v: bool) -> bool:
    """
    Symbolic: CJMP.GE is deterministic based on N and V flags.

    pre: 0 <= target <= 1023
    post: __return__ == True
    """
    state = make_state()
    state.sr['N'] = n
    state.sr['V'] = v
    state.regs[1] = target

    # CJMP.GE R1 (jump if N == V)
    execute_instruction(state, make_instruction(0x20, cond_mod=0x8, ra=1))

    # If N == V, should jump; otherwise PC += 4
    if n == v:
        return state.pc == target
    else:
        return state.pc == 4


def check_cjmp_lt_deterministic(target: int, n: bool, v: bool) -> bool:
    """
    Symbolic: CJMP.LT is deterministic based on N and V flags.

    pre: 0 <= target <= 1023
    post: __return__ == True
    """
    state = make_state()
    state.sr['N'] = n
    state.sr['V'] = v
    state.regs[1] = target

    # CJMP.LT R1 (jump if N != V)
    execute_instruction(state, make_instruction(0x20, cond_mod=0x9, ra=1))

    # If N != V, should jump; otherwise PC += 4
    if n != v:
        return state.pc == target
    else:
        return state.pc == 4


# ============================================================================
# SYMBOLIC TESTS - REGISTER BOUNDS
# ============================================================================

def check_all_registers_32bit_after_add(a: int, b: int) -> bool:
    """
    Symbolic: All registers remain in 32-bit range after ADD.

    pre: 0 <= a <= 0xFFFFFFFF
    pre: 0 <= b <= 0xFFFFFFFF
    post: __return__ == True
    """
    state = make_state()
    state.regs[1] = a
    state.regs[2] = b

    # ADD R3, R1, R2, #255
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=2, imm=255))

    # All registers must be in valid range
    for val in state.regs:
        if not (0 <= val <= 0xFFFFFFFF):
            return False
    return True


def check_all_registers_32bit_after_mul(a: int, b: int) -> bool:
    """
    Symbolic: All registers remain in 32-bit range after MULH.

    pre: 0 <= a <= 0xFFFFFFFF
    pre: 0 <= b <= 0xFFFFFFFF
    post: __return__ == True
    """
    state = make_state()
    state.regs[1] = a
    state.regs[2] = b

    # MULH R3, R1, R2
    execute_instruction(state, make_instruction(0x05, rd=3, ra=1, rb=2))

    # All registers must be in valid range
    for val in state.regs:
        if not (0 <= val <= 0xFFFFFFFF):
            return False
    return True


# ============================================================================
# SYMBOLIC TESTS - HALF-CARRY FLAG
# ============================================================================

def check_half_carry_bit3_to_bit4(a: int, b: int) -> bool:
    """
    Symbolic: Half-carry flag set when carry from bit 3 to bit 4.

    pre: 0 <= a <= 0xFFFFFFFF
    pre: 0 <= b <= 0xFFFFFFFF
    post: __return__ == True
    """
    state = make_state()
    state.regs[1] = a
    state.regs[2] = b

    # ADD R3, R1, R2, #0
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=2, imm=0))

    # Calculate expected half-carry
    low_nibble_sum = (a & 0x0F) + (b & 0x0F)
    expected_half_carry = low_nibble_sum > 0x0F

    return state.sr['H'] == expected_half_carry


# ============================================================================
# SYMBOLIC TESTS - DETERMINISM
# ============================================================================

def check_deterministic_execution(a: int, b: int, rd: int) -> bool:
    """
    Symbolic: Same inputs produce same outputs (determinism).

    pre: 0 <= a <= 0xFFFF
    pre: 0 <= b <= 0xFFFF
    pre: 1 <= rd <= 15
    post: __return__ == True
    """
    # First execution
    state1 = make_state()
    state1.regs[1] = a
    state1.regs[2] = b
    execute_instruction(state1, make_instruction(0x01, rd=rd, ra=1, rb=2, imm=0))

    # Second execution with same inputs
    state2 = make_state()
    state2.regs[1] = a
    state2.regs[2] = b
    execute_instruction(state2, make_instruction(0x01, rd=rd, ra=1, rb=2, imm=0))

    # Results must be identical
    return state1.regs[rd] == state2.regs[rd] and state1.sr == state2.sr
