from hypothesis import given, strategies as st, assume, settings
from tinyvm import CPUState, execute_instruction, N32Error
import pytest


def make_instruction(opcode, cond_mod=0, rd=0, ra=0, rb=0, imm=0):
    """Helper function to build 32-bit instruction in big-endian format."""
    return (opcode << 24) | (cond_mod << 20) | (rd << 16) | (ra << 12) | (rb << 8) | imm


def make_state():
    """Create a fresh CPU state for testing."""
    return CPUState(regs=[0]*16, pc=0, sr={f: False for f in "ZNCVPH"}, memory=bytearray(1024))


# ============================================================================
# PROPERTY-BASED TESTS - INVARIANTS
# ============================================================================

@given(st.integers(min_value=0, max_value=0xFFFFFFFF))
@settings(max_examples=1000)
def test_instruction_safety(inst):
    """PBT: Any instruction should not crash the VM"""
    state = make_state()
    try:
        execute_instruction(state, inst)
        # Execution should complete without exceptions (or raise expected N32Error)
    except N32Error:
        # N32Error is acceptable for invalid memory access
        pass
    except Exception as e:
        # Other exceptions indicate implementation issues
        pytest.fail(f"Unexpected exception for instruction {hex(inst)}: {e}")


@given(
    opcode=st.sampled_from([0x01, 0x02, 0x03, 0x04, 0x05]),  # Arithmetic ops
    rd=st.integers(min_value=0, max_value=15),
    ra=st.integers(min_value=0, max_value=15),
    rb=st.integers(min_value=0, max_value=15),
    imm=st.integers(min_value=0, max_value=255),
    r1_val=st.integers(min_value=0, max_value=0xFFFFFFFF),
    r2_val=st.integers(min_value=0, max_value=0xFFFFFFFF)
)
@settings(max_examples=500)
def test_r0_always_zero_arithmetic(opcode, rd, ra, rb, imm, r1_val, r2_val):
    """PBT: R0 is always 0 after any arithmetic operation"""
    state = make_state()
    state.regs[1] = r1_val
    state.regs[2] = r2_val

    inst = make_instruction(opcode, rd=rd, ra=ra, rb=rb, imm=imm)
    execute_instruction(state, inst)

    # R0 must always be 0
    assert state.regs[0] == 0, f"R0 = {state.regs[0]}, expected 0"


@given(
    opcode=st.sampled_from([0x01, 0x02, 0x03, 0x04]),  # ADD, ADDC, SUB, SUBB
    rd=st.integers(min_value=1, max_value=15),
    ra=st.integers(min_value=0, max_value=15),
    rb=st.integers(min_value=0, max_value=15),
    imm=st.integers(min_value=0, max_value=255),
    r1_val=st.integers(min_value=0, max_value=0xFFFFFFFF),
    r2_val=st.integers(min_value=0, max_value=0xFFFFFFFF)
)
@settings(max_examples=500)
def test_zero_flag_if_result_zero(opcode, rd, ra, rb, imm, r1_val, r2_val):
    """PBT: If result is 0, Zero flag must be set"""
    state = make_state()
    state.regs[1] = r1_val
    state.regs[2] = r2_val

    inst = make_instruction(opcode, rd=rd, ra=ra, rb=rb, imm=imm)
    execute_instruction(state, inst)

    if state.regs[rd] == 0:
        assert state.sr['Z'] is True, f"Result is 0 but Z flag is {state.sr['Z']}"


@given(
    opcode=st.sampled_from([0x01, 0x02, 0x03, 0x04]),
    rd=st.integers(min_value=1, max_value=15),
    ra=st.integers(min_value=0, max_value=15),
    rb=st.integers(min_value=0, max_value=15),
    imm=st.integers(min_value=0, max_value=255),
    r1_val=st.integers(min_value=0, max_value=0xFFFFFFFF),
    r2_val=st.integers(min_value=0, max_value=0xFFFFFFFF)
)
@settings(max_examples=500)
def test_negative_flag_if_msb_set(opcode, rd, ra, rb, imm, r1_val, r2_val):
    """PBT: If MSB is set, Negative flag must be set"""
    state = make_state()
    state.regs[1] = r1_val
    state.regs[2] = r2_val

    inst = make_instruction(opcode, rd=rd, ra=ra, rb=rb, imm=imm)
    execute_instruction(state, inst)

    if state.regs[rd] & 0x80000000:
        assert state.sr['N'] is True, f"MSB set but N flag is {state.sr['N']}"


@given(
    opcode=st.sampled_from([0x01, 0x02, 0x03, 0x04]),
    rd=st.integers(min_value=1, max_value=15),
    ra=st.integers(min_value=0, max_value=15),
    rb=st.integers(min_value=0, max_value=15),
    imm=st.integers(min_value=0, max_value=255),
    r1_val=st.integers(min_value=0, max_value=0xFFFFFFFF),
    r2_val=st.integers(min_value=0, max_value=0xFFFFFFFF)
)
@settings(max_examples=500)
def test_parity_flag_consistency(opcode, rd, ra, rb, imm, r1_val, r2_val):
    """PBT: Parity flag matches actual parity of lowest 8 bits"""
    state = make_state()
    state.regs[1] = r1_val
    state.regs[2] = r2_val

    inst = make_instruction(opcode, rd=rd, ra=ra, rb=rb, imm=imm)
    execute_instruction(state, inst)

    # Check parity of lowest 8 bits
    lowest_byte = state.regs[rd] & 0xFF
    ones_count = bin(lowest_byte).count('1')
    expected_parity = (ones_count % 2 == 0)

    assert state.sr['P'] == expected_parity, \
        f"Parity mismatch: result={hex(state.regs[rd])}, byte={hex(lowest_byte)}, ones={ones_count}, P={state.sr['P']}"


@given(
    rd=st.integers(min_value=1, max_value=15),
    ra=st.integers(min_value=0, max_value=15),
    rb=st.integers(min_value=0, max_value=15),
    imm=st.integers(min_value=0, max_value=255),
    r1_val=st.integers(min_value=0, max_value=0xFFFFFFFF),
    r2_val=st.integers(min_value=0, max_value=0xFFFFFFFF)
)
@settings(max_examples=300)
def test_zero_and_negative_mutually_exclusive(rd, ra, rb, imm, r1_val, r2_val):
    """PBT: Zero and Negative flags cannot both be set (0 is not negative)"""
    state = make_state()
    state.regs[1] = r1_val
    state.regs[2] = r2_val

    # Test with ADD
    inst = make_instruction(0x01, rd=rd, ra=ra, rb=rb, imm=imm)
    execute_instruction(state, inst)

    # Z and N should not both be True
    if state.sr['Z'] and state.sr['N']:
        pytest.fail(f"Both Z and N are set for result {hex(state.regs[rd])}")


@given(
    opcode=st.sampled_from([0x01, 0x02, 0x03, 0x04, 0x05]),
    rd=st.integers(min_value=0, max_value=15),
    ra=st.integers(min_value=0, max_value=15),
    rb=st.integers(min_value=0, max_value=15)
)
@settings(max_examples=300)
def test_pc_increments_non_jump(opcode, rd, ra, rb):
    """PBT: PC increments by 4 for non-jump instructions"""
    state = make_state()
    state.pc = 100

    inst = make_instruction(opcode, rd=rd, ra=ra, rb=rb, imm=0)
    execute_instruction(state, inst)

    # PC should increment by 4 for arithmetic ops
    assert state.pc == 104, f"PC should be 104, got {state.pc}"


# ============================================================================
# PROPERTY-BASED TESTS - ARITHMETIC PROPERTIES
# ============================================================================

@given(
    val=st.integers(min_value=0, max_value=0xFFFFFFFF)
)
@settings(max_examples=200)
def test_add_identity(val):
    """PBT: x + 0 = x"""
    state = make_state()
    state.regs[1] = val

    # ADD R2, R1, R0, #0 (R2 = R1 + 0 + 0)
    inst = make_instruction(0x01, rd=2, ra=1, rb=0, imm=0)
    execute_instruction(state, inst)

    assert state.regs[2] == val, f"Expected {val}, got {state.regs[2]}"


@given(
    val=st.integers(min_value=0, max_value=0xFFFFFFFF)
)
@settings(max_examples=200)
def test_sub_identity(val):
    """PBT: x - 0 = x"""
    state = make_state()
    state.regs[1] = val

    # SUB R2, R1, R0, #0 (R2 = R1 - 0 - 0)
    inst = make_instruction(0x03, rd=2, ra=1, rb=0, imm=0)
    execute_instruction(state, inst)

    assert state.regs[2] == val, f"Expected {val}, got {state.regs[2]}"


@given(
    val=st.integers(min_value=0, max_value=0xFFFFFFFF)
)
@settings(max_examples=200)
def test_sub_self_zero(val):
    """PBT: x - x = 0"""
    state = make_state()
    state.regs[1] = val

    # SUB R2, R1, R1, #0 (R2 = R1 - R1 - 0)
    inst = make_instruction(0x03, rd=2, ra=1, rb=1, imm=0)
    execute_instruction(state, inst)

    assert state.regs[2] == 0, f"Expected 0, got {state.regs[2]}"
    assert state.sr['Z'] is True, "Z flag should be set"


@given(
    a=st.integers(min_value=0, max_value=0xFFFF),  # Limit to avoid overflow
    b=st.integers(min_value=0, max_value=0xFFFF)
)
@settings(max_examples=200)
def test_add_commutative(a, b):
    """PBT: a + b = b + a"""
    state1 = make_state()
    state1.regs[1] = a
    state1.regs[2] = b
    # ADD R3, R1, R2, #0
    execute_instruction(state1, make_instruction(0x01, rd=3, ra=1, rb=2, imm=0))

    state2 = make_state()
    state2.regs[1] = b
    state2.regs[2] = a
    # ADD R3, R1, R2, #0
    execute_instruction(state2, make_instruction(0x01, rd=3, ra=1, rb=2, imm=0))

    assert state1.regs[3] == state2.regs[3], \
        f"{a} + {b} != {b} + {a}: {state1.regs[3]} != {state2.regs[3]}"


@given(
    val=st.integers(min_value=0, max_value=0xFFFFFFFF)
)
@settings(max_examples=200)
def test_mul_zero(val):
    """PBT: x * 0 = 0 (high bits)"""
    state = make_state()
    state.regs[1] = val
    state.regs[2] = 0

    # MULH R3, R1, R2
    inst = make_instruction(0x05, rd=3, ra=1, rb=2)
    execute_instruction(state, inst)

    # High bits of val * 0 should be 0
    assert state.regs[3] == 0, f"Expected 0, got {state.regs[3]}"


# ============================================================================
# PROPERTY-BASED TESTS - BIT OPERATIONS
# ============================================================================

@given(
    val=st.integers(min_value=0, max_value=0xFFFFFFFF),
    rot=st.integers(min_value=0, max_value=31)
)
@settings(max_examples=200)
def test_rotr_twice_returns_original(val, rot):
    """PBT: Rotating right by n then left by n returns original (test with 32-n)"""
    state = make_state()
    state.regs[1] = val
    state.regs[2] = rot

    # ROTR R3, R1, R2, #0 (rotate right by rot)
    execute_instruction(state, make_instruction(0x12, rd=3, ra=1, rb=2, imm=0))
    rotated = state.regs[3]

    # ROTR R4, R3, R0, #(32-rot) (rotate right by 32-rot = rotate left by rot)
    state.regs[3] = rotated
    inverse_rot = (32 - rot) % 32
    execute_instruction(state, make_instruction(0x12, rd=4, ra=3, rb=0, imm=inverse_rot))

    assert state.regs[4] == val, \
        f"Rotate {val} by {rot} then by {inverse_rot} should return {val}, got {state.regs[4]}"


@given(
    val=st.integers(min_value=0, max_value=0xFFFFFFFF)
)
@settings(max_examples=200)
def test_rotr_by_32_identity(val):
    """PBT: Rotating by 32 bits returns original value"""
    state = make_state()
    state.regs[1] = val
    state.regs[2] = 16

    # ROTR R3, R1, R2, #16 (total rotation = 32)
    execute_instruction(state, make_instruction(0x12, rd=3, ra=1, rb=2, imm=16))

    assert state.regs[3] == val, f"Expected {hex(val)}, got {hex(state.regs[3])}"


@given(
    val=st.integers(min_value=0, max_value=0xFFFFFFFF),
    pos=st.integers(min_value=0, max_value=31)
)
@settings(max_examples=200)
def test_bext_single_bit(val, pos):
    """PBT: Extracting a single bit gives 0 or 1"""
    state = make_state()
    state.regs[1] = val
    state.regs[2] = pos

    # BEXT R3, R1, R2, #1 (extract 1 bit at position pos)
    execute_instruction(state, make_instruction(0x10, rd=3, ra=1, rb=2, imm=1))

    # Result should be 0 or 1
    assert state.regs[3] in [0, 1], f"Single bit extract gave {state.regs[3]}"

    # Should match the actual bit at that position
    expected = (val >> pos) & 1
    assert state.regs[3] == expected, \
        f"Bit {pos} of {hex(val)} should be {expected}, got {state.regs[3]}"


# ============================================================================
# PROPERTY-BASED TESTS - CONTROL FLOW
# ============================================================================

@given(
    cond=st.sampled_from([0x0, 0x1, 0x2, 0x3, 0x4, 0x8, 0x9, 0xA, 0xB]),
    target=st.integers(min_value=0, max_value=1023),
    z=st.booleans(),
    n=st.booleans(),
    c=st.booleans(),
    v=st.booleans()
)
@settings(max_examples=500)
def test_cjmp_deterministic(cond, target, z, n, c, v):
    """PBT: CJMP behavior is deterministic for given flags"""
    state1 = make_state()
    state1.sr['Z'] = z
    state1.sr['N'] = n
    state1.sr['C'] = c
    state1.sr['V'] = v
    state1.regs[1] = target

    execute_instruction(state1, make_instruction(0x20, cond_mod=cond, ra=1))
    pc1 = state1.pc

    # Execute again with same flags
    state2 = make_state()
    state2.sr['Z'] = z
    state2.sr['N'] = n
    state2.sr['C'] = c
    state2.sr['V'] = v
    state2.regs[1] = target

    execute_instruction(state2, make_instruction(0x20, cond_mod=cond, ra=1))
    pc2 = state2.pc

    # Results should be identical
    assert pc1 == pc2, f"Nondeterministic CJMP: {pc1} != {pc2}"


@given(
    target=st.integers(min_value=0, max_value=1023)
)
@settings(max_examples=100)
def test_cjmp_eq_only_checks_z(target):
    """PBT: CJMP.EQ only depends on Z flag"""
    # When Z=True, should jump regardless of other flags
    for n in [True, False]:
        for c in [True, False]:
            for v in [True, False]:
                state = make_state()
                state.sr['Z'] = True
                state.sr['N'] = n
                state.sr['C'] = c
                state.sr['V'] = v
                state.regs[1] = target

                execute_instruction(state, make_instruction(0x20, cond_mod=0x0, ra=1))
                assert state.pc == target, f"CJMP.EQ should jump when Z=1"


# ============================================================================
# PROPERTY-BASED TESTS - CARRY/BORROW PROPAGATION
# ============================================================================

@given(
    a=st.integers(min_value=0, max_value=0xFFFFFFFF),
    b=st.integers(min_value=0, max_value=0xFFFFFFFF),
    imm=st.integers(min_value=0, max_value=255)
)
@settings(max_examples=300)
def test_add_carry_flag_correctness(a, b, imm):
    """PBT: Carry flag is set iff unsigned addition overflows"""
    state = make_state()
    state.regs[1] = a
    state.regs[2] = b

    # ADD R3, R1, R2, #imm
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=2, imm=imm))

    # Calculate expected carry
    result_64 = a + b + imm
    expected_carry = result_64 > 0xFFFFFFFF

    assert state.sr['C'] == expected_carry, \
        f"Carry flag mismatch: {a} + {b} + {imm} = {result_64}, carry should be {expected_carry}"


@given(
    a=st.integers(min_value=0, max_value=0xFFFFFFFF),
    b=st.integers(min_value=0, max_value=0xFFFFFFFF),
    imm=st.integers(min_value=0, max_value=255)
)
@settings(max_examples=300)
def test_sub_borrow_flag_correctness(a, b, imm):
    """PBT: Borrow (C) flag is set iff unsigned subtraction underflows"""
    state = make_state()
    state.regs[1] = a
    state.regs[2] = b

    # SUB R3, R1, R2, #imm
    execute_instruction(state, make_instruction(0x03, rd=3, ra=1, rb=2, imm=imm))

    # Calculate expected borrow
    expected_borrow = a < (b + imm)

    assert state.sr['C'] == expected_borrow, \
        f"Borrow flag mismatch: {a} - {b} - {imm}, borrow should be {expected_borrow}"


# ============================================================================
# PROPERTY-BASED TESTS - OVERFLOW DETECTION
# ============================================================================

@given(
    a=st.integers(min_value=0, max_value=0x7FFFFFFF),  # Positive values
    b=st.integers(min_value=0, max_value=0x7FFFFFFF)
)
@settings(max_examples=200)
def test_add_overflow_pos_pos(a, b):
    """PBT: Overflow when two positive numbers sum to negative"""
    assume(a > 0 and b > 0)  # Both positive
    assume(a + b > 0x7FFFFFFF)  # Would overflow

    state = make_state()
    state.regs[1] = a
    state.regs[2] = b

    # ADD R3, R1, R2, #0
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=2, imm=0))

    # Overflow should be set
    assert state.sr['V'] is True, \
        f"Overflow not set for {a} + {b} = {state.regs[3]}"


@given(
    a=st.integers(min_value=0x80000000, max_value=0xFFFFFFFF),  # Negative values
    b=st.integers(min_value=0x80000000, max_value=0xFFFFFFFF)
)
@settings(max_examples=200)
def test_add_overflow_neg_neg(a, b):
    """PBT: Overflow when two negative numbers sum to positive"""
    # In two's complement, a and b are negative
    # Convert to signed for checking
    signed_a = a if a < 0x80000000 else a - 0x100000000
    signed_b = b if b < 0x80000000 else b - 0x100000000
    signed_sum = signed_a + signed_b

    assume(signed_sum < -0x80000000)  # Would overflow in negative direction

    state = make_state()
    state.regs[1] = a
    state.regs[2] = b

    # ADD R3, R1, R2, #0
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=2, imm=0))

    # Overflow should be set
    assert state.sr['V'] is True, \
        f"Overflow not set for {hex(a)} + {hex(b)} = {hex(state.regs[3])}"


# ============================================================================
# PROPERTY-BASED TESTS - REGISTER BOUNDS
# ============================================================================

@given(
    reg_values=st.lists(
        st.integers(min_value=0, max_value=0xFFFFFFFF),
        min_size=16,
        max_size=16
    ),
    opcode=st.sampled_from([0x01, 0x02, 0x03, 0x04, 0x05])
)
@settings(max_examples=200)
def test_all_registers_bounded(reg_values, opcode):
    """PBT: All register values remain in 32-bit range"""
    state = make_state()
    state.regs = list(reg_values)

    # Execute arbitrary arithmetic instruction
    inst = make_instruction(opcode, rd=5, ra=1, rb=2, imm=100)
    execute_instruction(state, inst)

    # All registers should be in valid range
    for i, val in enumerate(state.regs):
        assert 0 <= val <= 0xFFFFFFFF, \
            f"R{i} out of bounds: {val}"


# ============================================================================
# PROPERTY-BASED TESTS - IDEMPOTENCE
# ============================================================================

@given(
    val=st.integers(min_value=0, max_value=0xFFFFFFFF)
)
@settings(max_examples=100)
def test_rotr_by_zero_idempotent(val):
    """PBT: Rotating by 0 is idempotent"""
    state = make_state()
    state.regs[1] = val

    # ROTR R2, R1, R0, #0
    execute_instruction(state, make_instruction(0x12, rd=2, ra=1, rb=0, imm=0))

    assert state.regs[2] == val, f"ROTR by 0 changed value: {hex(val)} -> {hex(state.regs[2])}"


# ============================================================================
# PROPERTY-BASED TESTS - FLAGS CONSISTENCY
# ============================================================================

@given(
    rd=st.integers(min_value=1, max_value=15),
    ra=st.integers(min_value=0, max_value=15),
    rb=st.integers(min_value=0, max_value=15),
    imm=st.integers(min_value=0, max_value=255)
)
@settings(max_examples=200)
def test_multiple_execution_same_result(rd, ra, rb, imm):
    """PBT: Executing same instruction twice with same state gives same result"""
    # First execution
    state1 = make_state()
    state1.regs[1] = 12345
    state1.regs[2] = 67890
    inst = make_instruction(0x01, rd=rd, ra=ra, rb=rb, imm=imm)
    execute_instruction(state1, inst)

    # Second execution with same initial state
    state2 = make_state()
    state2.regs[1] = 12345
    state2.regs[2] = 67890
    execute_instruction(state2, inst)

    # Results should be identical
    assert state1.regs[rd] == state2.regs[rd], "Nondeterministic execution"
    assert state1.sr == state2.sr, "Nondeterministic flags"
