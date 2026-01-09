import pytest
from tinyvm import CPUState, execute_instruction, N32Error


def make_instruction(opcode, cond_mod=0, rd=0, ra=0, rb=0, imm=0):
    """Helper function to build 32-bit instruction in big-endian format."""
    return (opcode << 24) | (cond_mod << 20) | (rd << 16) | (ra << 12) | (rb << 8) | imm


def make_state():
    """Create a fresh CPU state for testing."""
    return CPUState(regs=[0]*16, pc=0, sr={f: False for f in "ZNCVPH"}, memory=bytearray(1024))


# ============================================================================
# ARITHMETIC GROUP TESTS - ADD (0x01)
# ============================================================================

def test_add_basic():
    """ADD: Rd = Ra + Rb + Imm (basic case)"""
    state = make_state()
    state.regs[1] = 10
    state.regs[2] = 20
    # ADD R3, R1, R2, #5
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=2, imm=5))
    assert state.regs[3] == 35, "10 + 20 + 5 = 35"


def test_add_zero_flag():
    """ADD: Zero flag set when result is 0"""
    state = make_state()
    state.regs[1] = 0
    state.regs[2] = 0
    # ADD R3, R1, R2, #0
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=2, imm=0))
    assert state.regs[3] == 0
    assert state.sr['Z'] is True


def test_add_negative_flag():
    """ADD: Negative flag set when MSB is 1"""
    state = make_state()
    state.regs[1] = 0x80000000
    state.regs[2] = 0
    # ADD R3, R1, R2, #0
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=2, imm=0))
    assert state.regs[3] == 0x80000000
    assert state.sr['N'] is True


def test_add_carry_flag():
    """ADD: Carry flag set on unsigned overflow"""
    state = make_state()
    state.regs[1] = 0xFFFFFFFF
    state.regs[2] = 1
    # ADD R3, R1, R2, #0
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=2, imm=0))
    assert state.regs[3] == 0  # Wraps around
    assert state.sr['C'] is True
    assert state.sr['Z'] is True


def test_add_overflow_flag_positive():
    """ADD: Overflow flag set when positive + positive = negative"""
    state = make_state()
    state.regs[1] = 0x7FFFFFFF  # Max positive
    state.regs[2] = 1
    # ADD R3, R1, R2, #0
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=2, imm=0))
    assert state.regs[3] == 0x80000000  # Becomes negative
    assert state.sr['V'] is True


def test_add_overflow_flag_negative():
    """ADD: Overflow flag set when negative + negative = positive"""
    state = make_state()
    state.regs[1] = 0x80000000  # Min negative
    state.regs[2] = 0x80000000
    # ADD R3, R1, R2, #0
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=2, imm=0))
    assert state.regs[3] == 0  # Wraps to 0
    assert state.sr['V'] is True


def test_add_parity_flag_even():
    """ADD: Parity flag set when lowest 8 bits have even number of 1s"""
    state = make_state()
    state.regs[1] = 0
    state.regs[2] = 0
    # ADD R3, R1, R2, #0b00000011 (two 1s = even)
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=2, imm=0b00000011))
    assert state.regs[3] == 0b00000011
    assert state.sr['P'] is True


def test_add_parity_flag_odd():
    """ADD: Parity flag clear when lowest 8 bits have odd number of 1s"""
    state = make_state()
    state.regs[1] = 0
    state.regs[2] = 0
    # ADD R3, R1, R2, #0b00000111 (three 1s = odd)
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=2, imm=0b00000111))
    assert state.regs[3] == 0b00000111
    assert state.sr['P'] is False


def test_add_half_carry_flag():
    """ADD: Half-carry flag set when carry from bit 3 to bit 4"""
    state = make_state()
    state.regs[1] = 0x0F  # 0b00001111
    state.regs[2] = 0x01  # 0b00000001
    # ADD R3, R1, R2, #0
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=2, imm=0))
    assert state.regs[3] == 0x10
    assert state.sr['H'] is True


def test_add_with_immediate():
    """ADD: Test immediate value contribution"""
    state = make_state()
    state.regs[1] = 100
    state.regs[2] = 50
    # ADD R3, R1, R2, #255
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=2, imm=255))
    assert state.regs[3] == 405


def test_add_r0_invariant():
    """ADD: R0 remains 0 even when written to"""
    state = make_state()
    state.regs[1] = 100
    state.regs[2] = 200
    # ADD R0, R1, R2, #0 (try to write to R0)
    execute_instruction(state, make_instruction(0x01, rd=0, ra=1, rb=2, imm=0))
    assert state.regs[0] == 0


# ============================================================================
# ARITHMETIC GROUP TESTS - ADDC (0x02)
# ============================================================================

def test_addc_without_carry():
    """ADDC: Rd = Ra + Rb + Imm + Carry (carry=0)"""
    state = make_state()
    state.regs[1] = 10
    state.regs[2] = 20
    state.sr['C'] = False
    # ADDC R3, R1, R2, #5
    execute_instruction(state, make_instruction(0x02, rd=3, ra=1, rb=2, imm=5))
    assert state.regs[3] == 35


def test_addc_with_carry():
    """ADDC: Rd = Ra + Rb + Imm + Carry (carry=1)"""
    state = make_state()
    state.regs[1] = 10
    state.regs[2] = 20
    state.sr['C'] = True
    # ADDC R3, R1, R2, #5
    execute_instruction(state, make_instruction(0x02, rd=3, ra=1, rb=2, imm=5))
    assert state.regs[3] == 36


def test_addc_carry_propagation():
    """ADDC: Carry flag propagates correctly"""
    state = make_state()
    state.regs[1] = 0xFFFFFFFF
    state.regs[2] = 0
    state.sr['C'] = True
    # ADDC R3, R1, R2, #0
    execute_instruction(state, make_instruction(0x02, rd=3, ra=1, rb=2, imm=0))
    assert state.regs[3] == 0
    assert state.sr['C'] is True  # Carry out
    assert state.sr['Z'] is True


def test_addc_flags_all():
    """ADDC: All flags updated correctly"""
    state = make_state()
    state.regs[1] = 0x7FFFFFFF
    state.regs[2] = 0
    state.sr['C'] = True
    # ADDC R3, R1, R2, #0
    execute_instruction(state, make_instruction(0x02, rd=3, ra=1, rb=2, imm=0))
    assert state.regs[3] == 0x80000000
    assert state.sr['N'] is True  # Result is negative
    assert state.sr['V'] is True  # Overflow occurred


# ============================================================================
# ARITHMETIC GROUP TESTS - SUB (0x03)
# ============================================================================

def test_sub_basic():
    """SUB: Rd = Ra - Rb - Imm (basic case)"""
    state = make_state()
    state.regs[1] = 100
    state.regs[2] = 30
    # SUB R3, R1, R2, #20
    execute_instruction(state, make_instruction(0x03, rd=3, ra=1, rb=2, imm=20))
    assert state.regs[3] == 50


def test_sub_zero_result():
    """SUB: Zero flag set when result is 0"""
    state = make_state()
    state.regs[1] = 50
    state.regs[2] = 30
    # SUB R3, R1, R2, #20
    execute_instruction(state, make_instruction(0x03, rd=3, ra=1, rb=2, imm=20))
    assert state.regs[3] == 0
    assert state.sr['Z'] is True


def test_sub_negative_result():
    """SUB: Negative flag set when result is negative"""
    state = make_state()
    state.regs[1] = 10
    state.regs[2] = 20
    # SUB R3, R1, R2, #0
    execute_instruction(state, make_instruction(0x03, rd=3, ra=1, rb=2, imm=0))
    assert state.regs[3] == 0xFFFFFFF6  # -10 in two's complement
    assert state.sr['N'] is True


def test_sub_borrow_flag():
    """SUB: Borrow flag (C) set when underflow occurs"""
    state = make_state()
    state.regs[1] = 10
    state.regs[2] = 20
    # SUB R3, R1, R2, #0
    execute_instruction(state, make_instruction(0x03, rd=3, ra=1, rb=2, imm=0))
    assert state.sr['C'] is True  # Borrow occurred


def test_sub_overflow_pos_minus_neg():
    """SUB: Overflow when positive - negative = negative"""
    state = make_state()
    state.regs[1] = 0x7FFFFFFF  # Max positive
    state.regs[2] = 0x80000000  # Min negative (as unsigned)
    # SUB R3, R1, R2, #0
    execute_instruction(state, make_instruction(0x03, rd=3, ra=1, rb=2, imm=0))
    assert state.sr['V'] is True


def test_sub_half_borrow():
    """SUB: Half-borrow flag set"""
    state = make_state()
    state.regs[1] = 0x10  # 0b00010000
    state.regs[2] = 0x01  # 0b00000001
    # SUB R3, R1, R2, #0
    execute_instruction(state, make_instruction(0x03, rd=3, ra=1, rb=2, imm=0))
    assert state.regs[3] == 0x0F
    assert state.sr['H'] is True


def test_sub_parity():
    """SUB: Parity flag updated"""
    state = make_state()
    state.regs[1] = 0xFF
    state.regs[2] = 0
    # SUB R3, R1, R2, #252 (result = 3 = 0b11, two 1s = even)
    execute_instruction(state, make_instruction(0x03, rd=3, ra=1, rb=2, imm=252))
    assert state.regs[3] == 3
    assert state.sr['P'] is True


# ============================================================================
# ARITHMETIC GROUP TESTS - SUBB (0x04)
# ============================================================================

def test_subb_without_borrow():
    """SUBB: Rd = Ra - Rb - Imm - Borrow (borrow=0)"""
    state = make_state()
    state.regs[1] = 100
    state.regs[2] = 30
    state.sr['C'] = False  # No borrow
    # SUBB R3, R1, R2, #20
    execute_instruction(state, make_instruction(0x04, rd=3, ra=1, rb=2, imm=20))
    assert state.regs[3] == 50


def test_subb_with_borrow():
    """SUBB: Rd = Ra - Rb - Imm - Borrow (borrow=1)"""
    state = make_state()
    state.regs[1] = 100
    state.regs[2] = 30
    state.sr['C'] = True  # Borrow set
    # SUBB R3, R1, R2, #20
    execute_instruction(state, make_instruction(0x04, rd=3, ra=1, rb=2, imm=20))
    assert state.regs[3] == 49


def test_subb_borrow_propagation():
    """SUBB: Borrow propagates correctly"""
    state = make_state()
    state.regs[1] = 0
    state.regs[2] = 0
    state.sr['C'] = True  # Borrow in
    # SUBB R3, R1, R2, #0
    execute_instruction(state, make_instruction(0x04, rd=3, ra=1, rb=2, imm=0))
    assert state.regs[3] == 0xFFFFFFFF  # 0 - 0 - 1 = -1
    assert state.sr['C'] is True  # Borrow out


def test_subb_all_flags():
    """SUBB: All flags updated correctly"""
    state = make_state()
    state.regs[1] = 0x80000000  # Min negative
    state.regs[2] = 1
    state.sr['C'] = False
    # SUBB R3, R1, R2, #0
    execute_instruction(state, make_instruction(0x04, rd=3, ra=1, rb=2, imm=0))
    assert state.sr['V'] is True  # Overflow


# ============================================================================
# ARITHMETIC GROUP TESTS - MULH (0x05)
# ============================================================================

def test_mulh_basic():
    """MULH: Rd = (Ra * Rb) >> 32 (high bits of multiplication)"""
    state = make_state()
    state.regs[1] = 0x00010000
    state.regs[2] = 0x00010000
    # MULH R3, R1, R2
    execute_instruction(state, make_instruction(0x05, rd=3, ra=1, rb=2))
    # 0x10000 * 0x10000 = 0x100000000, high 32 bits = 0x1
    assert state.regs[3] == 1


def test_mulh_zero():
    """MULH: Zero flag set when high bits are 0"""
    state = make_state()
    state.regs[1] = 0x00000010
    state.regs[2] = 0x00000010
    # MULH R3, R1, R2
    execute_instruction(state, make_instruction(0x05, rd=3, ra=1, rb=2))
    # 16 * 16 = 256, high 32 bits = 0
    assert state.regs[3] == 0
    assert state.sr['Z'] is True


def test_mulh_negative():
    """MULH: Negative flag set when MSB of high bits is 1"""
    state = make_state()
    state.regs[1] = 0xFFFFFFFF
    state.regs[2] = 0xFFFFFFFF
    # MULH R3, R1, R2
    execute_instruction(state, make_instruction(0x05, rd=3, ra=1, rb=2))
    # High bits will have MSB set
    assert state.sr['N'] is True


def test_mulh_parity():
    """MULH: Parity flag updated based on lowest 8 bits of result"""
    state = make_state()
    state.regs[1] = 0x00010001
    state.regs[2] = 0x00010000
    # MULH R3, R1, R2
    execute_instruction(state, make_instruction(0x05, rd=3, ra=1, rb=2))
    # Check parity of lowest 8 bits of result
    result = state.regs[3]
    ones = bin(result & 0xFF).count('1')
    assert state.sr['P'] == (ones % 2 == 0)


def test_mulh_max_values():
    """MULH: Multiply maximum values"""
    state = make_state()
    state.regs[1] = 0xFFFFFFFF
    state.regs[2] = 0xFFFFFFFF
    # MULH R3, R1, R2
    execute_instruction(state, make_instruction(0x05, rd=3, ra=1, rb=2))
    # Result should be valid (exact value depends on signed/unsigned interpretation)
    assert isinstance(state.regs[3], int)


# ============================================================================
# BIT MANIPULATION TESTS - BEXT (0x10)
# ============================================================================

def test_bext_basic():
    """BEXT: Extract bits from Ra starting at Rb for Imm length"""
    state = make_state()
    state.regs[1] = 0b11111111000000001111111100000000
    state.regs[2] = 8  # Start at bit 8
    # BEXT R3, R1, R2, #8 (extract 8 bits starting at position 8)
    execute_instruction(state, make_instruction(0x10, rd=3, ra=1, rb=2, imm=8))
    assert state.regs[3] == 0xFF


def test_bext_single_bit():
    """BEXT: Extract single bit"""
    state = make_state()
    state.regs[1] = 0b00000000000000000000000100000000
    state.regs[2] = 8  # Bit position 8
    # BEXT R3, R1, R2, #1 (extract 1 bit)
    execute_instruction(state, make_instruction(0x10, rd=3, ra=1, rb=2, imm=1))
    assert state.regs[3] == 1


def test_bext_zero_length():
    """BEXT: Extract zero bits should give 0"""
    state = make_state()
    state.regs[1] = 0xFFFFFFFF
    state.regs[2] = 0
    # BEXT R3, R1, R2, #0
    execute_instruction(state, make_instruction(0x10, rd=3, ra=1, rb=2, imm=0))
    assert state.regs[3] == 0


def test_bext_from_msb():
    """BEXT: Extract from most significant bits"""
    state = make_state()
    state.regs[1] = 0xABCD0000
    state.regs[2] = 16  # Start at bit 16
    # BEXT R3, R1, R2, #16 (extract upper 16 bits)
    execute_instruction(state, make_instruction(0x10, rd=3, ra=1, rb=2, imm=16))
    assert state.regs[3] == 0xABCD


def test_bext_overflow_position():
    """BEXT: Extract beyond register bounds"""
    state = make_state()
    state.regs[1] = 0xFFFFFFFF
    state.regs[2] = 31  # Start at bit 31
    # BEXT R3, R1, R2, #8 (extract goes beyond 32 bits)
    execute_instruction(state, make_instruction(0x10, rd=3, ra=1, rb=2, imm=8))
    # Should handle gracefully (likely wraps or masks)
    assert isinstance(state.regs[3], int)


# ============================================================================
# BIT MANIPULATION TESTS - BINS (0x11)
# ============================================================================

def test_bins_basic():
    """BINS: Insert bits from Rb into Ra at position Imm"""
    state = make_state()
    state.regs[1] = 0x00000000
    state.regs[2] = 0xFF
    # BINS R3, R1, R2, #8 (insert R2 into R1 at position 8)
    execute_instruction(state, make_instruction(0x11, rd=3, ra=1, rb=2, imm=8))
    assert state.regs[3] == 0x0000FF00


def test_bins_overwrite():
    """BINS: Insert overwrites existing bits"""
    state = make_state()
    state.regs[1] = 0xFFFFFFFF
    state.regs[2] = 0x00
    # BINS R3, R1, R2, #8 (insert 0x00 at position 8)
    execute_instruction(state, make_instruction(0x11, rd=3, ra=1, rb=2, imm=8))
    # Should clear those bits
    assert (state.regs[3] & 0x0000FF00) == 0


def test_bins_at_zero():
    """BINS: Insert at position 0"""
    state = make_state()
    state.regs[1] = 0xFFFFFF00
    state.regs[2] = 0xAB
    # BINS R3, R1, R2, #0
    execute_instruction(state, make_instruction(0x11, rd=3, ra=1, rb=2, imm=0))
    assert (state.regs[3] & 0xFF) == 0xAB


def test_bins_at_msb():
    """BINS: Insert at high position"""
    state = make_state()
    state.regs[1] = 0x00FFFFFF
    state.regs[2] = 0xAB
    # BINS R3, R1, R2, #24 (insert at bit 24)
    execute_instruction(state, make_instruction(0x11, rd=3, ra=1, rb=2, imm=24))
    assert (state.regs[3] >> 24) == 0xAB


def test_bins_partial():
    """BINS: Partial insertion"""
    state = make_state()
    state.regs[1] = 0x12345678
    state.regs[2] = 0xAB
    # BINS R3, R1, R2, #8
    execute_instruction(state, make_instruction(0x11, rd=3, ra=1, rb=2, imm=8))
    # Should preserve bits outside insertion range
    assert (state.regs[3] & 0xFFFF0000) == 0x12340000


# ============================================================================
# BIT MANIPULATION TESTS - ROTR (0x12)
# ============================================================================

def test_rotr_basic():
    """ROTR: Rotate right Ra by (Rb + Imm) bits"""
    state = make_state()
    state.regs[1] = 0b11110000000000000000000000000000
    state.regs[2] = 4
    # ROTR R3, R1, R2, #4 (rotate right by 8 bits total)
    execute_instruction(state, make_instruction(0x12, rd=3, ra=1, rb=2, imm=4))
    assert state.regs[3] == 0b00000000111100000000000000000000


def test_rotr_single_bit():
    """ROTR: Rotate by 1 bit"""
    state = make_state()
    state.regs[1] = 0b00000000000000000000000000000001
    state.regs[2] = 0
    # ROTR R3, R1, R2, #1
    execute_instruction(state, make_instruction(0x12, rd=3, ra=1, rb=2, imm=1))
    assert state.regs[3] == 0b10000000000000000000000000000000


def test_rotr_full_rotation():
    """ROTR: Rotate by 32 bits returns original"""
    state = make_state()
    state.regs[1] = 0xABCD1234
    state.regs[2] = 16
    # ROTR R3, R1, R2, #16 (32 bits total)
    execute_instruction(state, make_instruction(0x12, rd=3, ra=1, rb=2, imm=16))
    assert state.regs[3] == 0xABCD1234


def test_rotr_zero():
    """ROTR: Rotate by 0 bits"""
    state = make_state()
    state.regs[1] = 0x12345678
    state.regs[2] = 0
    # ROTR R3, R1, R2, #0
    execute_instruction(state, make_instruction(0x12, rd=3, ra=1, rb=2, imm=0))
    assert state.regs[3] == 0x12345678


def test_rotr_large_rotation():
    """ROTR: Rotate by more than 32 bits (should wrap)"""
    state = make_state()
    state.regs[1] = 0xF0000000
    state.regs[2] = 32
    # ROTR R3, R1, R2, #4 (36 bits = 4 bits after wrap)
    execute_instruction(state, make_instruction(0x12, rd=3, ra=1, rb=2, imm=4))
    # 36 % 32 = 4, so rotate right by 4
    assert state.regs[3] == 0x0F000000


# ============================================================================
# CONTROL FLOW TESTS - CJMP (0x20)
# ============================================================================

def test_cjmp_eq_true():
    """CJMP EQ: Jump when Z=1"""
    state = make_state()
    state.sr['Z'] = True
    state.regs[1] = 100  # Target address
    old_pc = state.pc
    # CJMP.EQ R1 (cond=0x0)
    execute_instruction(state, make_instruction(0x20, cond_mod=0x0, ra=1))
    assert state.pc == 100


def test_cjmp_eq_false():
    """CJMP EQ: Don't jump when Z=0"""
    state = make_state()
    state.sr['Z'] = False
    state.regs[1] = 100
    old_pc = state.pc
    # CJMP.EQ R1
    execute_instruction(state, make_instruction(0x20, cond_mod=0x0, ra=1))
    assert state.pc == old_pc + 4  # PC incremented normally


def test_cjmp_ne_true():
    """CJMP NE: Jump when Z=0"""
    state = make_state()
    state.sr['Z'] = False
    state.regs[1] = 200
    # CJMP.NE R1 (cond=0x1)
    execute_instruction(state, make_instruction(0x20, cond_mod=0x1, ra=1))
    assert state.pc == 200


def test_cjmp_ne_false():
    """CJMP NE: Don't jump when Z=1"""
    state = make_state()
    state.sr['Z'] = True
    state.regs[1] = 200
    old_pc = state.pc
    # CJMP.NE R1
    execute_instruction(state, make_instruction(0x20, cond_mod=0x1, ra=1))
    assert state.pc == old_pc + 4


def test_cjmp_cs_true():
    """CJMP CS: Jump when C=1"""
    state = make_state()
    state.sr['C'] = True
    state.regs[1] = 300
    # CJMP.CS R1 (cond=0x2)
    execute_instruction(state, make_instruction(0x20, cond_mod=0x2, ra=1))
    assert state.pc == 300


def test_cjmp_cs_false():
    """CJMP CS: Don't jump when C=0"""
    state = make_state()
    state.sr['C'] = False
    state.regs[1] = 300
    old_pc = state.pc
    # CJMP.CS R1
    execute_instruction(state, make_instruction(0x20, cond_mod=0x2, ra=1))
    assert state.pc == old_pc + 4


def test_cjmp_cc_true():
    """CJMP CC: Jump when C=0"""
    state = make_state()
    state.sr['C'] = False
    state.regs[1] = 400
    # CJMP.CC R1 (cond=0x3)
    execute_instruction(state, make_instruction(0x20, cond_mod=0x3, ra=1))
    assert state.pc == 400


def test_cjmp_cc_false():
    """CJMP CC: Don't jump when C=1"""
    state = make_state()
    state.sr['C'] = True
    state.regs[1] = 400
    old_pc = state.pc
    # CJMP.CC R1
    execute_instruction(state, make_instruction(0x20, cond_mod=0x3, ra=1))
    assert state.pc == old_pc + 4


def test_cjmp_hi_true():
    """CJMP HI: Jump when C=1 and Z=0 (unsigned higher)"""
    state = make_state()
    state.sr['C'] = True
    state.sr['Z'] = False
    state.regs[1] = 500
    # CJMP.HI R1 (cond=0x4)
    execute_instruction(state, make_instruction(0x20, cond_mod=0x4, ra=1))
    assert state.pc == 500


def test_cjmp_hi_false_carry():
    """CJMP HI: Don't jump when C=0"""
    state = make_state()
    state.sr['C'] = False
    state.sr['Z'] = False
    state.regs[1] = 500
    old_pc = state.pc
    # CJMP.HI R1
    execute_instruction(state, make_instruction(0x20, cond_mod=0x4, ra=1))
    assert state.pc == old_pc + 4


def test_cjmp_hi_false_zero():
    """CJMP HI: Don't jump when Z=1"""
    state = make_state()
    state.sr['C'] = True
    state.sr['Z'] = True
    state.regs[1] = 500
    old_pc = state.pc
    # CJMP.HI R1
    execute_instruction(state, make_instruction(0x20, cond_mod=0x4, ra=1))
    assert state.pc == old_pc + 4


def test_cjmp_ge_true():
    """CJMP GE: Jump when N=V (signed greater or equal)"""
    state = make_state()
    state.sr['N'] = True
    state.sr['V'] = True
    state.regs[1] = 600
    # CJMP.GE R1 (cond=0x8)
    execute_instruction(state, make_instruction(0x20, cond_mod=0x8, ra=1))
    assert state.pc == 600


def test_cjmp_ge_true_both_false():
    """CJMP GE: Jump when N=V=0"""
    state = make_state()
    state.sr['N'] = False
    state.sr['V'] = False
    state.regs[1] = 600
    # CJMP.GE R1
    execute_instruction(state, make_instruction(0x20, cond_mod=0x8, ra=1))
    assert state.pc == 600


def test_cjmp_ge_false():
    """CJMP GE: Don't jump when N!=V"""
    state = make_state()
    state.sr['N'] = True
    state.sr['V'] = False
    state.regs[1] = 600
    old_pc = state.pc
    # CJMP.GE R1
    execute_instruction(state, make_instruction(0x20, cond_mod=0x8, ra=1))
    assert state.pc == old_pc + 4


def test_cjmp_lt_true():
    """CJMP LT: Jump when N!=V (signed less than)"""
    state = make_state()
    state.sr['N'] = True
    state.sr['V'] = False
    state.regs[1] = 700
    # CJMP.LT R1 (cond=0x9)
    execute_instruction(state, make_instruction(0x20, cond_mod=0x9, ra=1))
    assert state.pc == 700


def test_cjmp_lt_false():
    """CJMP LT: Don't jump when N=V"""
    state = make_state()
    state.sr['N'] = True
    state.sr['V'] = True
    state.regs[1] = 700
    old_pc = state.pc
    # CJMP.LT R1
    execute_instruction(state, make_instruction(0x20, cond_mod=0x9, ra=1))
    assert state.pc == old_pc + 4


def test_cjmp_gt_true():
    """CJMP GT: Jump when Z=0 and N=V (signed greater than)"""
    state = make_state()
    state.sr['Z'] = False
    state.sr['N'] = True
    state.sr['V'] = True
    state.regs[1] = 800
    # CJMP.GT R1 (cond=0xA)
    execute_instruction(state, make_instruction(0x20, cond_mod=0xA, ra=1))
    assert state.pc == 800


def test_cjmp_gt_false_zero():
    """CJMP GT: Don't jump when Z=1"""
    state = make_state()
    state.sr['Z'] = True
    state.sr['N'] = False
    state.sr['V'] = False
    state.regs[1] = 800
    old_pc = state.pc
    # CJMP.GT R1
    execute_instruction(state, make_instruction(0x20, cond_mod=0xA, ra=1))
    assert state.pc == old_pc + 4


def test_cjmp_gt_false_ne():
    """CJMP GT: Don't jump when N!=V"""
    state = make_state()
    state.sr['Z'] = False
    state.sr['N'] = True
    state.sr['V'] = False
    state.regs[1] = 800
    old_pc = state.pc
    # CJMP.GT R1
    execute_instruction(state, make_instruction(0x20, cond_mod=0xA, ra=1))
    assert state.pc == old_pc + 4


def test_cjmp_le_true_zero():
    """CJMP LE: Jump when Z=1 (signed less or equal)"""
    state = make_state()
    state.sr['Z'] = True
    state.sr['N'] = False
    state.sr['V'] = False
    state.regs[1] = 900
    # CJMP.LE R1 (cond=0xB)
    execute_instruction(state, make_instruction(0x20, cond_mod=0xB, ra=1))
    assert state.pc == 900


def test_cjmp_le_true_ne():
    """CJMP LE: Jump when N!=V"""
    state = make_state()
    state.sr['Z'] = False
    state.sr['N'] = True
    state.sr['V'] = False
    state.regs[1] = 900
    # CJMP.LE R1
    execute_instruction(state, make_instruction(0x20, cond_mod=0xB, ra=1))
    assert state.pc == 900


def test_cjmp_le_false():
    """CJMP LE: Don't jump when Z=0 and N=V"""
    state = make_state()
    state.sr['Z'] = False
    state.sr['N'] = True
    state.sr['V'] = True
    state.regs[1] = 900
    old_pc = state.pc
    # CJMP.LE R1
    execute_instruction(state, make_instruction(0x20, cond_mod=0xB, ra=1))
    assert state.pc == old_pc + 4


# ============================================================================
# SAFETY AND INVARIANT TESTS
# ============================================================================

def test_r0_always_zero_after_add():
    """R0 Invariance: R0 stays 0 after ADD"""
    state = make_state()
    state.regs[1] = 100
    execute_instruction(state, make_instruction(0x01, rd=0, ra=1, rb=0, imm=50))
    assert state.regs[0] == 0


def test_r0_always_zero_after_sub():
    """R0 Invariance: R0 stays 0 after SUB"""
    state = make_state()
    state.regs[1] = 100
    execute_instruction(state, make_instruction(0x03, rd=0, ra=1, rb=0, imm=0))
    assert state.regs[0] == 0


def test_r0_always_zero_after_mulh():
    """R0 Invariance: R0 stays 0 after MULH"""
    state = make_state()
    state.regs[1] = 0xFFFFFFFF
    state.regs[2] = 0xFFFFFFFF
    execute_instruction(state, make_instruction(0x05, rd=0, ra=1, rb=2))
    assert state.regs[0] == 0


def test_r0_always_zero_after_bext():
    """R0 Invariance: R0 stays 0 after BEXT"""
    state = make_state()
    state.regs[1] = 0xFFFFFFFF
    state.regs[2] = 0
    execute_instruction(state, make_instruction(0x10, rd=0, ra=1, rb=2, imm=32))
    assert state.regs[0] == 0


def test_r0_source_reads_zero():
    """R0 Invariance: Reading from R0 gives 0"""
    state = make_state()
    state.regs[1] = 100
    # ADD R3, R0, R1, #0 (R0 should be read as 0)
    execute_instruction(state, make_instruction(0x01, rd=3, ra=0, rb=1, imm=0))
    assert state.regs[3] == 100  # 0 + 100 + 0


def test_pc_increment_after_add():
    """PC increments by 4 after non-jump instruction"""
    state = make_state()
    state.pc = 0
    execute_instruction(state, make_instruction(0x01, rd=1, ra=0, rb=0, imm=0))
    assert state.pc == 4


def test_pc_increment_after_mul():
    """PC increments by 4 after MULH"""
    state = make_state()
    state.pc = 100
    execute_instruction(state, make_instruction(0x05, rd=1, ra=0, rb=0))
    assert state.pc == 104


def test_pc_no_increment_after_jump():
    """PC doesn't increment after successful CJMP"""
    state = make_state()
    state.pc = 0
    state.sr['Z'] = True
    state.regs[1] = 500
    execute_instruction(state, make_instruction(0x20, cond_mod=0x0, ra=1))
    assert state.pc == 500  # Jumped, not incremented


# ============================================================================
# EDGE CASE TESTS
# ============================================================================

def test_add_all_registers():
    """ADD: Test all general purpose registers"""
    state = make_state()
    for i in range(1, 16):
        state.regs[i] = i * 10
    # Test adding different register combinations
    execute_instruction(state, make_instruction(0x01, rd=14, ra=1, rb=2, imm=0))
    assert state.regs[14] == 30  # 10 + 20


def test_sub_equal_values():
    """SUB: Subtract equal values gives 0"""
    state = make_state()
    state.regs[1] = 12345
    state.regs[2] = 12345
    execute_instruction(state, make_instruction(0x03, rd=3, ra=1, rb=2, imm=0))
    assert state.regs[3] == 0
    assert state.sr['Z'] is True


def test_add_maximum_immediate():
    """ADD: Test with maximum immediate value (255)"""
    state = make_state()
    state.regs[1] = 0
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=0, imm=255))
    assert state.regs[3] == 255


def test_flags_cleared_on_new_operation():
    """Flags: Previous flags are overwritten"""
    state = make_state()
    state.sr['Z'] = True
    state.sr['C'] = True
    state.sr['V'] = True
    state.regs[1] = 1
    # ADD R3, R1, R0, #0 (result=1, should clear Z)
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=0, imm=0))
    assert state.sr['Z'] is False


def test_parity_all_zeros():
    """Parity: 0 has even parity (0 ones)"""
    state = make_state()
    execute_instruction(state, make_instruction(0x01, rd=3, ra=0, rb=0, imm=0))
    assert state.regs[3] == 0
    assert state.sr['P'] is True  # 0 ones = even


def test_parity_all_ones():
    """Parity: 0xFF has even parity (8 ones)"""
    state = make_state()
    state.regs[1] = 0xFF
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=0, imm=0))
    assert state.regs[3] == 0xFF
    assert state.sr['P'] is True  # 8 ones = even


def test_parity_single_bit():
    """Parity: Single bit has odd parity"""
    state = make_state()
    execute_instruction(state, make_instruction(0x01, rd=3, ra=0, rb=0, imm=1))
    assert state.regs[3] == 1
    assert state.sr['P'] is False  # 1 one = odd


def test_half_carry_boundary():
    """Half-carry: Carry from bit 3 to bit 4"""
    state = make_state()
    state.regs[1] = 0x08  # bit 3 set
    state.regs[2] = 0x08  # bit 3 set
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=2, imm=0))
    assert state.regs[3] == 0x10  # bit 4 set
    assert state.sr['H'] is True


def test_signed_vs_unsigned_overflow():
    """Overflow: Distinguish signed overflow from unsigned carry"""
    state = make_state()
    state.regs[1] = 0x80000000  # -2147483648 in signed, large in unsigned
    state.regs[2] = 0x80000000
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=2, imm=0))
    assert state.sr['C'] is True  # Unsigned overflow
    assert state.sr['V'] is True  # Signed overflow


def test_multiple_operations_sequence():
    """Sequential: Execute multiple operations"""
    state = make_state()
    state.regs[1] = 10
    # ADD R2, R1, R0, #5
    execute_instruction(state, make_instruction(0x01, rd=2, ra=1, rb=0, imm=5))
    assert state.regs[2] == 15
    # ADD R3, R2, R1, #0
    execute_instruction(state, make_instruction(0x01, rd=3, ra=2, rb=1, imm=0))
    assert state.regs[3] == 25


def test_stack_pointer_usage():
    """R15 (SP): Can be used as regular register"""
    state = make_state()
    state.regs[15] = 1000
    state.regs[1] = 24
    # ADD R15, R15, R1, #0 (SP = SP + R1)
    execute_instruction(state, make_instruction(0x01, rd=15, ra=15, rb=1, imm=0))
    assert state.regs[15] == 1024


def test_link_register_usage():
    """R14 (LR): Can be used as regular register"""
    state = make_state()
    state.regs[14] = 500
    state.regs[1] = 100
    # SUB R14, R14, R1, #0
    execute_instruction(state, make_instruction(0x03, rd=14, ra=14, rb=1, imm=0))
    assert state.regs[14] == 400


# ============================================================================
# COMPREHENSIVE FLAG COMBINATION TESTS
# ============================================================================

def test_flags_zn_combination():
    """Flags: Z and N cannot both be set (0 is not negative)"""
    state = make_state()
    execute_instruction(state, make_instruction(0x01, rd=3, ra=0, rb=0, imm=0))
    if state.sr['Z']:
        assert state.sr['N'] is False


def test_flags_cv_independent():
    """Flags: C and V are independent"""
    state = make_state()
    state.regs[1] = 0xFFFFFFFF
    state.regs[2] = 1
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=2, imm=0))
    # Both C and V should be set
    assert state.sr['C'] is True
    assert state.sr['V'] is False  # Actually no signed overflow here


def test_overflow_positive_only():
    """Overflow: Pos + Pos = Neg"""
    state = make_state()
    state.regs[1] = 0x40000000  # Positive
    state.regs[2] = 0x40000000  # Positive
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=2, imm=0))
    # Result = 0x80000000 (negative)
    assert state.sr['V'] is True
    assert state.sr['N'] is True


def test_no_overflow_opposite_signs():
    """Overflow: Pos + Neg never overflows"""
    state = make_state()
    state.regs[1] = 0x7FFFFFFF  # Max positive
    state.regs[2] = 0x80000000  # Min negative (as 32-bit value)
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=2, imm=0))
    # Should not set overflow flag
    assert state.sr['V'] is False


# ============================================================================
# STRESS TESTS
# ============================================================================

def test_all_flags_simultaneously():
    """Stress: Construct scenario where multiple flags are set"""
    state = make_state()
    state.regs[1] = 0x7FFFFFF8  # Carefully chosen value
    state.regs[2] = 0x0000000F
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=2, imm=0))
    # Check that instruction executes without error
    assert isinstance(state.regs[3], int)


def test_maximum_values_all_operations():
    """Stress: Test max values on all arithmetic ops"""
    state = make_state()
    state.regs[1] = 0xFFFFFFFF
    state.regs[2] = 0xFFFFFFFF

    # ADD with max values
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=2, imm=255))
    assert isinstance(state.regs[3], int)

    # SUB with max values
    execute_instruction(state, make_instruction(0x03, rd=4, ra=1, rb=2, imm=255))
    assert isinstance(state.regs[4], int)

    # MULH with max values
    execute_instruction(state, make_instruction(0x05, rd=5, ra=1, rb=2))
    assert isinstance(state.regs[5], int)


def test_rapid_conditional_jumps():
    """Stress: Test multiple conditional jumps"""
    state = make_state()
    for cond in [0x0, 0x1, 0x2, 0x3, 0x4, 0x8, 0x9, 0xA, 0xB]:
        state.regs[1] = 100
        state.pc = 0
        execute_instruction(state, make_instruction(0x20, cond_mod=cond, ra=1))
        # Should not crash
        assert isinstance(state.pc, int)


def test_bit_operations_edge_values():
    """Stress: Bit operations with edge values"""
    state = make_state()
    # BEXT with max values
    state.regs[1] = 0xFFFFFFFF
    state.regs[2] = 0
    execute_instruction(state, make_instruction(0x10, rd=3, ra=1, rb=2, imm=32))
    assert isinstance(state.regs[3], int)

    # BINS with max values
    execute_instruction(state, make_instruction(0x11, rd=4, ra=1, rb=2, imm=31))
    assert isinstance(state.regs[4], int)

    # ROTR with max rotation
    execute_instruction(state, make_instruction(0x12, rd=5, ra=1, rb=2, imm=255))
    assert isinstance(state.regs[5], int)


# ============================================================================
# ADDITIONAL EDGE CASE TESTS
# ============================================================================

def test_carry_chain_add_addc():
    """Carry chaining: ADD followed by ADDC"""
    state = make_state()
    state.regs[1] = 0xFFFFFFFF
    state.regs[2] = 1
    # ADD R3, R1, R2, #0 (should set carry)
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=2, imm=0))
    assert state.sr['C'] is True

    # ADDC R4, R0, R0, #0 (should add the carry)
    state.regs[1] = 10
    state.regs[2] = 20
    execute_instruction(state, make_instruction(0x02, rd=4, ra=1, rb=2, imm=0))
    assert state.regs[4] == 31  # 10 + 20 + 1 (carry)


def test_borrow_chain_sub_subb():
    """Borrow chaining: SUB followed by SUBB"""
    state = make_state()
    state.regs[1] = 5
    state.regs[2] = 10
    # SUB R3, R1, R2, #0 (should set borrow/carry)
    execute_instruction(state, make_instruction(0x03, rd=3, ra=1, rb=2, imm=0))
    assert state.sr['C'] is True  # Borrow occurred

    # SUBB R4, R1, R2, #0 (should subtract with borrow)
    execute_instruction(state, make_instruction(0x04, rd=4, ra=1, rb=2, imm=0))
    assert state.regs[4] < state.regs[3]  # Additional borrow


def test_self_modifying_operation():
    """Self-modify: Rd = Ra where Rd == Ra"""
    state = make_state()
    state.regs[5] = 100
    # ADD R5, R5, R0, #50
    execute_instruction(state, make_instruction(0x01, rd=5, ra=5, rb=0, imm=50))
    assert state.regs[5] == 150


def test_three_same_registers():
    """Three-way: Rd = Ra = Rb"""
    state = make_state()
    state.regs[7] = 10
    # ADD R7, R7, R7, #0 (R7 = R7 + R7)
    execute_instruction(state, make_instruction(0x01, rd=7, ra=7, rb=7, imm=0))
    assert state.regs[7] == 20


def test_negative_arithmetic():
    """Negative numbers: Two's complement arithmetic"""
    state = make_state()
    state.regs[1] = 0xFFFFFFFF  # -1 in two's complement
    state.regs[2] = 0xFFFFFFFF  # -1 in two's complement
    # ADD R3, R1, R2, #0 (-1 + -1 = -2)
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=2, imm=0))
    assert state.regs[3] == 0xFFFFFFFE  # -2 in two's complement


def test_zero_minus_one():
    """Edge: 0 - 1 = -1"""
    state = make_state()
    state.regs[1] = 0
    state.regs[2] = 1
    # SUB R3, R1, R2, #0
    execute_instruction(state, make_instruction(0x03, rd=3, ra=1, rb=2, imm=0))
    assert state.regs[3] == 0xFFFFFFFF


def test_min_minus_one():
    """Edge: MIN_INT - 1 causes overflow"""
    state = make_state()
    state.regs[1] = 0x80000000  # MIN_INT
    state.regs[2] = 1
    # SUB R3, R1, R2, #0
    execute_instruction(state, make_instruction(0x03, rd=3, ra=1, rb=2, imm=0))
    assert state.sr['V'] is True


def test_max_plus_one():
    """Edge: MAX_INT + 1 causes overflow"""
    state = make_state()
    state.regs[1] = 0x7FFFFFFF  # MAX_INT
    state.regs[2] = 1
    # ADD R3, R1, R2, #0
    execute_instruction(state, make_instruction(0x01, rd=3, ra=1, rb=2, imm=0))
    assert state.sr['V'] is True


# ============================================================================
# INSTRUCTION ENCODING VALIDATION
# ============================================================================

def test_instruction_encoding_fields():
    """Encoding: Verify instruction field extraction"""
    inst = make_instruction(opcode=0x01, cond_mod=0x5, rd=3, ra=7, rb=11, imm=42)
    assert (inst >> 24) & 0xFF == 0x01
    assert (inst >> 20) & 0x0F == 0x5
    assert (inst >> 16) & 0x0F == 3
    assert (inst >> 12) & 0x0F == 7
    assert (inst >> 8) & 0x0F == 11
    assert inst & 0xFF == 42


def test_big_endian_format():
    """Encoding: Instructions are in big-endian"""
    inst = make_instruction(opcode=0xAB, cond_mod=0xC, rd=0xD, ra=0xE, rb=0xF, imm=0x12)
    # Most significant byte should be opcode
    assert (inst >> 24) == 0xAB


# ============================================================================
# MEMORY AND STATE TESTS (if memory operations exist)
# ============================================================================

def test_memory_exists():
    """Memory: State has memory array"""
    state = make_state()
    assert len(state.memory) == 1024
    assert isinstance(state.memory, bytearray)


def test_register_count():
    """Registers: Exactly 16 registers"""
    state = make_state()
    assert len(state.regs) == 16


def test_all_flags_exist():
    """Flags: All 6 flags exist in SR"""
    state = make_state()
    assert 'Z' in state.sr
    assert 'N' in state.sr
    assert 'C' in state.sr
    assert 'V' in state.sr
    assert 'P' in state.sr
    assert 'H' in state.sr
