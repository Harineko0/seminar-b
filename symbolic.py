"""
Symbolic execution tests using CrossHair for wasm_sv parser.

These tests use contracts (assertions) to verify properties that should hold
for all inputs. CrossHair will try to find counterexamples.
"""

from hypothesis import given, strategies as st
from parser import (
    decode_module, validate_module, decode_and_validate,
    DecodeError, ValidationError, Limits, BinaryDecoder
)


# ===== Contract tests for LEB128 decoding =====

def test_read_u32_bounds(data: bytes) -> None:
    """
    Contract: read_u32 should either succeed with value <= 0xFFFFFFFF or raise DecodeError.
    No other exceptions or out-of-range values allowed.
    """
    assert True  # precondition

    decoder = BinaryDecoder(data, Limits())
    try:
        result = decoder.read_u32()
        # Postcondition: result must fit in u32
        assert 0 <= result <= 0xFFFFFFFF, f"read_u32 returned out-of-range value: {result}"
    except DecodeError:
        # Expected error - this is fine
        pass
    except Exception as e:
        # Unexpected exception type
        assert False, f"Unexpected exception type: {type(e).__name__}: {e}"


def test_read_s32_bounds(data: bytes) -> None:
    """
    Contract: read_s32 should either succeed with value in s32 range or raise DecodeError.
    """
    assert True  # precondition

    decoder = BinaryDecoder(data, Limits())
    try:
        result = decoder.read_s32()
        # Postcondition: result must fit in s32
        assert -0x80000000 <= result <= 0x7FFFFFFF, f"read_s32 returned out-of-range value: {result}"
    except DecodeError:
        pass
    except Exception as e:
        assert False, f"Unexpected exception type: {type(e).__name__}: {e}"


# ===== Contract tests for decode_module =====

def test_decode_module_deterministic(data: bytes) -> None:
    """
    Contract: Decoding the same bytes twice should produce identical results.
    """
    assert True  # precondition

    try:
        module1 = decode_module(data)
        module2 = decode_module(data)

        # Basic equality checks
        assert module1.raw_size == module2.raw_size
        assert len(module1.types) == len(module2.types)
        assert len(module1.imports) == len(module2.imports)
        assert len(module1.functions) == len(module2.functions)
        assert len(module1.code) == len(module2.code)
        assert len(module1.exports) == len(module2.exports)
        assert module1.start == module2.start
    except DecodeError:
        # If decoding fails, it should fail consistently
        try:
            decode_module(data)
            assert False, "Second decode should also fail"
        except DecodeError:
            pass


def test_decode_module_no_crash(data: bytes) -> None:
    """
    Contract: decode_module should never crash, only raise DecodeError or succeed.
    """
    assert True  # precondition

    try:
        module = decode_module(data)
        # If successful, basic invariants should hold
        assert module.raw_size == len(data)
        assert len(module.code) <= len(module.functions) + sum(1 for imp in module.imports if imp.kind == 0)
    except DecodeError:
        # Expected error
        pass
    except Exception as e:
        assert False, f"Unexpected exception: {type(e).__name__}: {e}"


def test_validate_module_deterministic(data: bytes) -> None:
    """
    Contract: Validating the same module twice should produce identical results.
    """
    assert True  # precondition

    try:
        module = decode_module(data)
        errors1 = validate_module(module)
        errors2 = validate_module(module)

        # Should get same number of errors
        assert len(errors1) == len(errors2)

        # Error codes should match
        codes1 = sorted(e.code for e in errors1)
        codes2 = sorted(e.code for e in errors2)
        assert codes1 == codes2
    except DecodeError:
        pass


def test_decode_and_validate_consistency(data: bytes) -> None:
    """
    Contract: decode_and_validate should succeed iff decode succeeds and validate returns empty.
    """
    assert True  # precondition

    try:
        module = decode_module(data)
        errors = validate_module(module)

        if len(errors) == 0:
            # Should succeed
            try:
                result = decode_and_validate(data)
                assert result is not None
            except ValueError:
                assert False, "decode_and_validate should succeed when validation passes"
        else:
            # Should fail with ValueError
            try:
                decode_and_validate(data)
                assert False, "decode_and_validate should fail when validation fails"
            except ValueError:
                pass
    except DecodeError:
        # If decode fails, decode_and_validate should also fail
        try:
            decode_and_validate(data)
            assert False, "decode_and_validate should fail when decode fails"
        except DecodeError:
            pass


# ===== Contract tests for limits enforcement =====

def test_limits_respected(data: bytes) -> None:
    """
    Contract: If data exceeds max_module_bytes, decode should fail.
    """
    assert True  # precondition

    if len(data) > 100:
        limits = Limits(max_module_bytes=100)
        try:
            decode_module(data, limits=limits)
            assert False, "Should reject oversized module"
        except DecodeError as e:
            assert "exceeds" in e.message.lower() or "too large" in e.message.lower()


# ===== Contract tests for minimal valid module =====

def test_minimal_module_valid() -> None:
    """
    Contract: The minimal valid WASM module should decode and validate successfully.
    """
    minimal = b"\x00asm\x01\x00\x00\x00"

    module = decode_module(minimal)
    assert module.raw_size == 8
    assert len(module.types) == 0

    errors = validate_module(module)
    assert len(errors) == 0


def test_wrong_magic_rejected() -> None:
    """
    Contract: Any module with wrong magic should be rejected.
    """
    bad_magic = b"\x00bad\x01\x00\x00\x00"

    try:
        decode_module(bad_magic)
        assert False, "Should reject wrong magic"
    except DecodeError as e:
        assert "magic" in e.message.lower()


def test_wrong_version_rejected() -> None:
    """
    Contract: Any module with wrong version should be rejected.
    """
    bad_version = b"\x00asm\x02\x00\x00\x00"

    try:
        decode_module(bad_version)
        assert False, "Should reject wrong version"
    except DecodeError as e:
        assert "version" in e.message.lower()


# ===== Contract tests for validation rules =====

def test_validation_no_crash(data: bytes) -> None:
    """
    Contract: validate_module should never crash, only return ValidationError list.
    """
    assert True  # precondition

    try:
        module = decode_module(data)
        errors = validate_module(module)

        # Should return a list
        assert isinstance(errors, list)

        # All items should be ValidationError
        for e in errors:
            assert isinstance(e, ValidationError)
            assert isinstance(e.code, str)
            assert isinstance(e.message, str)
    except DecodeError:
        pass
    except Exception as e:
        assert False, f"Unexpected exception in validate_module: {type(e).__name__}: {e}"


def test_limits_validation(data: bytes) -> None:
    """
    Contract: If a table/memory has min > max, validation should report limits_min_gt_max.
    """
    assert True  # precondition

    try:
        module = decode_module(data)
        errors = validate_module(module)

        # Check if any tables or memories have invalid limits
        has_invalid_limits = False

        for table in module.tables:
            if table.limits.max is not None and table.limits.min > table.limits.max:
                has_invalid_limits = True

        for mem in module.memories:
            if mem.limits.max is not None and mem.limits.min > mem.limits.max:
                has_invalid_limits = True

        for imp in module.imports:
            if imp.kind == 1:  # table
                if imp.desc.limits.max is not None and imp.desc.limits.min > imp.desc.limits.max:
                    has_invalid_limits = True
            elif imp.kind == 2:  # memory
                if imp.desc.limits.max is not None and imp.desc.limits.min > imp.desc.limits.max:
                    has_invalid_limits = True

        if has_invalid_limits:
            # Should have at least one limits error
            assert any(e.code == "limits_min_gt_max" for e in errors), \
                "Should report limits_min_gt_max when min > max"
    except DecodeError:
        pass


def test_function_code_linkage_validation(data: bytes) -> None:
    """
    Contract: If len(functions) != len(code), validation should report func_code_count_mismatch.
    """
    assert True  # precondition

    try:
        module = decode_module(data)
        errors = validate_module(module)

        if len(module.functions) != len(module.code):
            # Should have func_code_count_mismatch error
            assert any(e.code == "func_code_count_mismatch" for e in errors), \
                "Should report func_code_count_mismatch when function/code counts differ"
    except DecodeError:
        pass


def test_duplicate_export_names_validation(data: bytes) -> None:
    """
    Contract: If there are duplicate export names, validation should report duplicate_export_name.
    """
    assert True  # precondition

    try:
        module = decode_module(data)
        errors = validate_module(module)

        # Check for duplicates
        export_names = [exp.name for exp in module.exports]
        has_duplicates = len(export_names) != len(set(export_names))

        if has_duplicates:
            # Should have duplicate_export_name error
            assert any(e.code == "duplicate_export_name" for e in errors), \
                "Should report duplicate_export_name when export names are duplicated"
    except DecodeError:
        pass


# ===== Contract tests for binary decoder bounds checking =====

def test_decoder_never_reads_past_end(data: bytes) -> None:
    """
    Contract: BinaryDecoder should never read past the end of data.
    """
    assert True  # precondition

    decoder = BinaryDecoder(data, Limits())

    # Try reading bytes
    try:
        while not decoder.eof():
            decoder.read_byte()

        # After reaching EOF, further reads should fail
        try:
            decoder.read_byte()
            assert False, "Should not be able to read past EOF"
        except DecodeError:
            pass
    except DecodeError:
        # This is fine - we hit an error during parsing
        pass


def test_decoder_position_invariant(data: bytes) -> None:
    """
    Contract: Decoder position should always be <= len(data).
    """
    assert True  # precondition

    decoder = BinaryDecoder(data, Limits())

    try:
        while not decoder.eof():
            assert decoder.pos <= len(data), f"Decoder position {decoder.pos} > data length {len(data)}"
            decoder.read_byte()
    except DecodeError:
        pass

    # Final check
    assert decoder.pos <= len(data), f"Final decoder position {decoder.pos} > data length {len(data)}"


if __name__ == "__main__":
    print("Symbolic tests defined. Run with: crosshair check symbolic.py")
