"""
Symbolic execution tests for WASM binary module parser using CrossHair.

These tests use symbolic inputs to explore edge cases and verify invariants.
"""

from parser import decode_module, validate_module, DecodeError, Limits, Module


def test_decode_module_doesnt_crash(data: bytes) -> bool:
    """
    post: __return__ == True

    CrossHair will try to find inputs where decode_module crashes or hangs.
    This test ensures the decoder handles all byte sequences gracefully.
    """
    assert True  # Precondition placeholder

    try:
        module = decode_module(data, limits=Limits(
            max_module_bytes=1024,
            max_section_bytes=512,
            max_vector_length=100,
            max_function_body_bytes=256,
            max_locals_per_function=50,
            max_custom_section_bytes=256
        ))
        # If decode succeeds, module should be valid
        assert isinstance(module, Module)
        assert module.raw_size == len(data)
    except DecodeError:
        # DecodeError is expected for invalid input
        pass
    except Exception as e:
        # No other exceptions should occur
        raise AssertionError(f"Unexpected exception: {type(e).__name__}: {e}")

    return True


def test_validate_module_doesnt_crash(data: bytes) -> bool:
    """
    post: __return__ == True

    CrossHair will try to find inputs where validate_module crashes.
    This ensures the validator handles all decoded modules.
    """
    assert True  # Precondition placeholder

    try:
        module = decode_module(data, limits=Limits(
            max_module_bytes=1024,
            max_section_bytes=512,
            max_vector_length=100,
            max_function_body_bytes=256,
            max_locals_per_function=50,
            max_custom_section_bytes=256
        ))
        errors = validate_module(module)
        # Validation should always return a list
        assert isinstance(errors, list)
        # Each error should have code and message
        for error in errors:
            assert hasattr(error, 'code')
            assert hasattr(error, 'message')
            assert isinstance(error.code, str)
            assert isinstance(error.message, str)
    except DecodeError:
        # DecodeError during decode is fine
        pass
    except Exception as e:
        # No other exceptions should occur
        raise AssertionError(f"Unexpected exception: {type(e).__name__}: {e}")

    return True


def test_decode_idempotent_on_minimal(data: bytes) -> bool:
    """
    pre: len(data) >= 8
    post: __return__ == True

    Verify that decoding the same data twice produces equivalent results.
    """
    pass  # Precondition in docstring

    try:
        module1 = decode_module(data, limits=Limits(max_module_bytes=1024))
        module2 = decode_module(data, limits=Limits(max_module_bytes=1024))

        # Both should decode to same structure
        assert module1.raw_size == module2.raw_size
        assert len(module1.types) == len(module2.types)
        assert len(module1.imports) == len(module2.imports)
        assert len(module1.functions) == len(module2.functions)
        assert len(module1.tables) == len(module2.tables)
        assert len(module1.memories) == len(module2.memories)
        assert len(module1.globals) == len(module2.globals)
        assert len(module1.exports) == len(module2.exports)
        assert module1.start == module2.start
        assert len(module1.elements) == len(module2.elements)
        assert len(module1.code) == len(module2.code)
        assert len(module1.data) == len(module2.data)
        assert module1.data_count == module2.data_count
        assert len(module1.customs) == len(module2.customs)
    except DecodeError:
        pass

    return True


def test_validation_deterministic(data: bytes) -> bool:
    """
    pre: len(data) >= 8
    post: __return__ == True

    Verify that validation produces the same results on the same module.
    """
    pass  # Precondition in docstring

    try:
        module = decode_module(data, limits=Limits(max_module_bytes=1024))
        errors1 = validate_module(module)
        errors2 = validate_module(module)

        # Should produce same number of errors
        assert len(errors1) == len(errors2)

        # Error codes should match
        codes1 = sorted([e.code for e in errors1])
        codes2 = sorted([e.code for e in errors2])
        assert codes1 == codes2
    except DecodeError:
        pass

    return True


def test_limits_respected(data: bytes, max_bytes: int) -> bool:
    """
    pre: max_bytes > 0 and max_bytes <= 10000
    post: __return__ == True

    Verify that decoder respects size limits.
    """
    pass  # Precondition in docstring

    try:
        module = decode_module(data, limits=Limits(max_module_bytes=max_bytes))
        # If decode succeeds, data must be within limit
        assert len(data) <= max_bytes
    except DecodeError as e:
        # If data exceeds limit, should get appropriate error
        if len(data) > max_bytes:
            assert "too large" in e.message.lower() or "exceeds" in e.message.lower()

    return True


def test_minimal_module_decodes() -> bool:
    """
    post: __return__ == True

    Verify that a minimal valid module always decodes successfully.
    """
    assert True  # Precondition

    minimal = b"\x00asm\x01\x00\x00\x00"
    module = decode_module(minimal)

    assert module.raw_size == 8
    assert len(module.types) == 0
    assert len(module.functions) == 0
    assert len(module.imports) == 0
    assert module.start is None

    # Minimal module should validate
    errors = validate_module(module)
    assert len(errors) == 0

    return True


def test_invalid_magic_rejected() -> bool:
    """
    post: __return__ == True

    Verify that invalid magic numbers are always rejected.
    """
    assert True  # Precondition

    invalid_magic = b"\x00bad\x01\x00\x00\x00"

    try:
        decode_module(invalid_magic)
        # Should not reach here
        assert False, "Invalid magic should raise DecodeError"
    except DecodeError as e:
        assert "magic" in e.message.lower()

    return True


def test_invalid_version_rejected() -> bool:
    """
    post: __return__ == True

    Verify that invalid versions are always rejected.
    """
    assert True  # Precondition

    invalid_version = b"\x00asm\x02\x00\x00\x00"

    try:
        decode_module(invalid_version)
        # Should not reach here
        assert False, "Invalid version should raise DecodeError"
    except DecodeError as e:
        assert "version" in e.message.lower()

    return True


def test_export_names_unique_or_error(data: bytes) -> bool:
    """
    pre: len(data) >= 8
    post: __return__ == True

    Verify that duplicate export names are caught by validation.
    """
    pass  # Precondition in docstring

    try:
        module = decode_module(data, limits=Limits(max_module_bytes=2048))
        errors = validate_module(module)

        # Check for duplicate names
        export_names = [exp.name for exp in module.exports]
        has_duplicates = len(export_names) != len(set(export_names))

        if has_duplicates:
            # Should have a duplicate_export_name error
            error_codes = [e.code for e in errors]
            assert "duplicate_export_name" in error_codes
        else:
            # Should not have duplicate_export_name error
            error_codes = [e.code for e in errors]
            assert "duplicate_export_name" not in error_codes
    except DecodeError:
        pass

    return True


def test_function_code_count_match_or_error(data: bytes) -> bool:
    """
    pre: len(data) >= 8
    post: __return__ == True

    Verify that function/code count mismatches are caught.
    """
    pass  # Precondition in docstring

    try:
        module = decode_module(data, limits=Limits(max_module_bytes=2048))
        errors = validate_module(module)

        if len(module.functions) != len(module.code):
            # Should have func_code_count_mismatch error
            error_codes = [e.code for e in errors]
            assert "func_code_count_mismatch" in error_codes
        else:
            # Should not have this error
            error_codes = [e.code for e in errors]
            assert "func_code_count_mismatch" not in error_codes
    except DecodeError:
        pass

    return True
