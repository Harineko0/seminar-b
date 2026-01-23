import pytest
from hypothesis import given, strategies as st, settings, HealthCheck

from parser import decode_module, validate_module, decode_and_validate, DecodeError, Limits

# Keep limits small for fast feedback; raise later if needed.
LIMITS = Limits(max_module_bytes=256)

@settings(
    max_examples=500,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(data=st.binary(min_size=0, max_size=LIMITS.max_module_bytes))
def test_decode_never_crashes_other_than_decodeerror(data: bytes) -> None:
    """
    Fuzz bytes: decoder may accept or reject, but should not crash with unexpected exceptions.
    """
    try:
        _m = decode_module(data, limits=LIMITS)
    except DecodeError:
        return  # expected for malformed inputs


@settings(max_examples=200)
@given(data=st.binary(min_size=0, max_size=LIMITS.max_module_bytes))
def test_decode_then_validate_is_total(data: bytes) -> None:
    """
    If decode succeeds, validation should always return a list (possibly empty),
    not crash with unexpected exceptions.
    """
    try:
        m = decode_module(data, limits=LIMITS)
    except DecodeError:
        return
    errs = validate_module(m)
    assert isinstance(errs, list)


# ===== Helper Functions for Test Generation =====

def encode_u32(n: int) -> bytes:
    """Encode unsigned 32-bit as LEB128."""
    result = []
    while True:
        byte = n & 0x7F
        n >>= 7
        if n != 0:
            result.append(byte | 0x80)
        else:
            result.append(byte)
            break
    return bytes(result)


def encode_s32(n: int) -> bytes:
    """Encode signed 32-bit as LEB128."""
    result = []
    while True:
        byte = n & 0x7F
        n >>= 7
        if (n == 0 and (byte & 0x40) == 0) or (n == -1 and (byte & 0x40) != 0):
            result.append(byte)
            break
        else:
            result.append(byte | 0x80)
    return bytes(result)


def make_wasm(*sections):
    """Construct a WASM module with magic + version + sections."""
    return b"\x00asm\x01\x00\x00\x00" + b"".join(sections)


def make_section(section_id: int, payload: bytes) -> bytes:
    """Construct a section with id and payload."""
    size = encode_u32(len(payload))
    return bytes([section_id]) + size + payload


# ===== Property tests for specific properties =====

@settings(max_examples=100)
@given(st.binary(min_size=8, max_size=100))
def test_invalid_magic_always_fails(data: bytes) -> None:
    """Property: modules with invalid magic should always fail."""
    # Corrupt the magic
    if len(data) >= 8:
        corrupted = b"\xFF\xFF\xFF\xFF" + data[4:]
        try:
            decode_module(corrupted, limits=LIMITS)
            assert False, "Should have raised DecodeError"
        except DecodeError:
            pass  # Expected


@settings(max_examples=100)
@given(st.binary(min_size=8, max_size=100))
def test_invalid_version_always_fails(data: bytes) -> None:
    """Property: modules with invalid version should always fail."""
    # Valid magic but invalid version
    if len(data) >= 8:
        corrupted = b"\x00asm\x02\x00\x00\x00" + data[8:]
        try:
            decode_module(corrupted, limits=LIMITS)
            assert False, "Should have raised DecodeError"
        except DecodeError:
            pass  # Expected


def test_minimal_module_always_valid() -> None:
    """Property: minimal module (just magic + version) should always decode."""
    wasm = b"\x00asm\x01\x00\x00\x00"
    module = decode_module(wasm, limits=LIMITS)
    assert module is not None
    assert len(module.types) == 0
    assert len(module.functions) == 0


@settings(max_examples=100)
@given(st.integers(min_value=0, max_value=2**32-1))
def test_u32_encoding_length(value: int) -> None:
    """Property: u32 LEB128 encoding should be at most 5 bytes."""
    encoded = encode_u32(value)
    assert len(encoded) <= 5
    assert len(encoded) >= 1


@settings(max_examples=100)
@given(st.integers(min_value=-2147483648, max_value=2147483647))
def test_s32_encoding_length(value: int) -> None:
    """Property: s32 LEB128 encoding should be at most 5 bytes."""
    encoded = encode_s32(value)
    assert len(encoded) <= 5
    assert len(encoded) >= 1


def test_empty_type_section() -> None:
    """Property: module with empty type section should decode."""
    type_section = make_section(1, encode_u32(0))
    wasm = make_wasm(type_section)
    module = decode_module(wasm, limits=LIMITS)
    assert len(module.types) == 0


def test_section_ordering_violation() -> None:
    """Property: out-of-order sections should fail."""
    # Export section (7) before function section (3) should fail
    export_section = make_section(7, encode_u32(0))
    func_section = make_section(3, encode_u32(0))

    wasm = make_wasm(export_section, func_section)
    try:
        decode_module(wasm, limits=LIMITS)
        assert False, "Should have raised DecodeError for section ordering"
    except DecodeError:
        pass  # Expected


@settings(max_examples=100)
@given(size=st.integers(min_value=1001, max_value=10000))
def test_module_size_limit_enforced(size: int) -> None:
    """Property: modules exceeding size limit should fail."""
    data = b"\x00asm\x01\x00\x00\x00" + b"\x00" * (size - 8)
    small_limits = Limits(max_module_bytes=1000)
    try:
        decode_module(data, limits=small_limits)
        assert False, "Should have raised DecodeError for size limit"
    except DecodeError:
        pass  # Expected


@settings(max_examples=50)
@given(st.integers(min_value=1, max_value=10))
def test_valid_type_section_decodes(num_types: int) -> None:
    """Property: type section with valid function types should decode."""
    # Create simple function types: [] -> []
    functype = b"\x60" + encode_u32(0) + encode_u32(0)
    types = [functype] * num_types
    payload = encode_u32(num_types) + b"".join(types)
    type_section = make_section(1, payload)

    wasm = make_wasm(type_section)
    module = decode_module(wasm, limits=LIMITS)
    assert len(module.types) == num_types


def test_function_code_count_must_match() -> None:
    """Property: function count != code count should produce validation error."""
    # Type: [] -> []
    functype = b"\x60" + encode_u32(0) + encode_u32(0)
    type_section = make_section(1, encode_u32(1) + functype)

    # 2 functions
    func_section = make_section(3, encode_u32(2) + encode_u32(0) + encode_u32(0))

    # Only 1 code entry (mismatch)
    func_body = encode_u32(0) + b"\x0b"  # empty locals, end
    code_section = make_section(10, encode_u32(1) + encode_u32(len(func_body)) + func_body)

    wasm = make_wasm(type_section, func_section, code_section)
    module = decode_module(wasm, limits=LIMITS)
    errors = validate_module(module)
    assert len(errors) > 0
    assert any("func" in e.message.lower() and "code" in e.message.lower() for e in errors)

