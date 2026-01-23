import pytest
from hypothesis import given, strategies as st, settings, HealthCheck, assume

from parser import (
    decode_module, validate_module, decode_and_validate,
    DecodeError, Limits, Module, ValType
)

# Keep limits small for fast feedback; raise later if needed.
LIMITS = Limits(max_module_bytes=256)

# WASM magic and version
WASM_MAGIC = b'\x00asm'
WASM_VERSION = b'\x01\x00\x00\x00'


def encode_u32_leb128(value: int) -> bytes:
    """Encode u32 as unsigned LEB128."""
    result = []
    while True:
        byte = value & 0x7F
        value >>= 7
        if value != 0:
            result.append(byte | 0x80)
        else:
            result.append(byte)
            break
    return bytes(result)


def encode_s32_leb128(value: int) -> bytes:
    """Encode s32 as signed LEB128."""
    result = []
    more = True
    while more:
        byte = value & 0x7F
        value >>= 7

        # Sign extend
        if (value == 0 and (byte & 0x40) == 0) or (value == -1 and (byte & 0x40) != 0):
            more = False
        else:
            byte |= 0x80

        result.append(byte)

    return bytes(result)


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


@settings(max_examples=100)
@given(data=st.binary(min_size=0, max_size=LIMITS.max_module_bytes))
def test_minimal_valid_module_decodes(data: bytes) -> None:
    """Minimal valid module (just magic + version) should decode."""
    minimal = WASM_MAGIC + WASM_VERSION
    module = decode_module(minimal, limits=LIMITS)
    assert module.raw_size == 8
    assert len(module.types) == 0


@settings(max_examples=100)
@given(
    num_types=st.integers(min_value=1, max_value=5),
    num_params=st.lists(st.integers(min_value=0, max_value=3), min_size=1, max_size=5),
    num_results=st.lists(st.integers(min_value=0, max_value=2), min_size=1, max_size=5),
)
def test_type_section_roundtrip(num_types: int, num_params: list, num_results: list) -> None:
    """Generate valid type sections and ensure they decode correctly."""
    # Build type section
    type_entries = []

    for i in range(num_types):
        params_count = num_params[i % len(num_params)]
        results_count = num_results[i % len(num_results)]

        # functype = 0x60 + params vec + results vec
        entry = b'\x60'
        entry += encode_u32_leb128(params_count)
        entry += bytes([0x7F] * params_count)  # all i32
        entry += encode_u32_leb128(results_count)
        entry += bytes([0x7F] * results_count)  # all i32

        type_entries.append(entry)

    type_payload = encode_u32_leb128(len(type_entries)) + b''.join(type_entries)

    # Build module
    module_bytes = WASM_MAGIC + WASM_VERSION
    module_bytes += b'\x01'  # Type section id
    module_bytes += encode_u32_leb128(len(type_payload))
    module_bytes += type_payload

    if len(module_bytes) > LIMITS.max_module_bytes:
        return

    module = decode_module(module_bytes, limits=LIMITS)
    assert len(module.types) == num_types


@settings(max_examples=100)
@given(
    immediate=st.integers(min_value=-2147483648, max_value=2147483647)
)
def test_i32_const_instruction_roundtrip(immediate: int) -> None:
    """Test that i32.const instructions decode correctly."""
    # Build a minimal function with i32.const
    # Type section: [] -> []
    type_payload = encode_u32_leb128(1) + b'\x60\x00\x00'

    # Function section: 1 function with type 0
    func_payload = encode_u32_leb128(1) + encode_u32_leb128(0)

    # Code section: function body with i32.const + end
    code_body = encode_u32_leb128(0)  # no locals
    code_body += b'\x41'  # i32.const
    code_body += encode_s32_leb128(immediate)
    code_body += b'\x0B'  # end

    code_payload = encode_u32_leb128(1)  # 1 function
    code_payload += encode_u32_leb128(len(code_body))
    code_payload += code_body

    # Build module
    module_bytes = WASM_MAGIC + WASM_VERSION
    module_bytes += b'\x01' + encode_u32_leb128(len(type_payload)) + type_payload
    module_bytes += b'\x03' + encode_u32_leb128(len(func_payload)) + func_payload
    module_bytes += b'\x0A' + encode_u32_leb128(len(code_payload)) + code_payload

    if len(module_bytes) > LIMITS.max_module_bytes:
        return

    module = decode_module(module_bytes, limits=LIMITS)
    errors = validate_module(module)

    assert len(errors) == 0
    assert len(module.code) == 1
    assert len(module.code[0].expr) == 2  # i32.const + end
    assert module.code[0].expr[0].opcode == 0x41
    assert module.code[0].expr[0].immediate == immediate


@settings(max_examples=50)
@given(
    export_name=st.binary(min_size=1, max_size=10),
)
def test_valid_export_section(export_name: bytes) -> None:
    """Test export section with valid function export."""
    # Type section: [] -> []
    type_payload = encode_u32_leb128(1) + b'\x60\x00\x00'

    # Function section: 1 function
    func_payload = encode_u32_leb128(1) + encode_u32_leb128(0)

    # Export section: export function 0
    export_entry = encode_u32_leb128(len(export_name)) + export_name
    export_entry += b'\x00'  # kind = func
    export_entry += encode_u32_leb128(0)  # index = 0

    export_payload = encode_u32_leb128(1) + export_entry

    # Code section
    code_body = encode_u32_leb128(0) + b'\x0B'  # no locals, just end
    code_payload = encode_u32_leb128(1) + encode_u32_leb128(len(code_body)) + code_body

    # Build module
    module_bytes = WASM_MAGIC + WASM_VERSION
    module_bytes += b'\x01' + encode_u32_leb128(len(type_payload)) + type_payload
    module_bytes += b'\x03' + encode_u32_leb128(len(func_payload)) + func_payload
    module_bytes += b'\x07' + encode_u32_leb128(len(export_payload)) + export_payload
    module_bytes += b'\x0A' + encode_u32_leb128(len(code_payload)) + code_payload

    if len(module_bytes) > LIMITS.max_module_bytes:
        return

    module = decode_module(module_bytes, limits=LIMITS)
    errors = validate_module(module)

    assert len(errors) == 0
    assert len(module.exports) == 1
    assert module.exports[0].name == export_name


def test_duplicate_export_names_detected() -> None:
    """Test that duplicate export names are detected."""
    export_name = b'test'

    # Type section: [] -> []
    type_payload = encode_u32_leb128(1) + b'\x60\x00\x00'

    # Function section: 2 functions
    func_payload = encode_u32_leb128(2)
    func_payload += encode_u32_leb128(0) + encode_u32_leb128(0)

    # Export section: export both with same name
    export_entry1 = encode_u32_leb128(len(export_name)) + export_name
    export_entry1 += b'\x00' + encode_u32_leb128(0)

    export_entry2 = encode_u32_leb128(len(export_name)) + export_name
    export_entry2 += b'\x00' + encode_u32_leb128(1)

    export_payload = encode_u32_leb128(2) + export_entry1 + export_entry2

    # Code section
    code_body = encode_u32_leb128(0) + b'\x0B'
    code_payload = encode_u32_leb128(2)
    code_payload += encode_u32_leb128(len(code_body)) + code_body
    code_payload += encode_u32_leb128(len(code_body)) + code_body

    # Build module
    module_bytes = WASM_MAGIC + WASM_VERSION
    module_bytes += b'\x01' + encode_u32_leb128(len(type_payload)) + type_payload
    module_bytes += b'\x03' + encode_u32_leb128(len(func_payload)) + func_payload
    module_bytes += b'\x07' + encode_u32_leb128(len(export_payload)) + export_payload
    module_bytes += b'\x0A' + encode_u32_leb128(len(code_payload)) + code_payload

    module = decode_module(module_bytes, limits=LIMITS)
    errors = validate_module(module)

    # Should have duplicate export name error
    assert any(e.code == "duplicate_export_name" for e in errors)


def test_section_order_violation_detected() -> None:
    """Test that out-of-order sections are rejected."""
    # Build module with Export section before Function section (wrong order)

    # Type section
    type_payload = encode_u32_leb128(1) + b'\x60\x00\x00'

    # Export section (should come after function section)
    export_payload = encode_u32_leb128(0)  # empty

    # Function section (should come before export section)
    func_payload = encode_u32_leb128(0)  # empty

    module_bytes = WASM_MAGIC + WASM_VERSION
    module_bytes += b'\x01' + encode_u32_leb128(len(type_payload)) + type_payload
    module_bytes += b'\x07' + encode_u32_leb128(len(export_payload)) + export_payload  # Export (7)
    module_bytes += b'\x03' + encode_u32_leb128(len(func_payload)) + func_payload     # Function (3)

    # Should raise DecodeError for section order
    with pytest.raises(DecodeError) as exc:
        decode_module(module_bytes, limits=LIMITS)

    assert exc.value.code == "section_order"


@settings(max_examples=50)
@given(
    local_idx=st.integers(min_value=0, max_value=5),
)
def test_local_index_validation(local_idx: int) -> None:
    """Test that out-of-range local indices are detected."""
    # Type section: [] -> []
    type_payload = encode_u32_leb128(1) + b'\x60\x00\x00'

    # Function section
    func_payload = encode_u32_leb128(1) + encode_u32_leb128(0)

    # Code section with local.get
    code_body = encode_u32_leb128(1)  # 1 local decl
    code_body += encode_u32_leb128(2)  # count = 2 locals
    code_body += b'\x7F'  # i32
    code_body += b'\x20'  # local.get
    code_body += encode_u32_leb128(local_idx)
    code_body += b'\x0B'  # end

    code_payload = encode_u32_leb128(1) + encode_u32_leb128(len(code_body)) + code_body

    # Build module
    module_bytes = WASM_MAGIC + WASM_VERSION
    module_bytes += b'\x01' + encode_u32_leb128(len(type_payload)) + type_payload
    module_bytes += b'\x03' + encode_u32_leb128(len(func_payload)) + func_payload
    module_bytes += b'\x0A' + encode_u32_leb128(len(code_payload)) + code_payload

    if len(module_bytes) > LIMITS.max_module_bytes:
        return

    module = decode_module(module_bytes, limits=LIMITS)
    errors = validate_module(module)

    # Total locals = 0 params + 2 locals = 2
    # So valid indices are 0, 1
    if local_idx >= 2:
        assert any(e.code == "local_index_out_of_range" for e in errors)
    else:
        assert len(errors) == 0


def test_limits_min_gt_max_detected() -> None:
    """Test that min > max in limits is detected."""
    # Memory section with min > max
    mem_payload = encode_u32_leb128(1)  # 1 memory
    mem_payload += b'\x01'  # flags = has max
    mem_payload += encode_u32_leb128(10)  # min = 10
    mem_payload += encode_u32_leb128(5)   # max = 5 (invalid!)

    module_bytes = WASM_MAGIC + WASM_VERSION
    module_bytes += b'\x05' + encode_u32_leb128(len(mem_payload)) + mem_payload

    module = decode_module(module_bytes, limits=LIMITS)
    errors = validate_module(module)

    assert any(e.code == "limits_min_gt_max" for e in errors)


def test_bad_magic_rejected() -> None:
    """Test that invalid magic is rejected."""
    bad_magic = b'\x00BAD' + WASM_VERSION

    with pytest.raises(DecodeError) as exc:
        decode_module(bad_magic, limits=LIMITS)

    assert exc.value.code == "bad_magic"


def test_bad_version_rejected() -> None:
    """Test that invalid version is rejected."""
    bad_version = WASM_MAGIC + b'\x02\x00\x00\x00'

    with pytest.raises(DecodeError) as exc:
        decode_module(bad_version, limits=LIMITS)

    assert exc.value.code == "bad_version"


def test_unsupported_opcode_rejected() -> None:
    """Test that unsupported opcodes are rejected."""
    # Type section
    type_payload = encode_u32_leb128(1) + b'\x60\x00\x00'

    # Function section
    func_payload = encode_u32_leb128(1) + encode_u32_leb128(0)

    # Code section with unsupported opcode 0x42 (i64.const)
    code_body = encode_u32_leb128(0)  # no locals
    code_body += b'\x42'  # i64.const (unsupported? or is it supported?)
    code_body += encode_s32_leb128(42)
    code_body += b'\x0B'

    code_payload = encode_u32_leb128(1) + encode_u32_leb128(len(code_body)) + code_body

    module_bytes = WASM_MAGIC + WASM_VERSION
    module_bytes += b'\x01' + encode_u32_leb128(len(type_payload)) + type_payload
    module_bytes += b'\x03' + encode_u32_leb128(len(func_payload)) + func_payload
    module_bytes += b'\x0A' + encode_u32_leb128(len(code_payload)) + code_payload

    with pytest.raises(DecodeError) as exc:
        decode_module(module_bytes, limits=LIMITS)

    assert exc.value.code == "unsupported_opcode"

