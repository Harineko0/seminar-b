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


@settings(max_examples=100)
@given(data=st.binary(min_size=0, max_size=LIMITS.max_module_bytes))
def test_validate_never_crashes(data: bytes) -> None:
    """
    Validator should never crash, even on successfully decoded malformed modules.
    """
    try:
        m = decode_module(data, limits=LIMITS)
    except DecodeError:
        return
    try:
        errs = validate_module(m)
        assert isinstance(errs, list)
        # All errors should have code and message
        for err in errs:
            assert hasattr(err, 'code')
            assert hasattr(err, 'message')
            assert isinstance(err.code, str)
            assert isinstance(err.message, str)
    except Exception as e:
        pytest.fail(f"Validator crashed with {type(e).__name__}: {e}")


def test_minimal_valid_module_always_decodes():
    """
    The minimal valid WASM module should always decode successfully.
    """
    minimal = b"\x00asm\x01\x00\x00\x00"
    m = decode_module(minimal)
    assert m is not None
    errors = validate_module(m)
    assert len(errors) == 0


@settings(max_examples=50)
@given(
    magic=st.binary(min_size=4, max_size=4),
    version=st.binary(min_size=4, max_size=4),
    sections=st.binary(min_size=0, max_size=100),
)
def test_invalid_magic_or_version_rejected(magic: bytes, version: bytes, sections: bytes) -> None:
    """
    Modules with invalid magic or version should be rejected.
    """
    if magic == b"\x00asm" and version == b"\x01\x00\x00\x00":
        # Valid magic and version, skip
        return

    data = magic + version + sections
    with pytest.raises(DecodeError):
        decode_module(data, limits=LIMITS)


@settings(max_examples=100)
@given(data=st.binary(min_size=8, max_size=LIMITS.max_module_bytes))
def test_decode_and_validate_combined(data: bytes) -> None:
    """
    decode_and_validate should either succeed or raise DecodeError or ValueError.
    """
    try:
        m = decode_and_validate(data, limits=LIMITS)
        assert m is not None
    except (DecodeError, ValueError):
        # Expected for malformed or invalid modules
        return
    except Exception as e:
        pytest.fail(f"Unexpected exception: {type(e).__name__}: {e}")
