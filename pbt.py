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

