from hypothesis import given, strategies as st

from tinyproto import (
    ChecksumMismatch,
    InvalidMagicByte,
    TruncatedData,
    UnsupportedVersion,
    decode_packet,
    encode_packet,
)

flags_strategy = st.fixed_dictionaries(
    {"encrypted": st.booleans(), "compressed": st.booleans(), "urgent": st.booleans()}
)


@given(
    version=st.sampled_from([0x01, 0x02]),
    flags=flags_strategy,
    options=st.binary(min_size=0, max_size=32),
    payload=st.binary(min_size=0, max_size=128),
)
def test_round_trip(version, flags, options, payload):
    packet = encode_packet(version, flags, options, payload)
    decoded = decode_packet(packet)
    assert decoded.version == version
    assert decoded.flags == flags
    assert decoded.options == options
    assert decoded.payload == payload


@given(
    version=st.sampled_from([0x01, 0x02]),
    flags=flags_strategy,
    options=st.binary(min_size=0, max_size=16),
    payload=st.binary(min_size=0, max_size=64),
)
def test_invalid_magic_byte(version, flags, options, payload):
    packet = bytearray(encode_packet(version, flags, options, payload))
    packet[0] ^= 0xFF
    try:
        decode_packet(bytes(packet))
        assert False, "Expected InvalidMagicByte"
    except InvalidMagicByte:
        assert True


@given(
    version=st.integers(min_value=0, max_value=255).filter(lambda v: v not in (1, 2)),
    flags=flags_strategy,
    options=st.binary(min_size=0, max_size=16),
    payload=st.binary(min_size=0, max_size=64),
)
def test_unsupported_version(version, flags, options, payload):
    packet = bytearray()
    packet.append(0x42)
    packet.append(version)
    packet.append(len(options))
    packet.extend(len(payload).to_bytes(2, "big"))
    flags_byte = 0
    if flags["encrypted"]:
        flags_byte |= 0x01
    if flags["compressed"]:
        flags_byte |= 0x02
    if flags["urgent"]:
        flags_byte |= 0x80
    packet.append(flags_byte)
    packet.extend(options)
    packet.extend(payload)
    checksum = 0
    for b in packet:
        checksum ^= b
    packet.append(checksum)
    try:
        decode_packet(bytes(packet))
        assert False, "Expected UnsupportedVersion"
    except UnsupportedVersion:
        assert True


@given(
    version=st.sampled_from([0x01, 0x02]),
    flags=flags_strategy,
    options=st.binary(min_size=0, max_size=16),
    payload=st.binary(min_size=0, max_size=64),
)
def test_truncated_data(version, flags, options, payload):
    packet = encode_packet(version, flags, options, payload)
    truncated = packet[:-1]
    try:
        decode_packet(truncated)
        assert False, "Expected TruncatedData"
    except TruncatedData:
        assert True


@given(
    version=st.sampled_from([0x01, 0x02]),
    flags=flags_strategy,
    options=st.binary(min_size=0, max_size=16),
    payload=st.binary(min_size=0, max_size=64),
)
def test_checksum_mismatch(version, flags, options, payload):
    packet = bytearray(encode_packet(version, flags, options, payload))
    packet[-1] ^= 0xFF
    try:
        decode_packet(bytes(packet))
        assert False, "Expected ChecksumMismatch"
    except ChecksumMismatch:
        assert True
