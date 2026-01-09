from dataclasses import dataclass
from typing import Dict

class TinyProtoError(Exception):
    """Base exception for TinyProto errors."""
    pass

@dataclass
class Packet:
    version: int
    flags: Dict[str, bool]
    options: bytes
    payload: bytes

def decode_packet(data: bytes) -> Packet:
    """
    Decodes a TinyProto binary packet.
    
    Args:
        data: The raw bytes to decode.
        
    Returns:
        A Packet dataclass object.
        
    Raises:
        TinyProtoError: If validation fails (Magic Byte, Version, Checksum, etc.)
    """
    if len(data) < 7:
        raise TinyProtoError("Truncated Data")
    if data[0] != 0x42:
        raise TinyProtoError("Invalid Magic Byte")

    version = data[1]
    if version not in (0x01, 0x02):
        raise TinyProtoError("Unsupported Version")

    hdr_len = data[2]
    pyld_len = int.from_bytes(data[3:5], "big")
    flags_byte = data[5]

    expected_len = 6 + hdr_len + pyld_len + 1
    if len(data) < expected_len:
        raise TinyProtoError("Truncated Data")
    if len(data) > expected_len:
        raise TinyProtoError("Checksum Mismatch")

    checksum = _xor_checksum(data[:-1])
    if checksum != data[-1]:
        raise TinyProtoError("Checksum Mismatch")

    options_start = 6
    options_end = options_start + hdr_len
    payload_end = options_end + pyld_len
    options = data[options_start:options_end]
    payload = data[options_end:payload_end]

    flags = {
        "encrypted": bool(flags_byte & 0x01),
        "compressed": bool(flags_byte & 0x02),
        "urgent": bool(flags_byte & 0x80),
    }
    return Packet(version=version, flags=flags, options=options, payload=payload)

def encode_packet(version: int, flags: Dict[str, bool], options: bytes, payload: bytes) -> bytes:
    """
    Encodes data into a TinyProto binary packet.
    
    Args:
        version: Protocol version (1 or 2).
        flags: A dictionary containing boolean keys 'encrypted', 'compressed', 'urgent'.
        options: Header options bytes.
        payload: Payload bytes.
        
    Returns:
        The complete binary packet including the checksum.
    """
    if version not in (0x01, 0x02):
        raise TinyProtoError("Unsupported Version")
    if len(options) > 0xFF:
        raise TinyProtoError("Options Too Long")
    if len(payload) > 0xFFFF:
        raise TinyProtoError("Payload Too Long")

    flags_byte = 0
    if bool(flags.get("encrypted", False)):
        flags_byte |= 0x01
    if bool(flags.get("compressed", False)):
        flags_byte |= 0x02
    if bool(flags.get("urgent", False)):
        flags_byte |= 0x80

    header = bytes(
        [
            0x42,
            version,
            len(options),
        ]
    )
    header += len(payload).to_bytes(2, "big")
    header += bytes([flags_byte])

    body = header + options + payload
    checksum = _xor_checksum(body)
    return body + bytes([checksum])


def _xor_checksum(data: bytes) -> int:
    checksum = 0
    for b in data:
        checksum ^= b
    return checksum


def check_roundtrip(
    version: int,
    options: bytes,
    payload: bytes,
    encrypted: bool,
    compressed: bool,
    urgent: bool,
) -> Packet:
    """
    pre: version in (1, 2)
    pre: len(options) <= 0xFF
    pre: len(payload) <= 0xFFFF
    post: __return__.version == version
    post: __return__.options == options
    post: __return__.payload == payload
    post: __return__.flags == {"encrypted": encrypted, "compressed": compressed, "urgent": urgent}
    """
    flags = {"encrypted": encrypted, "compressed": compressed, "urgent": urgent}
    encoded = encode_packet(version, flags, options, payload)
    return decode_packet(encoded)


def check_magic_validation(
    version: int,
    options: bytes,
    payload: bytes,
    encrypted: bool,
    compressed: bool,
    urgent: bool,
) -> bool:
    """
    pre: version in (1, 2)
    pre: len(options) <= 0xFF
    pre: len(payload) <= 0xFFFF
    post: __return__ is True
    """
    flags = {"encrypted": encrypted, "compressed": compressed, "urgent": urgent}
    encoded = encode_packet(version, flags, options, payload)
    tampered = bytes([0x00]) + encoded[1:]
    try:
        decode_packet(tampered)
    except TinyProtoError as exc:
        return str(exc) == "Invalid Magic Byte"
    return False


def check_checksum_validation(
    version: int,
    options: bytes,
    payload: bytes,
    encrypted: bool,
    compressed: bool,
    urgent: bool,
) -> bool:
    """
    pre: version in (1, 2)
    pre: len(options) <= 0xFF
    pre: len(payload) <= 0xFFFF
    post: __return__ is True
    """
    flags = {"encrypted": encrypted, "compressed": compressed, "urgent": urgent}
    encoded = encode_packet(version, flags, options, payload)
    tampered = encoded[:-1] + bytes([encoded[-1] ^ 0xFF])
    try:
        decode_packet(tampered)
    except TinyProtoError as exc:
        return str(exc) == "Checksum Mismatch"
    return False


def check_truncated_data(
    version: int,
    options: bytes,
    payload: bytes,
    encrypted: bool,
    compressed: bool,
    urgent: bool,
) -> bool:
    """
    pre: version in (1, 2)
    pre: len(options) <= 0xFF
    pre: len(payload) <= 0xFFFF
    post: __return__ is True
    """
    flags = {"encrypted": encrypted, "compressed": compressed, "urgent": urgent}
    encoded = encode_packet(version, flags, options, payload)
    truncated = encoded[:-1]
    try:
        decode_packet(truncated)
    except TinyProtoError as exc:
        return str(exc) == "Truncated Data"
    return False


def check_unsupported_version(
    bad_version: int,
    options: bytes,
    payload: bytes,
) -> bool:
    """
    pre: bad_version not in (1, 2)
    pre: len(options) <= 0xFF
    pre: len(payload) <= 0xFFFF
    post: __return__ is True
    """
    flags = {"encrypted": False, "compressed": False, "urgent": False}
    header = bytes([0x42, bad_version, len(options)])
    header += len(payload).to_bytes(2, "big")
    header += bytes([0x00])
    body = header + options + payload
    checksum = _xor_checksum(body)
    encoded = body + bytes([checksum])
    try:
        decode_packet(encoded)
    except TinyProtoError as exc:
        return str(exc) == "Unsupported Version"
    return False


def check_encoded_header_fields(
    version: int,
    options: bytes,
    payload: bytes,
    encrypted: bool,
    compressed: bool,
    urgent: bool,
) -> bytes:
    """
    pre: version in (1, 2)
    pre: len(options) <= 0xFF
    pre: len(payload) <= 0xFFFF
    post: __return__[0] == 0x42
    post: __return__[1] == version
    post: __return__[2] == len(options)
    post: __return__[3:5] == len(payload).to_bytes(2, "big")
    post: len(__return__) == 6 + len(options) + len(payload) + 1
    """
    flags = {"encrypted": encrypted, "compressed": compressed, "urgent": urgent}
    return encode_packet(version, flags, options, payload)


def check_encoded_flags_bits(
    version: int,
    options: bytes,
    payload: bytes,
    encrypted: bool,
    compressed: bool,
    urgent: bool,
) -> bytes:
    """
    pre: version in (1, 2)
    pre: len(options) <= 0xFF
    pre: len(payload) <= 0xFFFF
    post: (__return__[5] & 0x01 != 0) == encrypted
    post: (__return__[5] & 0x02 != 0) == compressed
    post: (__return__[5] & 0x80 != 0) == urgent
    """
    flags = {"encrypted": encrypted, "compressed": compressed, "urgent": urgent}
    return encode_packet(version, flags, options, payload)


def check_checksum_matches_xor(
    version: int,
    options: bytes,
    payload: bytes,
    encrypted: bool,
    compressed: bool,
    urgent: bool,
) -> bytes:
    """
    pre: version in (1, 2)
    pre: len(options) <= 0xFF
    pre: len(payload) <= 0xFFFF
    post: __return__[-1] == _xor_checksum(__return__[:-1])
    """
    flags = {"encrypted": encrypted, "compressed": compressed, "urgent": urgent}
    return encode_packet(version, flags, options, payload)


def check_rejects_extra_bytes(
    version: int,
    options: bytes,
    payload: bytes,
    encrypted: bool,
    compressed: bool,
    urgent: bool,
) -> bool:
    """
    pre: version in (1, 2)
    pre: len(options) <= 0xFF
    pre: len(payload) <= 0xFFFF
    post: __return__ is True
    """
    flags = {"encrypted": encrypted, "compressed": compressed, "urgent": urgent}
    encoded = encode_packet(version, flags, options, payload)
    extended = encoded + b"\x00"
    try:
        decode_packet(extended)
    except TinyProtoError as exc:
        return str(exc) == "Checksum Mismatch"
    return False


def check_decode_ignores_unknown_flag_bits(
    version: int,
    options: bytes,
    payload: bytes,
    encrypted: bool,
    compressed: bool,
    urgent: bool,
    extra_flags: int,
) -> Packet:
    """
    pre: version in (1, 2)
    pre: len(options) <= 0xFF
    pre: len(payload) <= 0xFFFF
    pre: 0 <= extra_flags <= 0xFF
    post: __return__.flags == {"encrypted": encrypted, "compressed": compressed, "urgent": urgent}
    """
    flags_byte = 0
    if encrypted:
        flags_byte |= 0x01
    if compressed:
        flags_byte |= 0x02
    if urgent:
        flags_byte |= 0x80
    flags_byte |= extra_flags & 0x7C

    header = bytes([0x42, version, len(options)])
    header += len(payload).to_bytes(2, "big")
    header += bytes([flags_byte])
    body = header + options + payload
    checksum = _xor_checksum(body)
    encoded = body + bytes([checksum])
    return decode_packet(encoded)
