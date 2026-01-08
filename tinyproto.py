from dataclasses import dataclass
from typing import Dict

class TinyProtoError(Exception):
    """Base exception for TinyProto errors."""


class InvalidMagicByte(TinyProtoError):
    """Raised when the magic byte is invalid."""


class UnsupportedVersion(TinyProtoError):
    """Raised when the protocol version is unsupported."""


class TruncatedData(TinyProtoError):
    """Raised when the packet is shorter than expected."""


class ChecksumMismatch(TinyProtoError):
    """Raised when the checksum does not match."""

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
    if len(data) < 1:
        raise TruncatedData("Packet too short to read magic byte.")
    if data[0] != 0x42:
        raise InvalidMagicByte(f"Invalid magic byte: {data[0]:#04x}")
    if len(data) < 2:
        raise TruncatedData("Packet too short to read version.")

    version = data[1]
    if version not in (0x01, 0x02):
        raise UnsupportedVersion(f"Unsupported version: {version:#04x}")
    if len(data) < 6:
        raise TruncatedData("Packet too short to read header.")

    hdr_len = data[2]
    pyld_len = int.from_bytes(data[3:5], "big")
    flags_byte = data[5]

    expected_len = 6 + hdr_len + pyld_len + 1
    if len(data) < expected_len:
        raise TruncatedData("Packet shorter than specified lengths.")
    if len(data) > expected_len:
        raise TinyProtoError("Packet longer than specified lengths.")

    checksum = data[expected_len - 1]
    calc_checksum = 0
    for b in data[: expected_len - 1]:
        calc_checksum ^= b
    if calc_checksum != checksum:
        raise ChecksumMismatch("Checksum mismatch.")

    options_start = 6
    options_end = options_start + hdr_len
    payload_start = options_end
    payload_end = payload_start + pyld_len

    options = data[options_start:options_end]
    payload = data[payload_start:payload_end]

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
        raise UnsupportedVersion(f"Unsupported version: {version:#04x}")
    if len(options) > 0xFF:
        raise TinyProtoError("Options too long for header length field.")
    if len(payload) > 0xFFFF:
        raise TinyProtoError("Payload too long for payload length field.")

    flags_byte = 0
    if flags.get("encrypted"):
        flags_byte |= 0x01
    if flags.get("compressed"):
        flags_byte |= 0x02
    if flags.get("urgent"):
        flags_byte |= 0x80

    header = bytearray()
    header.append(0x42)
    header.append(version)
    header.append(len(options))
    header.extend(len(payload).to_bytes(2, "big"))
    header.append(flags_byte)
    header.extend(options)
    header.extend(payload)

    checksum = 0
    for b in header:
        checksum ^= b
    header.append(checksum)
    return bytes(header)
