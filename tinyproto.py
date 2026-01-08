from dataclasses import dataclass
from typing import Dict, Any

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
    if len(data) < 1:
        raise TinyProtoError("Truncated Data")
    if data[0] != 0x42:
        raise TinyProtoError("Invalid Magic Byte")
    if len(data) < 6:
        raise TinyProtoError("Truncated Data")

    version = data[1]
    if version not in (0x01, 0x02):
        raise TinyProtoError("Unsupported Version")

    hdr_len = data[2]
    pyld_len = int.from_bytes(data[3:5], "big")
    flags_byte = data[5]

    expected_len = 6 + hdr_len + pyld_len + 1
    if len(data) != expected_len:
        raise TinyProtoError("Truncated Data")

    checksum = data[-1]
    calc = 0
    for b in data[:-1]:
        calc ^= b
    if calc != checksum:
        raise TinyProtoError("Checksum Mismatch")

    options = data[6:6 + hdr_len]
    payload = data[6 + hdr_len:6 + hdr_len + pyld_len]
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
    if len(options) > 0xFF or len(payload) > 0xFFFF:
        raise TinyProtoError("Truncated Data")

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

    packet = header + options + payload
    checksum = 0
    for b in packet:
        checksum ^= b
    packet.append(checksum)
    return bytes(packet)
