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
    # TODO: Implement the decoding logic according to the specification.
    # 1. Validate minimum length and Magic Byte (0x42).
    # 2. Extract Version, Hdr Len, Pyld Len, and Flags.
    # 3. Validate total packet size vs expected lengths.
    # 4. Verify Checksum (XOR sum of all bytes except the last one).
    # 5. Parse Flags bitmask (0x01: encrypted, 0x02: compressed, 0x80: urgent).
    # 6. Return the Packet object.
    pass

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
    # TODO: Implement the encoding logic.
    # 1. Construct the header (Magic Byte, Version, Lengths, Flags).
    # 2. Append Options and Payload.
    # 3. Calculate the XOR Checksum of the entire sequence.
    # 4. Append the Checksum and return the result.
    pass
