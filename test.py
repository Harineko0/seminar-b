import pytest
from tinyproto import decode_packet, encode_packet, TinyProtoError, Packet


# ============================================================================
# HELPER FUNCTIONS FOR BLACK-BOX TESTING
# ============================================================================

def build_packet(version=0x01, hdr_len=0, pyld_len=0, flags=0x00,
                 options=b"", payload=b"") -> bytes:
    """
    Helper to manually construct a valid TinyProto packet with correct checksum.
    This allows us to create test packets without using encode_packet.
    """
    magic = 0x42

    # Build packet bytes (big-endian for multi-byte fields)
    packet = bytearray()
    packet.append(magic)
    packet.append(version)
    packet.append(hdr_len)
    packet.extend(pyld_len.to_bytes(2, 'big'))
    packet.append(flags)
    packet.extend(options)
    packet.extend(payload)

    # Calculate checksum (XOR of all bytes so far)
    checksum = 0
    for byte in packet:
        checksum ^= byte

    packet.append(checksum)
    return bytes(packet)


def flags_to_byte(encrypted=False, compressed=False, urgent=False) -> int:
    """Convert flag booleans to byte value."""
    result = 0
    if encrypted:
        result |= 0x01
    if compressed:
        result |= 0x02
    if urgent:
        result |= 0x80
    return result


# ============================================================================
# VALID PACKET TESTS (HAPPY PATH)
# ============================================================================

class TestValidPackets:
    """Tests for valid, well-formed packets."""

    def test_minimal_packet_v1(self):
        """Minimal valid packet: version 1, no options, no payload, no flags."""
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=0, flags=0x00)
        result = decode_packet(packet)

        assert result.version == 1
        assert result.flags == {"encrypted": False, "compressed": False, "urgent": False}
        assert result.options == b""
        assert result.payload == b""

    def test_minimal_packet_v2(self):
        """Minimal valid packet with version 2."""
        packet = build_packet(version=0x02, hdr_len=0, pyld_len=0, flags=0x00)
        result = decode_packet(packet)

        assert result.version == 2
        assert result.flags == {"encrypted": False, "compressed": False, "urgent": False}
        assert result.options == b""
        assert result.payload == b""

    def test_packet_with_small_payload(self):
        """Packet with small payload."""
        payload = b"Hello"
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=len(payload),
                            flags=0x00, payload=payload)
        result = decode_packet(packet)

        assert result.payload == payload
        assert result.options == b""

    def test_packet_with_small_options(self):
        """Packet with small options."""
        options = b"\x01\x02\x03"
        packet = build_packet(version=0x01, hdr_len=len(options), pyld_len=0,
                            flags=0x00, options=options)
        result = decode_packet(packet)

        assert result.options == options
        assert result.payload == b""

    def test_packet_with_options_and_payload(self):
        """Packet with both options and payload."""
        options = b"\xAA\xBB"
        payload = b"Test Data"
        packet = build_packet(version=0x01, hdr_len=len(options),
                            pyld_len=len(payload), flags=0x00,
                            options=options, payload=payload)
        result = decode_packet(packet)

        assert result.options == options
        assert result.payload == payload

    def test_packet_encrypted_flag(self):
        """Packet with encrypted flag set."""
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=0,
                            flags=0x01)
        result = decode_packet(packet)

        assert result.flags["encrypted"] == True
        assert result.flags["compressed"] == False
        assert result.flags["urgent"] == False

    def test_packet_compressed_flag(self):
        """Packet with compressed flag set."""
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=0,
                            flags=0x02)
        result = decode_packet(packet)

        assert result.flags["encrypted"] == False
        assert result.flags["compressed"] == True
        assert result.flags["urgent"] == False

    def test_packet_urgent_flag(self):
        """Packet with urgent flag set."""
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=0,
                            flags=0x80)
        result = decode_packet(packet)

        assert result.flags["encrypted"] == False
        assert result.flags["compressed"] == False
        assert result.flags["urgent"] == True

    def test_packet_all_flags_set(self):
        """Packet with all flags set."""
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=0,
                            flags=0x83)  # 0x01 | 0x02 | 0x80
        result = decode_packet(packet)

        assert result.flags["encrypted"] == True
        assert result.flags["compressed"] == True
        assert result.flags["urgent"] == True

    def test_packet_encrypted_and_compressed(self):
        """Packet with encrypted and compressed flags."""
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=0,
                            flags=0x03)
        result = decode_packet(packet)

        assert result.flags["encrypted"] == True
        assert result.flags["compressed"] == True
        assert result.flags["urgent"] == False

    def test_packet_encrypted_and_urgent(self):
        """Packet with encrypted and urgent flags."""
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=0,
                            flags=0x81)
        result = decode_packet(packet)

        assert result.flags["encrypted"] == True
        assert result.flags["compressed"] == False
        assert result.flags["urgent"] == True

    def test_packet_compressed_and_urgent(self):
        """Packet with compressed and urgent flags."""
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=0,
                            flags=0x82)
        result = decode_packet(packet)

        assert result.flags["encrypted"] == False
        assert result.flags["compressed"] == True
        assert result.flags["urgent"] == True

    def test_packet_max_options_length(self):
        """Packet with maximum options length (255 bytes)."""
        options = b"\xFF" * 255
        packet = build_packet(version=0x01, hdr_len=255, pyld_len=0,
                            flags=0x00, options=options)
        result = decode_packet(packet)

        assert result.options == options
        assert len(result.options) == 255

    def test_packet_large_payload_1kb(self):
        """Packet with 1KB payload."""
        payload = b"X" * 1024
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=1024,
                            flags=0x00, payload=payload)
        result = decode_packet(packet)

        assert result.payload == payload
        assert len(result.payload) == 1024

    def test_packet_large_payload_10kb(self):
        """Packet with 10KB payload."""
        payload = b"Y" * 10240
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=10240,
                            flags=0x00, payload=payload)
        result = decode_packet(packet)

        assert result.payload == payload
        assert len(result.payload) == 10240

    def test_packet_max_payload_length(self):
        """Packet with maximum payload length (65535 bytes)."""
        payload = b"\x00" * 65535
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=65535,
                            flags=0x00, payload=payload)
        result = decode_packet(packet)

        assert len(result.payload) == 65535

    def test_packet_binary_payload(self):
        """Packet with binary payload containing all byte values."""
        payload = bytes(range(256))
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=len(payload),
                            flags=0x00, payload=payload)
        result = decode_packet(packet)

        assert result.payload == payload

    def test_packet_binary_options(self):
        """Packet with binary options containing various byte values."""
        options = b"\x00\x01\xFF\x80\x7F"
        packet = build_packet(version=0x01, hdr_len=len(options), pyld_len=0,
                            flags=0x00, options=options)
        result = decode_packet(packet)

        assert result.options == options


# ============================================================================
# INVALID MAGIC BYTE TESTS
# ============================================================================

class TestInvalidMagicByte:
    """Tests for packets with invalid magic byte."""

    def test_wrong_magic_byte_0x00(self):
        """Magic byte is 0x00 instead of 0x42."""
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=0, flags=0x00)
        packet = bytearray(packet)
        packet[0] = 0x00  # Change magic byte

        with pytest.raises(TinyProtoError):
            decode_packet(bytes(packet))

    def test_wrong_magic_byte_0x41(self):
        """Magic byte is 0x41 (one less than correct)."""
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=0, flags=0x00)
        packet = bytearray(packet)
        packet[0] = 0x41

        with pytest.raises(TinyProtoError):
            decode_packet(bytes(packet))

    def test_wrong_magic_byte_0x43(self):
        """Magic byte is 0x43 (one more than correct)."""
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=0, flags=0x00)
        packet = bytearray(packet)
        packet[0] = 0x43

        with pytest.raises(TinyProtoError):
            decode_packet(bytes(packet))

    def test_wrong_magic_byte_0xFF(self):
        """Magic byte is 0xFF."""
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=0, flags=0x00)
        packet = bytearray(packet)
        packet[0] = 0xFF

        with pytest.raises(TinyProtoError):
            decode_packet(bytes(packet))

    def test_empty_data(self):
        """Empty byte array."""
        with pytest.raises(TinyProtoError):
            decode_packet(b"")

    def test_single_byte_wrong_magic(self):
        """Single byte with wrong magic."""
        with pytest.raises(TinyProtoError):
            decode_packet(b"\x00")


# ============================================================================
# UNSUPPORTED VERSION TESTS
# ============================================================================

class TestUnsupportedVersion:
    """Tests for packets with unsupported version."""

    def test_version_0(self):
        """Version 0 is not supported."""
        packet = build_packet(version=0x00, hdr_len=0, pyld_len=0, flags=0x00)

        with pytest.raises(TinyProtoError):
            decode_packet(packet)

    def test_version_3(self):
        """Version 3 is not supported."""
        packet = build_packet(version=0x03, hdr_len=0, pyld_len=0, flags=0x00)

        with pytest.raises(TinyProtoError):
            decode_packet(packet)

    def test_version_255(self):
        """Version 255 is not supported."""
        packet = build_packet(version=0xFF, hdr_len=0, pyld_len=0, flags=0x00)

        with pytest.raises(TinyProtoError):
            decode_packet(packet)

    def test_version_128(self):
        """Version 128 is not supported."""
        packet = build_packet(version=0x80, hdr_len=0, pyld_len=0, flags=0x00)

        with pytest.raises(TinyProtoError):
            decode_packet(packet)


# ============================================================================
# TRUNCATED DATA TESTS
# ============================================================================

class TestTruncatedData:
    """Tests for packets with truncated/incomplete data."""

    def test_truncated_header_1_byte(self):
        """Only magic byte present."""
        with pytest.raises(TinyProtoError):
            decode_packet(b"\x42")

    def test_truncated_header_2_bytes(self):
        """Only magic and version present."""
        with pytest.raises(TinyProtoError):
            decode_packet(b"\x42\x01")

    def test_truncated_header_3_bytes(self):
        """Header incomplete, missing payload length."""
        with pytest.raises(TinyProtoError):
            decode_packet(b"\x42\x01\x00")

    def test_truncated_header_4_bytes(self):
        """Header incomplete, partial payload length."""
        with pytest.raises(TinyProtoError):
            decode_packet(b"\x42\x01\x00\x00")

    def test_truncated_header_5_bytes(self):
        """Header incomplete, missing flags."""
        with pytest.raises(TinyProtoError):
            decode_packet(b"\x42\x01\x00\x00\x00")

    def test_missing_checksum_minimal(self):
        """Complete header but missing checksum."""
        # Magic, Version, HdrLen, PyldLen (2 bytes), Flags = 6 bytes
        # Missing checksum (should be 7 bytes total)
        with pytest.raises(TinyProtoError):
            decode_packet(b"\x42\x01\x00\x00\x00\x00")

    def test_missing_options_partial(self):
        """Header specifies options but they're missing."""
        packet = build_packet(version=0x01, hdr_len=10, pyld_len=0, flags=0x00)
        # Truncate to remove some options and checksum
        packet = packet[:10]

        with pytest.raises(TinyProtoError):
            decode_packet(packet)

    def test_missing_options_complete(self):
        """Header specifies options but none provided."""
        packet = build_packet(version=0x01, hdr_len=5, pyld_len=0, flags=0x00,
                            options=b"\x01\x02\x03\x04\x05")
        # Truncate to remove all options and checksum
        packet = packet[:6]

        with pytest.raises(TinyProtoError):
            decode_packet(packet)

    def test_missing_payload_partial(self):
        """Header specifies payload but it's partially missing."""
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=100, flags=0x00,
                            payload=b"X" * 100)
        # Truncate to have only 50 bytes of payload
        packet = packet[:56]  # 6 header + 50 payload

        with pytest.raises(TinyProtoError):
            decode_packet(packet)

    def test_missing_payload_complete(self):
        """Header specifies payload but none provided."""
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=50, flags=0x00,
                            payload=b"X" * 50)
        # Truncate to remove all payload and checksum
        packet = packet[:6]

        with pytest.raises(TinyProtoError):
            decode_packet(packet)

    def test_missing_checksum_with_payload(self):
        """Complete packet but missing checksum."""
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=10, flags=0x00,
                            payload=b"0123456789")
        # Remove checksum (last byte)
        packet = packet[:-1]

        with pytest.raises(TinyProtoError):
            decode_packet(packet)

    def test_missing_checksum_with_options(self):
        """Complete packet with options but missing checksum."""
        packet = build_packet(version=0x01, hdr_len=5, pyld_len=0, flags=0x00,
                            options=b"\x01\x02\x03\x04\x05")
        packet = packet[:-1]

        with pytest.raises(TinyProtoError):
            decode_packet(packet)


# ============================================================================
# CHECKSUM MISMATCH TESTS
# ============================================================================

class TestChecksumMismatch:
    """Tests for packets with incorrect checksums."""

    def test_checksum_off_by_one(self):
        """Checksum is off by one."""
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=0, flags=0x00)
        packet = bytearray(packet)
        packet[-1] ^= 0x01  # Flip one bit in checksum

        with pytest.raises(TinyProtoError):
            decode_packet(bytes(packet))

    def test_checksum_completely_wrong(self):
        """Checksum is completely wrong (0xFF)."""
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=0, flags=0x00)
        packet = bytearray(packet)
        packet[-1] = 0xFF

        with pytest.raises(TinyProtoError):
            decode_packet(bytes(packet))

    def test_checksum_zero(self):
        """Checksum is 0x00 (likely wrong unless XOR is 0)."""
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=5, flags=0x00,
                            payload=b"HELLO")
        packet = bytearray(packet)
        packet[-1] = 0x00

        with pytest.raises(TinyProtoError):
            decode_packet(bytes(packet))

    def test_corrupted_payload_byte(self):
        """One byte in payload is corrupted."""
        payload = b"TEST DATA"
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=len(payload),
                            flags=0x00, payload=payload)
        packet = bytearray(packet)
        packet[6] ^= 0xFF  # Flip all bits in first payload byte

        with pytest.raises(TinyProtoError):
            decode_packet(bytes(packet))

    def test_corrupted_options_byte(self):
        """One byte in options is corrupted."""
        options = b"\x01\x02\x03"
        packet = build_packet(version=0x01, hdr_len=len(options), pyld_len=0,
                            flags=0x00, options=options)
        packet = bytearray(packet)
        packet[7] ^= 0x55  # Corrupt second options byte

        with pytest.raises(TinyProtoError):
            decode_packet(bytes(packet))

    def test_corrupted_version_byte(self):
        """Version byte is corrupted but still valid (1->2)."""
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=0, flags=0x00)
        packet = bytearray(packet)
        packet[1] = 0x02  # Change version without updating checksum

        with pytest.raises(TinyProtoError):
            decode_packet(bytes(packet))

    def test_corrupted_flags_byte(self):
        """Flags byte is corrupted."""
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=0, flags=0x00)
        packet = bytearray(packet)
        packet[5] = 0x83  # Change flags without updating checksum

        with pytest.raises(TinyProtoError):
            decode_packet(bytes(packet))


# ============================================================================
# ENCODING TESTS
# ============================================================================

class TestEncoding:
    """Tests for encode_packet function."""

    def test_encode_minimal_v1(self):
        """Encode minimal packet version 1."""
        result = encode_packet(
            version=1,
            flags={"encrypted": False, "compressed": False, "urgent": False},
            options=b"",
            payload=b""
        )

        assert result[0] == 0x42  # Magic
        assert result[1] == 0x01  # Version
        assert result[2] == 0x00  # Hdr len
        assert result[3:5] == b"\x00\x00"  # Pyld len
        assert result[5] == 0x00  # Flags
        assert len(result) == 7  # 6 header + 1 checksum

    def test_encode_minimal_v2(self):
        """Encode minimal packet version 2."""
        result = encode_packet(
            version=2,
            flags={"encrypted": False, "compressed": False, "urgent": False},
            options=b"",
            payload=b""
        )

        assert result[0] == 0x42  # Magic
        assert result[1] == 0x02  # Version
        assert len(result) == 7

    def test_encode_with_payload(self):
        """Encode packet with payload."""
        payload = b"Hello, World!"
        result = encode_packet(
            version=1,
            flags={"encrypted": False, "compressed": False, "urgent": False},
            options=b"",
            payload=payload
        )

        pyld_len = int.from_bytes(result[3:5], 'big')
        assert pyld_len == len(payload)
        assert result[6:6+len(payload)] == payload

    def test_encode_with_options(self):
        """Encode packet with options."""
        options = b"\xAA\xBB\xCC"
        result = encode_packet(
            version=1,
            flags={"encrypted": False, "compressed": False, "urgent": False},
            options=options,
            payload=b""
        )

        assert result[2] == len(options)  # Hdr len
        assert result[6:6+len(options)] == options

    def test_encode_with_options_and_payload(self):
        """Encode packet with both options and payload."""
        options = b"\x01\x02"
        payload = b"Data"
        result = encode_packet(
            version=1,
            flags={"encrypted": False, "compressed": False, "urgent": False},
            options=options,
            payload=payload
        )

        hdr_len = result[2]
        pyld_len = int.from_bytes(result[3:5], 'big')

        assert hdr_len == len(options)
        assert pyld_len == len(payload)
        assert result[6:6+hdr_len] == options
        assert result[6+hdr_len:6+hdr_len+pyld_len] == payload

    def test_encode_encrypted_flag(self):
        """Encode with encrypted flag."""
        result = encode_packet(
            version=1,
            flags={"encrypted": True, "compressed": False, "urgent": False},
            options=b"",
            payload=b""
        )

        assert result[5] & 0x01 == 0x01
        assert result[5] & 0x02 == 0x00
        assert result[5] & 0x80 == 0x00

    def test_encode_compressed_flag(self):
        """Encode with compressed flag."""
        result = encode_packet(
            version=1,
            flags={"encrypted": False, "compressed": True, "urgent": False},
            options=b"",
            payload=b""
        )

        assert result[5] & 0x02 == 0x02

    def test_encode_urgent_flag(self):
        """Encode with urgent flag."""
        result = encode_packet(
            version=1,
            flags={"encrypted": False, "compressed": False, "urgent": True},
            options=b"",
            payload=b""
        )

        assert result[5] & 0x80 == 0x80

    def test_encode_all_flags(self):
        """Encode with all flags set."""
        result = encode_packet(
            version=1,
            flags={"encrypted": True, "compressed": True, "urgent": True},
            options=b"",
            payload=b""
        )

        assert result[5] == 0x83  # 0x01 | 0x02 | 0x80

    def test_encode_big_endian_payload_length(self):
        """Verify payload length is big-endian."""
        payload = b"X" * 0x0102  # 258 bytes
        result = encode_packet(
            version=1,
            flags={"encrypted": False, "compressed": False, "urgent": False},
            options=b"",
            payload=payload
        )

        assert result[3] == 0x01  # High byte
        assert result[4] == 0x02  # Low byte

    def test_encode_checksum_calculation(self):
        """Verify checksum is XOR of all preceding bytes."""
        result = encode_packet(
            version=1,
            flags={"encrypted": False, "compressed": False, "urgent": False},
            options=b"",
            payload=b""
        )

        # Calculate expected checksum
        expected = 0
        for byte in result[:-1]:
            expected ^= byte

        assert result[-1] == expected

    def test_encode_large_payload(self):
        """Encode packet with large payload."""
        payload = b"Z" * 1000
        result = encode_packet(
            version=1,
            flags={"encrypted": False, "compressed": False, "urgent": False},
            options=b"",
            payload=payload
        )

        pyld_len = int.from_bytes(result[3:5], 'big')
        assert pyld_len == 1000
        assert len(result) == 6 + 1000 + 1  # header + payload + checksum


# ============================================================================
# ROUND-TRIP TESTS
# ============================================================================

class TestRoundTrip:
    """Tests for encode -> decode round trips."""

    def test_roundtrip_minimal(self):
        """Round trip minimal packet."""
        encoded = encode_packet(1, {"encrypted": False, "compressed": False,
                                    "urgent": False}, b"", b"")
        decoded = decode_packet(encoded)

        assert decoded.version == 1
        assert decoded.options == b""
        assert decoded.payload == b""

    def test_roundtrip_with_payload(self):
        """Round trip with payload."""
        payload = b"Test Data 123"
        encoded = encode_packet(1, {"encrypted": False, "compressed": False,
                                    "urgent": False}, b"", payload)
        decoded = decode_packet(encoded)

        assert decoded.payload == payload

    def test_roundtrip_with_options(self):
        """Round trip with options."""
        options = b"\x01\x02\x03\x04\x05"
        encoded = encode_packet(1, {"encrypted": False, "compressed": False,
                                    "urgent": False}, options, b"")
        decoded = decode_packet(encoded)

        assert decoded.options == options

    def test_roundtrip_all_flags(self):
        """Round trip with all flags."""
        encoded = encode_packet(1, {"encrypted": True, "compressed": True,
                                    "urgent": True}, b"", b"")
        decoded = decode_packet(encoded)

        assert decoded.flags["encrypted"] == True
        assert decoded.flags["compressed"] == True
        assert decoded.flags["urgent"] == True

    def test_roundtrip_version_2(self):
        """Round trip version 2 packet."""
        payload = b"V2 Test"
        encoded = encode_packet(2, {"encrypted": False, "compressed": False,
                                    "urgent": False}, b"", payload)
        decoded = decode_packet(encoded)

        assert decoded.version == 2
        assert decoded.payload == payload

    def test_roundtrip_complex(self):
        """Round trip with all components."""
        options = b"\xFF\xFE\xFD"
        payload = b"Complex payload with various bytes: \x00\x01\x80\xFF"
        flags = {"encrypted": True, "compressed": False, "urgent": True}

        encoded = encode_packet(1, flags, options, payload)
        decoded = decode_packet(encoded)

        assert decoded.version == 1
        assert decoded.options == options
        assert decoded.payload == payload
        assert decoded.flags == flags

    def test_roundtrip_large_payload(self):
        """Round trip with large payload."""
        payload = bytes(range(256)) * 10  # 2560 bytes
        encoded = encode_packet(1, {"encrypted": False, "compressed": False,
                                    "urgent": False}, b"", payload)
        decoded = decode_packet(encoded)

        assert decoded.payload == payload

    def test_roundtrip_max_options(self):
        """Round trip with maximum options."""
        options = bytes(range(256))[:-1]  # 255 bytes
        encoded = encode_packet(1, {"encrypted": False, "compressed": False,
                                    "urgent": False}, options, b"")
        decoded = decode_packet(encoded)

        assert decoded.options == options


# ============================================================================
# EDGE CASE TESTS
# ============================================================================

class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_payload_length_boundary_255(self):
        """Payload exactly 255 bytes."""
        payload = b"X" * 255
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=255,
                            flags=0x00, payload=payload)
        result = decode_packet(packet)

        assert len(result.payload) == 255

    def test_payload_length_boundary_256(self):
        """Payload exactly 256 bytes."""
        payload = b"X" * 256
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=256,
                            flags=0x00, payload=payload)
        result = decode_packet(packet)

        assert len(result.payload) == 256

    def test_payload_length_boundary_257(self):
        """Payload exactly 257 bytes."""
        payload = b"X" * 257
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=257,
                            flags=0x00, payload=payload)
        result = decode_packet(packet)

        assert len(result.payload) == 257

    def test_payload_length_32767(self):
        """Payload at 32767 bytes (max signed 16-bit)."""
        payload = b"Y" * 32767
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=32767,
                            flags=0x00, payload=payload)
        result = decode_packet(packet)

        assert len(result.payload) == 32767

    def test_payload_length_32768(self):
        """Payload at 32768 bytes (min negative if signed)."""
        payload = b"Z" * 32768
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=32768,
                            flags=0x00, payload=payload)
        result = decode_packet(packet)

        assert len(result.payload) == 32768

    def test_flags_undefined_bits(self):
        """Flags with undefined bits set."""
        # Bits other than 0x01, 0x02, 0x80 are set
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=0,
                            flags=0x7C)  # Bits 2-6 set
        result = decode_packet(packet)

        # Should still decode (spec doesn't say these must be zero)
        assert result.flags["encrypted"] == False
        assert result.flags["compressed"] == False
        assert result.flags["urgent"] == False

    def test_checksum_all_zeros_data(self):
        """Packet where all data bytes are zero."""
        payload = b"\x00" * 10
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=10,
                            flags=0x00, payload=payload)
        result = decode_packet(packet)

        assert result.payload == payload

    def test_checksum_all_ones_data(self):
        """Packet where all data bytes are 0xFF."""
        payload = b"\xFF" * 10
        options = b"\xFF" * 5
        packet = build_packet(version=0x01, hdr_len=5, pyld_len=10,
                            flags=0xFF, options=options, payload=payload)
        result = decode_packet(packet)

        assert result.payload == payload
        assert result.options == options
    
    def test_max_combined_length(self):
        """Test maximum possible combined length of options and payload."""
        hdr_len = 255
        pyld_len = 65535
        options = b"\x01" * hdr_len
        payload = b"\x02" * pyld_len
        packet = build_packet(version=0x01, hdr_len=hdr_len, pyld_len=pyld_len,
                            flags=0x00, options=options, payload=payload)
        
        # This will test if the total length (65797 bytes) is handled correctly
        result = decode_packet(packet)
        assert len(result.options) == 255
        assert len(result.payload) == 65535

    def test_encode_options_too_long(self):
        """Encoder should handle options that exceed 1-byte length limit."""
        options = b"X" * 256  # Cannot fit in 1-byte Hdr Len
        with pytest.raises(TinyProtoError):
            encode_packet(1, {"encrypted": False, "compressed": False, "urgent": False}, 
                         options, b"")

# ============================================================================
# SPECIFICATION COMPLIANCE TESTS
# ============================================================================

class TestSpecificationCompliance:
    """Tests verifying strict adherence to specification."""

    def test_magic_byte_must_be_0x42(self):
        """Specification: Magic byte must be exactly 0x42."""
        valid = build_packet(version=0x01, hdr_len=0, pyld_len=0, flags=0x00)
        assert valid[0] == 0x42

        # Any other value should fail
        for magic in [0x00, 0x41, 0x43, 0xFF]:
            invalid = bytearray(valid)
            invalid[0] = magic
            with pytest.raises(TinyProtoError):
                decode_packet(bytes(invalid))

    def test_supported_versions_only_1_and_2(self):
        """Specification: Supported versions are 0x01 and 0x02 only."""
        # Version 1 should work
        v1 = build_packet(version=0x01, hdr_len=0, pyld_len=0, flags=0x00)
        result = decode_packet(v1)
        assert result.version == 1

        # Version 2 should work
        v2 = build_packet(version=0x02, hdr_len=0, pyld_len=0, flags=0x00)
        result = decode_packet(v2)
        assert result.version == 2

        # All other versions should fail
        for ver in [0x00, 0x03, 0x04, 0xFF]:
            invalid = build_packet(version=ver, hdr_len=0, pyld_len=0, flags=0x00)
            with pytest.raises(TinyProtoError):
                decode_packet(invalid)

    def test_payload_length_is_big_endian(self):
        """Specification: Payload length is 2 bytes, big-endian."""
        # Test value 0x0102 (258 decimal)
        payload = b"X" * 258
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=258,
                            flags=0x00, payload=payload)

        # Verify big-endian encoding
        assert packet[3] == 0x01  # High byte first
        assert packet[4] == 0x02  # Low byte second

        result = decode_packet(packet)
        assert len(result.payload) == 258

    def test_flags_bitmask_definition(self):
        """Specification: Flags are 0x01=encrypted, 0x02=compressed, 0x80=urgent."""
        # Test each flag individually
        enc = build_packet(version=0x01, hdr_len=0, pyld_len=0, flags=0x01)
        result = decode_packet(enc)
        assert result.flags["encrypted"] == True
        assert result.flags["compressed"] == False
        assert result.flags["urgent"] == False

        comp = build_packet(version=0x01, hdr_len=0, pyld_len=0, flags=0x02)
        result = decode_packet(comp)
        assert result.flags["encrypted"] == False
        assert result.flags["compressed"] == True
        assert result.flags["urgent"] == False

        urg = build_packet(version=0x01, hdr_len=0, pyld_len=0, flags=0x80)
        result = decode_packet(urg)
        assert result.flags["encrypted"] == False
        assert result.flags["compressed"] == False
        assert result.flags["urgent"] == True

    def test_checksum_is_xor_of_all_bytes(self):
        """Specification: Checksum is XOR of all bytes before it."""
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=5,
                            flags=0x00, payload=b"HELLO")

        # Calculate expected checksum
        expected = 0
        for byte in packet[:-1]:
            expected ^= byte

        assert packet[-1] == expected

        # Should decode successfully
        decode_packet(packet)

        # Change checksum should fail
        invalid = bytearray(packet)
        invalid[-1] ^= 0xFF
        with pytest.raises(TinyProtoError):
            decode_packet(bytes(invalid))

    def test_header_length_range_0_to_255(self):
        """Specification: Header length is 1 byte (0-255)."""
        # Test boundaries
        for hdr_len in [0, 1, 127, 128, 254, 255]:
            options = b"\x00" * hdr_len
            packet = build_packet(version=0x01, hdr_len=hdr_len, pyld_len=0,
                                flags=0x00, options=options)
            result = decode_packet(packet)
            assert len(result.options) == hdr_len

    def test_payload_length_range_0_to_65535(self):
        """Specification: Payload length is 2 bytes (0-65535)."""
        # Test boundaries (max is expensive, so test smaller values and structure)
        for pyld_len in [0, 1, 255, 256, 257, 65534]:
            payload = b"\x00" * pyld_len
            packet = build_packet(version=0x01, hdr_len=0, pyld_len=pyld_len,
                                flags=0x00, payload=payload)
            result = decode_packet(packet)
            assert len(result.payload) == pyld_len


# ============================================================================
# ADVANCED EDGE CASE TESTS (ADDITIONAL TEST CASES)
# ============================================================================

class TestAdvancedEdgeCases:
    """Additional edge case tests for specific bug patterns."""

    def test_trailing_bytes_after_valid_packet(self):
        """
        Test handling of trailing bytes appended to a valid packet.

        This tests a common bug where implementations might use len(data)
        directly for checksum calculations instead of calculating only up to
        the expected packet length, causing checksum mismatches.

        Expected behavior: Implementation should either raise an error for
        extra data or ignore it and return only the valid packet.
        """
        # Build a valid minimal packet
        valid_packet = build_packet(version=0x01, hdr_len=0, pyld_len=0, flags=0x00)

        # Append trailing bytes
        packet_with_trailing = valid_packet + b"\x00"

        # Attempt to decode - the implementation should either:
        # 1. Raise TinyProtoError for extra unexpected data, OR
        # 2. Successfully decode and ignore the trailing bytes
        #
        # The spec doesn't explicitly define this behavior, but the implementation
        # should handle it consistently. Testing both scenarios:

        try:
            result = decode_packet(packet_with_trailing)
            # If it succeeds, verify it decoded correctly (ignoring trailing bytes)
            assert result.version == 1
            assert result.options == b""
            assert result.payload == b""
        except TinyProtoError:
            # If it raises an error, that's also acceptable behavior
            pass

    def test_trailing_bytes_multiple(self):
        """Test packet with multiple trailing bytes."""
        valid_packet = build_packet(version=0x01, hdr_len=0, pyld_len=5,
                                   flags=0x00, payload=b"HELLO")
        packet_with_trailing = valid_packet + b"\xFF\xFF\xFF"

        try:
            result = decode_packet(packet_with_trailing)
            assert result.payload == b"HELLO"
        except TinyProtoError:
            pass

    def test_large_payload_length_0x8000(self):
        """
        Test payload length of 0x8000 (32768) - boundary for signed interpretation.

        In languages like C/C++, if Pyld Len is treated as a signed 16-bit integer,
        values >= 0x8000 would be interpreted as negative numbers, causing bugs.

        This test ensures the implementation treats the payload length as unsigned.
        """
        pyld_len = 0x8000  # 32768 - would be -32768 if treated as signed
        payload = b"X" * pyld_len
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=pyld_len,
                            flags=0x00, payload=payload)

        result = decode_packet(packet)
        assert len(result.payload) == 32768
        assert result.payload == payload

    def test_large_payload_length_0xFFFF(self):
        """Test maximum payload length 0xFFFF (65535) - would be -1 if signed."""
        # This is expensive to test with actual data, so we test the structure
        pyld_len = 0xFFFF
        payload = b"Y" * pyld_len
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=pyld_len,
                            flags=0x00, payload=payload)

        result = decode_packet(packet)
        assert len(result.payload) == 65535

    def test_large_payload_length_0x8001(self):
        """Test payload length just above signed boundary."""
        pyld_len = 0x8001  # 32769
        payload = b"Z" * pyld_len
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=pyld_len,
                            flags=0x00, payload=payload)

        result = decode_packet(packet)
        assert len(result.payload) == 32769

    def test_empty_options_and_payload_slicing(self):
        """
        Test that slicing operations correctly handle empty options and payload.

        When Hdr Len=0 and Pyld Len=0, slicing like data[6:6] should return
        empty bytes objects, not cause errors.
        """
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=0, flags=0x00)
        result = decode_packet(packet)

        # Verify both are empty bytes
        assert result.options == b""
        assert result.payload == b""
        assert isinstance(result.options, bytes)
        assert isinstance(result.payload, bytes)
        assert len(result.options) == 0
        assert len(result.payload) == 0

    def test_empty_options_with_payload(self):
        """Test empty options (Hdr Len=0) with non-empty payload."""
        payload = b"Data"
        packet = build_packet(version=0x01, hdr_len=0, pyld_len=len(payload),
                            flags=0x00, payload=payload)
        result = decode_packet(packet)

        assert result.options == b""
        assert isinstance(result.options, bytes)
        assert len(result.options) == 0
        assert result.payload == payload

    def test_empty_payload_with_options(self):
        """Test empty payload (Pyld Len=0) with non-empty options."""
        options = b"\x01\x02\x03"
        packet = build_packet(version=0x01, hdr_len=len(options), pyld_len=0,
                            flags=0x00, options=options)
        result = decode_packet(packet)

        assert result.options == options
        assert result.payload == b""
        assert isinstance(result.payload, bytes)
        assert len(result.payload) == 0
