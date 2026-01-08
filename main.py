from tinyproto import decode_packet, encode_packet

def main():
    # Setup sample data
    version = 1
    flags = {"encrypted": True, "compressed": False, "urgent": True}
    options = b"\x01\x02"
    payload = b"Hello, TinyProto!"

    print("--- Encoding ---")
    try:
        packet_bytes = encode_packet(version, flags, options, payload)
        print(f"Encoded Hex: {packet_bytes.hex()}")

        print("\n--- Decoding ---")
        decoded = decode_packet(packet_bytes)
        print(f"Decoded Object: {decoded}")
        
        # Validation
        assert decoded.version == version
        assert decoded.payload == payload
        print("\nSuccess: Round-trip check passed!")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
