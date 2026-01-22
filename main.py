from parser import decode_and_validate, Limits

def main() -> None:
    # Minimal valid WASM module: magic + version, no sections.
    wasm_bytes = b"\x00asm\x01\x00\x00\x00"

    module = decode_and_validate(wasm_bytes, limits=Limits(max_module_bytes=64))
    print("OK:", module)

if __name__ == "__main__":
    main()

