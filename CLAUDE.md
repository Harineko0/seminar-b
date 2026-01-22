# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`wasm_sv` is a WebAssembly binary module parser and structural validator implemented in Python. It decodes WASM binary format (`.wasm` bytes) into an AST (Python dataclasses) and performs deterministic structural validation. This is NOT a compiler or interpreter - no execution occurs.

## Architecture

### Public API

All external code MUST use `parser.py`. Never import from internal modules directly.

Three public entry points:
- `decode_module(data: bytes, *, limits: Limits = Limits()) -> Module`
- `validate_module(module: Module) -> list[ValidationError]`
- `decode_and_validate(data: bytes, *, limits: Limits = Limits()) -> Module`

### Error Types

- `DecodeError` (exception) - Binary is malformed or uses unsupported WASM features
- `ValidationError` (dataclass) - Structural validation failures (bad indices, duplicate exports, etc.)

### Supported WASM Subset

See `SPEC.md` for complete details. Key restrictions:
- Value types: only `i32` and `i64` (no floats)
- Instructions: subset of 6 opcodes (`i32.const`, `local.get`, `local.set`, `i32.add`, `call`, `end`)
- Element/Data segments: only active mode for table/memory 0 with `i32.const` offset
- All sections 0-12 supported with strict ordering rules

### Resource Limits

`Limits` dataclass prevents DoS/path explosion:
- `max_module_bytes` (default 1 MiB)
- `max_section_bytes` (default 512 KiB)
- `max_vector_length` (default 50,000)
- `max_function_body_bytes` (default 64 KiB)
- `max_locals_per_function` (default 10,000)
- `max_custom_section_bytes` (default 256 KiB)

## Development Commands

### Run Basic Script
```bash
uv run main.py
```

### Testing (Three-Layer Strategy)

**Unit tests:**
```bash
uv run pytest test.py           # All unit tests
uv run pytest test.py::test_foo # Specific test
make pytest                     # Via Makefile
make pytest test_foo            # Via Makefile with filter
```

**Property-based tests (Hypothesis):**
```bash
uv run pytest pbt.py            # All PBT tests
uv run pytest pbt.py -k pattern # Filter by pattern
make hypothesis                 # Via Makefile
make hypothesis -k pattern      # Via Makefile with filter
```

**Symbolic execution (CrossHair):**
```bash
uv run crosshair check symbolic.py        # Check all
uv run crosshair check symbolic.py --per_path_timeout=5  # Custom timeout
make crosshair                            # Via Makefile
```

**Run all tests:**
```bash
make test    # Runs pytest → hypothesis → crosshair in sequence
```

**Makefile help:**
```bash
make help    # Shows all available targets with examples
```

### Dependencies

Managed by `uv` (specified in `pyproject.toml`):
- hypothesis 6.150.0 (property-based testing)
- pytest 9.0.0 (unit testing)
- crosshair-tool 0.0.101 (symbolic execution)

Python 3.11+ required.

## File Organization

- `parser.py` - **Public API** (start here)
- `SPEC.md` - Complete specification of supported WASM subset
- `main.py` - Minimal example usage

### Test Files
- `test.py` - Unit tests
- `pbt.py` - Property-based tests (Hypothesis)
- `symbolic.py` - Symbolic execution tests (CrossHair)
