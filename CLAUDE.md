# wasm_sv

WASM Binary Module Parser + Structural Validator (Python)

## Rules

- UNIX philosophy (file separation)

## Test strategy
```
# Run Basic Script
uv run main.py

# Run Unit Tests
uv run pytest test.py

# Run Property-Based Tests
uv run pytest pbt.py

# Run Symbolic Execution
uv run crosshair check symbolic.py
```

## Installed packages
- hypothesis 6.150.0 
- pytest 9.0.0 
- crosshair-tool 0.0.101
