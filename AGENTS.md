# TinyProto
lightweight, binary-oriented serialization protocol designed for resource-constrained IoT devices.

## Test strategy
```
# Run Basic Script
uv run main.py

# Run Unit Tests
uv run pytest test.py

# Run Property-Based Tests
uv run pytest pbt.py

# Run Symbolic Execution
uv run crosshair check tinyproto.py
```
## Installed packages
- hypothesis 6.150.0 
- pytest 9.0.0 
- crosshair-tool 0.0.101
