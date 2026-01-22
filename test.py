"""
Unit tests for WASM binary module parser and validator.
"""

import pytest
from parser import decode_module, validate_module, decode_and_validate, DecodeError, Limits

