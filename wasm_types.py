"""
WebAssembly AST dataclasses.

Defines the complete Abstract Syntax Tree for WebAssembly modules.
"""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Optional


# ===== Value Types =====

class ValType(IntEnum):
    """WebAssembly value types."""
    I32 = 0x7F
    I64 = 0x7E
    F32 = 0x7D
    F64 = 0x7C


class RefType(IntEnum):
    """WebAssembly reference types."""
    FUNCREF = 0x70
    EXTERNREF = 0x6F


# ===== Limits =====

@dataclass
class Limits:
    """Memory and table limits."""
    min: int
    max: Optional[int] = None


# ===== Function Types =====

@dataclass
class FuncType:
    """Function type (signature)."""
    params: List[ValType]
    results: List[ValType]


# ===== Table Types =====

@dataclass
class TableType:
    """Table type."""
    element_type: RefType  # Only FUNCREF in MVP
    limits: Limits


# ===== Memory Types =====

@dataclass
class MemType:
    """Memory type."""
    limits: Limits


# ===== Global Types =====

@dataclass
class GlobalType:
    """Global variable type."""
    valtype: ValType
    mutable: bool


# ===== Instructions =====

class Opcode(IntEnum):
    """Supported WebAssembly opcodes (subset)."""
    END = 0x0B
    LOCAL_GET = 0x20
    LOCAL_SET = 0x21
    I32_CONST = 0x41
    I32_ADD = 0x6A
    CALL = 0x10


@dataclass
class Instruction:
    """WebAssembly instruction with immediate."""
    opcode: Opcode
    immediate: Optional[int] = None  # For i32.const, local.get, local.set, call


@dataclass
class Expr:
    """Expression (sequence of instructions ending with 'end')."""
    instructions: List[Instruction]


# ===== Imports =====

class ImportKind(IntEnum):
    """Import description kind."""
    FUNC = 0x00
    TABLE = 0x01
    MEM = 0x02
    GLOBAL = 0x03


@dataclass
class Import:
    """Import declaration."""
    module: str
    name: str
    kind: ImportKind
    # Type depends on kind:
    # FUNC: typeidx (int)
    # TABLE: TableType
    # MEM: MemType
    # GLOBAL: GlobalType
    typeidx: Optional[int] = None
    table_type: Optional[TableType] = None
    mem_type: Optional[MemType] = None
    global_type: Optional[GlobalType] = None


# ===== Exports =====

@dataclass
class Export:
    """Export declaration."""
    name: str
    kind: ImportKind  # Reuse ImportKind for export kind
    index: int


# ===== Globals =====

@dataclass
class Global:
    """Global variable definition."""
    type: GlobalType
    init: Expr


# ===== Element Segments =====

@dataclass
class ElementSegment:
    """Element segment (table initialization).

    Restricted to active mode for table 0 with i32.const offset.
    """
    table_idx: int  # Always 0 in our subset
    offset: Expr  # Must be i32.const followed by end
    init: List[int]  # Function indices


# ===== Data Segments =====

@dataclass
class DataSegment:
    """Data segment (memory initialization).

    Restricted to active mode for memory 0 with i32.const offset.
    """
    memory_idx: int  # Always 0 in our subset
    offset: Expr  # Must be i32.const followed by end
    init: bytes


# ===== Code (Function Bodies) =====

@dataclass
class LocalDecl:
    """Local variable declaration (count + type)."""
    count: int
    valtype: ValType


@dataclass
class FuncBody:
    """Function body (locals + expression)."""
    locals: List[LocalDecl]
    expr: Expr


# ===== Custom Sections =====

@dataclass
class CustomSection:
    """Custom section with name and raw data."""
    name: str
    data: bytes


# ===== Module =====

@dataclass
class Module:
    """Complete WebAssembly module."""
    # Section 1: Type
    types: List[FuncType] = field(default_factory=list)

    # Section 2: Import
    imports: List[Import] = field(default_factory=list)

    # Section 3: Function (type indices)
    functions: List[int] = field(default_factory=list)

    # Section 4: Table
    tables: List[TableType] = field(default_factory=list)

    # Section 5: Memory
    memories: List[MemType] = field(default_factory=list)

    # Section 6: Global
    globals: List[Global] = field(default_factory=list)

    # Section 7: Export
    exports: List[Export] = field(default_factory=list)

    # Section 8: Start
    start: Optional[int] = None

    # Section 9: Element
    elements: List[ElementSegment] = field(default_factory=list)

    # Section 10: Code (function bodies)
    code: List[FuncBody] = field(default_factory=list)

    # Section 11: Data
    data: List[DataSegment] = field(default_factory=list)

    # Section 12: Data Count
    data_count: Optional[int] = None

    # Section 0: Custom (can appear multiple times, anywhere)
    customs: List[CustomSection] = field(default_factory=list)
