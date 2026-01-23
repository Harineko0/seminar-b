"""
parser.py - Public API surface for WASM binary module parsing + structural validation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List, Union
from enum import Enum


# ----------------------------
# Public error / result types
# ----------------------------

class DecodeError(Exception):
    """Raised when bytes are not decodable under the supported WASM subset."""
    def __init__(self, message: str, *, offset: Optional[int] = None, code: str = "decode_error"):
        super().__init__(message)
        self.message = message
        self.offset = offset
        self.code = code


@dataclass(frozen=True)
class ValidationError:
    """A structural validation error found in a decoded module."""
    code: str
    message: str
    context: Optional[str] = None


@dataclass(frozen=True)
class Limits:
    """Resource limits to prevent pathological inputs."""
    max_module_bytes: int = 1_048_576  # 1 MiB
    max_section_bytes: int = 524_288   # 512 KiB
    max_vector_length: int = 50_000
    max_function_body_bytes: int = 65_536
    max_locals_per_function: int = 10_000
    max_custom_section_bytes: int = 262_144


# ----------------------------
# AST dataclasses
# ----------------------------

class ValType(Enum):
    I32 = 0x7F
    I64 = 0x7E


@dataclass(frozen=True)
class FuncType:
    params: List[ValType]
    results: List[ValType]


@dataclass(frozen=True)
class TableLimits:
    min: int
    max: Optional[int] = None


@dataclass(frozen=True)
class MemLimits:
    min: int
    max: Optional[int] = None


@dataclass(frozen=True)
class GlobalType:
    valtype: ValType
    mutable: bool


class ImportKind(Enum):
    FUNC = 0
    TABLE = 1
    MEM = 2
    GLOBAL = 3


@dataclass(frozen=True)
class ImportFunc:
    module: bytes
    name: bytes
    typeidx: int


@dataclass(frozen=True)
class ImportTable:
    module: bytes
    name: bytes
    limits: TableLimits


@dataclass(frozen=True)
class ImportMem:
    module: bytes
    name: bytes
    limits: MemLimits


@dataclass(frozen=True)
class ImportGlobal:
    module: bytes
    name: bytes
    globaltype: GlobalType


Import = Union[ImportFunc, ImportTable, ImportMem, ImportGlobal]


class ExportKind(Enum):
    FUNC = 0
    TABLE = 1
    MEM = 2
    GLOBAL = 3


@dataclass(frozen=True)
class Export:
    name: bytes
    kind: ExportKind
    index: int


@dataclass(frozen=True)
class Instruction:
    opcode: int
    immediate: Optional[int] = None


@dataclass(frozen=True)
class Expression:
    instructions: List[Instruction]


@dataclass(frozen=True)
class Global:
    globaltype: GlobalType
    init_expr: Expression


@dataclass(frozen=True)
class LocalDecl:
    count: int
    valtype: ValType


@dataclass(frozen=True)
class FuncBody:
    locals: List[LocalDecl]
    expr: Expression


@dataclass(frozen=True)
class ElemSegment:
    tableidx: int
    offset_expr: Expression
    init: List[int]


@dataclass(frozen=True)
class DataSegment:
    memidx: int
    offset_expr: Expression
    data: bytes


@dataclass(frozen=True)
class CustomSection:
    name: bytes
    data: bytes


@dataclass(frozen=True)
class Module:
    """Decoded WASM module AST."""
    raw_size: int
    types: List[FuncType] = field(default_factory=list)
    imports: List[Import] = field(default_factory=list)
    function_types: List[int] = field(default_factory=list)  # typeidx for each defined func
    tables: List[TableLimits] = field(default_factory=list)
    memories: List[MemLimits] = field(default_factory=list)
    globals: List[Global] = field(default_factory=list)
    exports: List[Export] = field(default_factory=list)
    start: Optional[int] = None
    elements: List[ElemSegment] = field(default_factory=list)
    code: List[FuncBody] = field(default_factory=list)
    data: List[DataSegment] = field(default_factory=list)
    data_count: Optional[int] = None
    customs: List[CustomSection] = field(default_factory=list)


# ----------------------------
# Binary reader
# ----------------------------

class BinaryReader:
    def __init__(self, data: bytes, limits: Limits):
        self.data = data
        self.pos = 0
        self.limits = limits

    def read_byte(self) -> int:
        if self.pos >= len(self.data):
            raise DecodeError("Unexpected end of data", offset=self.pos)
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_bytes(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise DecodeError(f"Cannot read {n} bytes", offset=self.pos)
        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result

    def read_u32_leb128(self) -> int:
        """Decode unsigned LEB128 as u32."""
        result = 0
        shift = 0
        for _ in range(5):  # u32 needs at most 5 bytes
            if self.pos >= len(self.data):
                raise DecodeError("Truncated LEB128", offset=self.pos)
            b = self.data[self.pos]
            self.pos += 1
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                # Check if overlong encoding
                if shift >= 32:
                    raise DecodeError("LEB128 overlong encoding", offset=self.pos - 1)
                if result > 0xFFFFFFFF:
                    raise DecodeError("LEB128 exceeds u32", offset=self.pos - 1)
                return result
            shift += 7
        raise DecodeError("LEB128 too long for u32", offset=self.pos)

    def read_s32_leb128(self) -> int:
        """Decode signed LEB128 as s32."""
        result = 0
        shift = 0
        for _ in range(5):  # s32 needs at most 5 bytes
            if self.pos >= len(self.data):
                raise DecodeError("Truncated signed LEB128", offset=self.pos)
            b = self.data[self.pos]
            self.pos += 1
            result |= (b & 0x7F) << shift
            shift += 7
            if (b & 0x80) == 0:
                # Sign extend
                if shift < 32 and (b & 0x40):
                    result |= (~0 << shift)
                # Convert to signed 32-bit
                if result >= 0x80000000:
                    result -= 0x100000000
                if result < -0x80000000 or result > 0x7FFFFFFF:
                    raise DecodeError("Signed LEB128 exceeds s32 range", offset=self.pos - 1)
                return result
        raise DecodeError("Signed LEB128 too long for s32", offset=self.pos)

    def read_name(self) -> bytes:
        """Read a name (length-prefixed byte string)."""
        length = self.read_u32_leb128()
        return self.read_bytes(length)

    def read_vector(self, reader_func, limit_name="vector"):
        """Read a vector of items."""
        count = self.read_u32_leb128()
        if count > self.limits.max_vector_length:
            raise DecodeError(f"{limit_name} length {count} exceeds limit {self.limits.max_vector_length}", offset=self.pos)
        items = []
        for _ in range(count):
            items.append(reader_func())
        return items

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def at_end(self) -> bool:
        return self.pos >= len(self.data)


# ----------------------------
# Decoders
# ----------------------------

def decode_valtype(reader: BinaryReader) -> ValType:
    b = reader.read_byte()
    if b == 0x7F:
        return ValType.I32
    elif b == 0x7E:
        return ValType.I64
    else:
        raise DecodeError(f"Unsupported valtype: 0x{b:02X}", offset=reader.pos - 1, code="unsupported_valtype")


def decode_functype(reader: BinaryReader) -> FuncType:
    tag = reader.read_byte()
    if tag != 0x60:
        raise DecodeError(f"Expected functype tag 0x60, got 0x{tag:02X}", offset=reader.pos - 1)
    params = reader.read_vector(lambda: decode_valtype(reader), "functype params")
    results = reader.read_vector(lambda: decode_valtype(reader), "functype results")
    return FuncType(params=params, results=results)


def decode_limits(reader: BinaryReader):
    flags = reader.read_byte()
    if flags == 0x00:
        min_val = reader.read_u32_leb128()
        return (min_val, None)
    elif flags == 0x01:
        min_val = reader.read_u32_leb128()
        max_val = reader.read_u32_leb128()
        return (min_val, max_val)
    else:
        raise DecodeError(f"Bad limits flag: 0x{flags:02X}", offset=reader.pos - 1, code="bad_limits_flag")


def decode_import(reader: BinaryReader) -> Import:
    module = reader.read_name()
    name = reader.read_name()
    kind = reader.read_byte()

    if kind == 0:  # func
        typeidx = reader.read_u32_leb128()
        return ImportFunc(module=module, name=name, typeidx=typeidx)
    elif kind == 1:  # table
        elemtype = reader.read_byte()
        if elemtype != 0x70:
            raise DecodeError(f"Unsupported table elemtype: 0x{elemtype:02X}", offset=reader.pos - 1, code="unsupported_table_elemtype")
        min_val, max_val = decode_limits(reader)
        return ImportTable(module=module, name=name, limits=TableLimits(min=min_val, max=max_val))
    elif kind == 2:  # mem
        min_val, max_val = decode_limits(reader)
        return ImportMem(module=module, name=name, limits=MemLimits(min=min_val, max=max_val))
    elif kind == 3:  # global
        valtype = decode_valtype(reader)
        mut = reader.read_byte()
        if mut == 0x00:
            mutable = False
        elif mut == 0x01:
            mutable = True
        else:
            raise DecodeError(f"Bad mutability: 0x{mut:02X}", offset=reader.pos - 1, code="bad_mutability")
        return ImportGlobal(module=module, name=name, globaltype=GlobalType(valtype=valtype, mutable=mutable))
    else:
        raise DecodeError(f"Unknown import kind: {kind}", offset=reader.pos - 1)


def decode_export(reader: BinaryReader) -> Export:
    name = reader.read_name()
    kind_byte = reader.read_byte()
    if kind_byte == 0:
        kind = ExportKind.FUNC
    elif kind_byte == 1:
        kind = ExportKind.TABLE
    elif kind_byte == 2:
        kind = ExportKind.MEM
    elif kind_byte == 3:
        kind = ExportKind.GLOBAL
    else:
        raise DecodeError(f"Unknown export kind: {kind_byte}", offset=reader.pos - 1)
    index = reader.read_u32_leb128()
    return Export(name=name, kind=kind, index=index)


def decode_expression(reader: BinaryReader, check_end: bool = True) -> Expression:
    """Decode a restricted expression (sequence of instructions ending with 0x0B)."""
    instructions = []
    while True:
        opcode = reader.read_byte()

        if opcode == 0x0B:  # end
            instructions.append(Instruction(opcode=opcode))
            break
        elif opcode == 0x41:  # i32.const
            imm = reader.read_s32_leb128()
            instructions.append(Instruction(opcode=opcode, immediate=imm))
        elif opcode == 0x20:  # local.get
            localidx = reader.read_u32_leb128()
            instructions.append(Instruction(opcode=opcode, immediate=localidx))
        elif opcode == 0x21:  # local.set
            localidx = reader.read_u32_leb128()
            instructions.append(Instruction(opcode=opcode, immediate=localidx))
        elif opcode == 0x6A:  # i32.add
            instructions.append(Instruction(opcode=opcode))
        elif opcode == 0x10:  # call
            funcidx = reader.read_u32_leb128()
            instructions.append(Instruction(opcode=opcode, immediate=funcidx))
        else:
            raise DecodeError(f"Unsupported opcode: 0x{opcode:02X}", offset=reader.pos - 1, code="unsupported_opcode")

    return Expression(instructions=instructions)


def decode_global(reader: BinaryReader) -> Global:
    valtype = decode_valtype(reader)
    mut = reader.read_byte()
    if mut == 0x00:
        mutable = False
    elif mut == 0x01:
        mutable = True
    else:
        raise DecodeError(f"Bad mutability: 0x{mut:02X}", offset=reader.pos - 1, code="bad_mutability")

    init_expr = decode_expression(reader)
    return Global(globaltype=GlobalType(valtype=valtype, mutable=mutable), init_expr=init_expr)


def decode_element_segment(reader: BinaryReader) -> ElemSegment:
    """Decode element segment (restricted to active mode with tableidx=0)."""
    tableidx = reader.read_u32_leb128()
    if tableidx != 0:
        raise DecodeError(f"Unsupported element form: tableidx={tableidx}", offset=reader.pos, code="unsupported_element_form")

    # Offset expr must be exactly i32.const followed by end
    offset_start = reader.pos
    offset_expr = decode_expression(reader)

    # Validate it's exactly i32.const + end
    if len(offset_expr.instructions) != 2:
        raise DecodeError("Element offset_expr must be exactly i32.const + end", offset=offset_start, code="unsupported_element_form")
    if offset_expr.instructions[0].opcode != 0x41 or offset_expr.instructions[1].opcode != 0x0B:
        raise DecodeError("Element offset_expr must be i32.const + end", offset=offset_start, code="unsupported_element_form")

    init = reader.read_vector(lambda: reader.read_u32_leb128(), "element init")
    return ElemSegment(tableidx=tableidx, offset_expr=offset_expr, init=init)


def decode_code_body(reader: BinaryReader, limits: Limits) -> FuncBody:
    """Decode a function body."""
    body_size = reader.read_u32_leb128()
    if body_size > limits.max_function_body_bytes:
        raise DecodeError(f"Function body size {body_size} exceeds limit {limits.max_function_body_bytes}", offset=reader.pos)

    body_start = reader.pos
    body_data = reader.read_bytes(body_size)
    body_reader = BinaryReader(body_data, limits)

    # Decode locals
    locals = []
    local_count = body_reader.read_u32_leb128()
    total_locals = 0
    for _ in range(local_count):
        count = body_reader.read_u32_leb128()
        valtype = decode_valtype(body_reader)
        total_locals += count
        if total_locals > limits.max_locals_per_function:
            raise DecodeError(f"Total locals {total_locals} exceeds limit {limits.max_locals_per_function}", offset=body_start)
        locals.append(LocalDecl(count=count, valtype=valtype))

    # Decode expression
    expr = decode_expression(body_reader)

    # Check that we consumed exactly the body size
    if not body_reader.at_end():
        raise DecodeError("Trailing bytes in function body", offset=body_start, code="trailing_bytes_in_expr")

    return FuncBody(locals=locals, expr=expr)


def decode_data_segment(reader: BinaryReader) -> DataSegment:
    """Decode data segment (restricted to active mode with memidx=0)."""
    memidx = reader.read_u32_leb128()
    if memidx != 0:
        raise DecodeError(f"Unsupported data form: memidx={memidx}", offset=reader.pos, code="unsupported_data_form")

    # Offset expr must be exactly i32.const followed by end
    offset_start = reader.pos
    offset_expr = decode_expression(reader)

    # Validate it's exactly i32.const + end
    if len(offset_expr.instructions) != 2:
        raise DecodeError("Data offset_expr must be exactly i32.const + end", offset=offset_start, code="unsupported_data_form")
    if offset_expr.instructions[0].opcode != 0x41 or offset_expr.instructions[1].opcode != 0x0B:
        raise DecodeError("Data offset_expr must be i32.const + end", offset=offset_start, code="unsupported_data_form")

    # Read data bytes
    data_len = reader.read_u32_leb128()
    data = reader.read_bytes(data_len)

    return DataSegment(memidx=memidx, offset_expr=offset_expr, data=data)


# ----------------------------
# Section decoders
# ----------------------------

def decode_type_section(reader: BinaryReader) -> List[FuncType]:
    return reader.read_vector(lambda: decode_functype(reader), "type section")


def decode_import_section(reader: BinaryReader) -> List[Import]:
    return reader.read_vector(lambda: decode_import(reader), "import section")


def decode_function_section(reader: BinaryReader) -> List[int]:
    return reader.read_vector(lambda: reader.read_u32_leb128(), "function section")


def decode_table_section(reader: BinaryReader) -> List[TableLimits]:
    def read_table():
        elemtype = reader.read_byte()
        if elemtype != 0x70:
            raise DecodeError(f"Unsupported table elemtype: 0x{elemtype:02X}", offset=reader.pos - 1, code="unsupported_table_elemtype")
        min_val, max_val = decode_limits(reader)
        return TableLimits(min=min_val, max=max_val)
    return reader.read_vector(read_table, "table section")


def decode_memory_section(reader: BinaryReader) -> List[MemLimits]:
    def read_memory():
        min_val, max_val = decode_limits(reader)
        return MemLimits(min=min_val, max=max_val)
    return reader.read_vector(read_memory, "memory section")


def decode_global_section(reader: BinaryReader) -> List[Global]:
    return reader.read_vector(lambda: decode_global(reader), "global section")


def decode_export_section(reader: BinaryReader) -> List[Export]:
    return reader.read_vector(lambda: decode_export(reader), "export section")


def decode_element_section(reader: BinaryReader) -> List[ElemSegment]:
    return reader.read_vector(lambda: decode_element_segment(reader), "element section")


def decode_code_section(reader: BinaryReader, limits: Limits) -> List[FuncBody]:
    return reader.read_vector(lambda: decode_code_body(reader, limits), "code section")


def decode_data_section(reader: BinaryReader) -> List[DataSegment]:
    return reader.read_vector(lambda: decode_data_segment(reader), "data section")


# ----------------------------
# Main decoder
# ----------------------------

def decode_module(data: bytes, *, limits: Limits = Limits()) -> Module:
    """
    Decode a WASM binary module (subset) into a Module AST.

    Raises:
        DecodeError: on malformed input or unsupported forms.
    """
    if len(data) > limits.max_module_bytes:
        raise DecodeError(f"Module size {len(data)} exceeds limit {limits.max_module_bytes}")

    reader = BinaryReader(data, limits)

    # Check magic and version
    magic = reader.read_bytes(4)
    if magic != b'\x00asm':
        raise DecodeError(f"Invalid magic bytes: {magic.hex()}", offset=0)

    version = reader.read_bytes(4)
    if version != b'\x01\x00\x00\x00':
        raise DecodeError(f"Invalid version: {version.hex()}", offset=4)

    # Collect module data
    types = []
    imports = []
    function_types = []
    tables = []
    memories = []
    globals = []
    exports = []
    start = None
    elements = []
    code = []
    data_segs = []
    data_count = None
    customs = []

    # Track section order (non-custom sections)
    last_section_id = -1
    section_seen = {}

    # Parse sections
    while not reader.at_end():
        section_id = reader.read_byte()
        payload_len = reader.read_u32_leb128()

        # Check payload size limit
        if section_id == 0:  # Custom section
            if payload_len > limits.max_custom_section_bytes:
                raise DecodeError(f"Custom section size {payload_len} exceeds limit {limits.max_custom_section_bytes}", offset=reader.pos)
        else:
            if payload_len > limits.max_section_bytes:
                raise DecodeError(f"Section {section_id} size {payload_len} exceeds limit {limits.max_section_bytes}", offset=reader.pos)

        section_start = reader.pos
        section_data = reader.read_bytes(payload_len)
        section_reader = BinaryReader(section_data, limits)

        # Custom sections can appear anywhere
        if section_id == 0:
            name = section_reader.read_name()
            custom_data = section_data[section_reader.pos:]
            customs.append(CustomSection(name=name, data=custom_data))
            continue

        # Check section ordering for non-custom sections
        if section_id in section_seen:
            raise DecodeError(f"Duplicate section {section_id}", offset=section_start - 5, code="section_order")

        if section_id < last_section_id:
            raise DecodeError(f"Section {section_id} out of order (last was {last_section_id})", offset=section_start - 5, code="section_order")

        section_seen[section_id] = True
        last_section_id = section_id

        # Decode section based on ID
        if section_id == 1:  # Type
            types.extend(decode_type_section(section_reader))
        elif section_id == 2:  # Import
            imports.extend(decode_import_section(section_reader))
        elif section_id == 3:  # Function
            function_types.extend(decode_function_section(section_reader))
        elif section_id == 4:  # Table
            tables.extend(decode_table_section(section_reader))
        elif section_id == 5:  # Memory
            memories.extend(decode_memory_section(section_reader))
        elif section_id == 6:  # Global
            globals.extend(decode_global_section(section_reader))
        elif section_id == 7:  # Export
            exports.extend(decode_export_section(section_reader))
        elif section_id == 8:  # Start
            start = section_reader.read_u32_leb128()
        elif section_id == 9:  # Element
            elements.extend(decode_element_section(section_reader))
        elif section_id == 10:  # Code
            code.extend(decode_code_section(section_reader, limits))
        elif section_id == 11:  # Data
            data_segs.extend(decode_data_section(section_reader))
        elif section_id == 12:  # DataCount
            data_count = section_reader.read_u32_leb128()
        else:
            raise DecodeError(f"Unknown section ID: {section_id}", offset=section_start - 5, code="unknown_section_id")

        # Check that section was fully consumed
        if not section_reader.at_end():
            raise DecodeError(f"Section {section_id} has leftover bytes", offset=section_start, code="section_size_mismatch")

    return Module(
        raw_size=len(data),
        types=types,
        imports=imports,
        function_types=function_types,
        tables=tables,
        memories=memories,
        globals=globals,
        exports=exports,
        start=start,
        elements=elements,
        code=code,
        data=data_segs,
        data_count=data_count,
        customs=customs
    )


# ----------------------------
# Validator
# ----------------------------

def validate_module(module: Module) -> List[ValidationError]:
    """
    Perform structural validation on a decoded module.

    Returns:
        List[ValidationError]: empty if valid.
    """
    errors = []

    # Compute index spaces
    imported_funcs = sum(1 for imp in module.imports if isinstance(imp, ImportFunc))
    defined_funcs = len(module.function_types)
    funcs_total = imported_funcs + defined_funcs

    imported_tables = sum(1 for imp in module.imports if isinstance(imp, ImportTable))
    defined_tables = len(module.tables)
    tables_total = imported_tables + defined_tables

    imported_mems = sum(1 for imp in module.imports if isinstance(imp, ImportMem))
    defined_mems = len(module.memories)
    mems_total = imported_mems + defined_mems

    imported_globals = sum(1 for imp in module.imports if isinstance(imp, ImportGlobal))
    defined_globals = len(module.globals)
    globals_total = imported_globals + defined_globals

    # Validate limits (min <= max)
    for i, table in enumerate(module.tables):
        if table.max is not None and table.min > table.max:
            errors.append(ValidationError(code="limits_min_gt_max", message=f"Table {i}: min {table.min} > max {table.max}"))

    for i, mem in enumerate(module.memories):
        if mem.max is not None and mem.min > mem.max:
            errors.append(ValidationError(code="limits_min_gt_max", message=f"Memory {i}: min {mem.min} > max {mem.max}"))

    for imp in module.imports:
        if isinstance(imp, ImportTable):
            if imp.limits.max is not None and imp.limits.min > imp.limits.max:
                errors.append(ValidationError(code="limits_min_gt_max", message=f"Imported table {imp.name}: min > max"))
        elif isinstance(imp, ImportMem):
            if imp.limits.max is not None and imp.limits.min > imp.limits.max:
                errors.append(ValidationError(code="limits_min_gt_max", message=f"Imported memory {imp.name}: min > max"))

    # Validate import type indices
    for imp in module.imports:
        if isinstance(imp, ImportFunc):
            if imp.typeidx >= len(module.types):
                errors.append(ValidationError(code="type_index_out_of_range", message=f"Import func typeidx {imp.typeidx} >= {len(module.types)}"))

    # Validate function type indices
    for i, typeidx in enumerate(module.function_types):
        if typeidx >= len(module.types):
            errors.append(ValidationError(code="type_index_out_of_range", message=f"Function {i} typeidx {typeidx} >= {len(module.types)}"))

    # Validate exports
    export_names = {}
    for exp in module.exports:
        # Check for duplicate export names
        if exp.name in export_names:
            errors.append(ValidationError(code="duplicate_export_name", message=f"Duplicate export name: {exp.name}"))
        export_names[exp.name] = True

        # Check index ranges
        if exp.kind == ExportKind.FUNC:
            if exp.index >= funcs_total:
                errors.append(ValidationError(code="index_out_of_range", message=f"Export func index {exp.index} >= {funcs_total}"))
        elif exp.kind == ExportKind.TABLE:
            if exp.index >= tables_total:
                errors.append(ValidationError(code="index_out_of_range", message=f"Export table index {exp.index} >= {tables_total}"))
        elif exp.kind == ExportKind.MEM:
            if exp.index >= mems_total:
                errors.append(ValidationError(code="index_out_of_range", message=f"Export mem index {exp.index} >= {mems_total}"))
        elif exp.kind == ExportKind.GLOBAL:
            if exp.index >= globals_total:
                errors.append(ValidationError(code="index_out_of_range", message=f"Export global index {exp.index} >= {globals_total}"))

    # Validate start function
    if module.start is not None:
        if module.start >= funcs_total:
            errors.append(ValidationError(code="index_out_of_range", message=f"Start funcidx {module.start} >= {funcs_total}"))
        else:
            # Get the type of the start function
            if module.start < imported_funcs:
                # It's an imported function
                func_imports = [imp for imp in module.imports if isinstance(imp, ImportFunc)]
                typeidx = func_imports[module.start].typeidx
            else:
                # It's a defined function
                typeidx = module.function_types[module.start - imported_funcs]

            if typeidx < len(module.types):
                func_type = module.types[typeidx]
                if len(func_type.params) != 0 or len(func_type.results) != 0:
                    errors.append(ValidationError(code="bad_start_signature", message=f"Start function has non-empty signature"))

    # Validate element segments
    for i, elem in enumerate(module.elements):
        for funcidx in elem.init:
            if funcidx >= funcs_total:
                errors.append(ValidationError(code="index_out_of_range", message=f"Element segment {i} funcidx {funcidx} >= {funcs_total}"))

    # Validate code section
    if len(module.code) != len(module.function_types):
        errors.append(ValidationError(code="func_code_count_mismatch", message=f"Code count {len(module.code)} != function count {len(module.function_types)}"))

    # Validate local and call indices in function bodies
    for func_idx, (typeidx, body) in enumerate(zip(module.function_types, module.code)):
        if typeidx >= len(module.types):
            continue  # Already reported above

        func_type = module.types[typeidx]
        num_params = len(func_type.params)
        num_locals = sum(decl.count for decl in body.locals)
        total_locals = num_params + num_locals

        # Check local indices
        for instr in body.expr.instructions:
            if instr.opcode in (0x20, 0x21):  # local.get, local.set
                if instr.immediate >= total_locals:
                    errors.append(ValidationError(
                        code="local_index_out_of_range",
                        message=f"Function {imported_funcs + func_idx}: local index {instr.immediate} >= {total_locals}"
                    ))
            elif instr.opcode == 0x10:  # call
                if instr.immediate >= funcs_total:
                    errors.append(ValidationError(
                        code="index_out_of_range",
                        message=f"Function {imported_funcs + func_idx}: call funcidx {instr.immediate} >= {funcs_total}"
                    ))

    # Validate data count
    if module.data_count is not None:
        if module.data_count != len(module.data):
            errors.append(ValidationError(code="data_count_mismatch", message=f"Data count {module.data_count} != data segments {len(module.data)}"))

    return errors


# ----------------------------
# Public API functions
# ----------------------------

def decode_and_validate(data: bytes, *, limits: Limits = Limits()) -> Module:
    """
    Convenience API: decode, then validate; raise on any validation errors.
    """
    module = decode_module(data, limits=limits)
    errors = validate_module(module)
    if errors:
        # Raise a single exception with a readable summary
        msg = "Validation failed:\n" + "\n".join(f"- {e.code}: {e.message}" for e in errors[:20])
        raise ValueError(msg)
    return module
