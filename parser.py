"""
parser.py - Public API surface for WASM binary module parsing + structural validation.
"""

from __future__ import annotations

from dataclasses import dataclass
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
# AST data structures
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
class MemoryLimits:
    min: int
    max: Optional[int] = None


@dataclass(frozen=True)
class TableType:
    limits: TableLimits


@dataclass(frozen=True)
class MemoryType:
    limits: MemoryLimits


@dataclass(frozen=True)
class GlobalType:
    valtype: ValType
    mutable: bool


# Import types
@dataclass(frozen=True)
class ImportFunc:
    module: str
    name: str
    typeidx: int


@dataclass(frozen=True)
class ImportTable:
    module: str
    name: str
    type: TableType


@dataclass(frozen=True)
class ImportMemory:
    module: str
    name: str
    type: MemoryType


@dataclass(frozen=True)
class ImportGlobal:
    module: str
    name: str
    type: GlobalType


Import = Union[ImportFunc, ImportTable, ImportMemory, ImportGlobal]


# Instructions
@dataclass(frozen=True)
class I32Const:
    immediate: int


@dataclass(frozen=True)
class LocalGet:
    localidx: int


@dataclass(frozen=True)
class LocalSet:
    localidx: int


@dataclass(frozen=True)
class I32Add:
    pass


@dataclass(frozen=True)
class Call:
    funcidx: int


@dataclass(frozen=True)
class End:
    pass


Instruction = Union[I32Const, LocalGet, LocalSet, I32Add, Call, End]


@dataclass(frozen=True)
class Expression:
    instructions: List[Instruction]


@dataclass(frozen=True)
class Global:
    type: GlobalType
    init: Expression


@dataclass(frozen=True)
class Export:
    name: str
    kind: int  # 0=func, 1=table, 2=mem, 3=global
    index: int


@dataclass(frozen=True)
class Element:
    tableidx: int
    offset: Expression
    init: List[int]


@dataclass(frozen=True)
class LocalDecl:
    count: int
    valtype: ValType


@dataclass(frozen=True)
class FuncBody:
    locals: List[LocalDecl]
    expr: Expression


@dataclass(frozen=True)
class Data:
    memidx: int
    offset: Expression
    init: bytes


@dataclass(frozen=True)
class CustomSection:
    name: str
    data: bytes


@dataclass(frozen=True)
class Module:
    """Decoded WASM module AST."""
    raw_size: int
    types: List[FuncType]
    imports: List[Import]
    functions: List[int]  # type indices
    tables: List[TableType]
    memories: List[MemoryType]
    globals: List[Global]
    exports: List[Export]
    start: Optional[int]
    elements: List[Element]
    code: List[FuncBody]
    data: List[Data]
    data_count: Optional[int]
    customs: List[CustomSection]


# ----------------------------
# Binary reader helper
# ----------------------------

class BinaryReader:
    def __init__(self, data: bytes, limits: Limits):
        self.data = data
        self.pos = 0
        self.limits = limits

    def eof(self) -> bool:
        return self.pos >= len(self.data)

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def read_byte(self) -> int:
        if self.pos >= len(self.data):
            raise DecodeError("Unexpected end of input", offset=self.pos)
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_bytes(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise DecodeError("Truncated input: unexpected end of input", offset=self.pos)
        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result

    def read_u32(self) -> int:
        """Decode unsigned LEB128 as u32."""
        result = 0
        shift = 0
        while True:
            if shift > 28:
                raise DecodeError("LEB128 u32 overflow", offset=self.pos)
            b = self.read_byte()
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
        if result > 0xFFFFFFFF:
            raise DecodeError("LEB128 u32 overflow", offset=self.pos)
        return result

    def read_s32(self) -> int:
        """Decode signed LEB128 as s32."""
        result = 0
        shift = 0
        while True:
            if shift > 28:
                raise DecodeError("LEB128 s32 overflow", offset=self.pos)
            b = self.read_byte()
            result |= (b & 0x7F) << shift
            shift += 7
            if (b & 0x80) == 0:
                # Sign extend
                if shift < 32 and (b & 0x40):
                    result |= -(1 << shift)
                break
        # Ensure it fits in s32
        if result < -2147483648 or result > 2147483647:
            raise DecodeError("LEB128 s32 overflow", offset=self.pos)
        return result

    def read_name(self) -> str:
        """Read a name (length-prefixed bytes, treated as UTF-8 for convenience)."""
        length = self.read_u32()
        if length > self.limits.max_section_bytes:
            raise DecodeError(f"Name too large: {length}", offset=self.pos)
        raw = self.read_bytes(length)
        # Spec says names are opaque bytes, but we decode as UTF-8 for convenience
        # and fall back to latin-1 if invalid UTF-8
        try:
            return raw.decode('utf-8')
        except UnicodeDecodeError:
            return raw.decode('latin-1')

    def read_vector(self, reader_fn, limit: Optional[int] = None):
        """Read a vector: count followed by elements."""
        count = self.read_u32()
        if limit is not None and count > limit:
            raise DecodeError(f"Vector length {count} exceeds limit {limit}", offset=self.pos)
        return [reader_fn() for _ in range(count)]


# ----------------------------
# Decoders for each section
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
        raise DecodeError(f"Invalid function type tag: 0x{tag:02X}", offset=reader.pos - 1)
    params = reader.read_vector(lambda: decode_valtype(reader), reader.limits.max_vector_length)
    results = reader.read_vector(lambda: decode_valtype(reader), reader.limits.max_vector_length)
    return FuncType(params=params, results=results)


def decode_limits(reader: BinaryReader) -> tuple[int, Optional[int]]:
    flags = reader.read_byte()
    if flags == 0x00:
        min_val = reader.read_u32()
        return (min_val, None)
    elif flags == 0x01:
        min_val = reader.read_u32()
        max_val = reader.read_u32()
        return (min_val, max_val)
    else:
        raise DecodeError(f"Bad limits flag: 0x{flags:02X}", offset=reader.pos - 1, code="bad_limits_flag")


def decode_expression(reader: BinaryReader, max_bytes: int) -> Expression:
    """Decode a restricted expression (must end with 0x0B)."""
    start_pos = reader.pos
    instructions: List[Instruction] = []

    while True:
        if reader.pos - start_pos > max_bytes:
            raise DecodeError("Expression too large", offset=reader.pos)

        opcode = reader.read_byte()

        if opcode == 0x0B:  # end
            instructions.append(End())
            break
        elif opcode == 0x41:  # i32.const
            immediate = reader.read_s32()
            instructions.append(I32Const(immediate=immediate))
        elif opcode == 0x20:  # local.get
            localidx = reader.read_u32()
            instructions.append(LocalGet(localidx=localidx))
        elif opcode == 0x21:  # local.set
            localidx = reader.read_u32()
            instructions.append(LocalSet(localidx=localidx))
        elif opcode == 0x6A:  # i32.add
            instructions.append(I32Add())
        elif opcode == 0x10:  # call
            funcidx = reader.read_u32()
            instructions.append(Call(funcidx=funcidx))
        else:
            raise DecodeError(f"Unsupported opcode: 0x{opcode:02X}", offset=reader.pos - 1, code="unsupported_opcode")

    return Expression(instructions=instructions)


def decode_type_section(reader: BinaryReader) -> List[FuncType]:
    return reader.read_vector(lambda: decode_functype(reader), reader.limits.max_vector_length)


def decode_import_section(reader: BinaryReader) -> List[Import]:
    def read_import() -> Import:
        module = reader.read_name()
        name = reader.read_name()
        kind = reader.read_byte()

        if kind == 0x00:  # func
            typeidx = reader.read_u32()
            return ImportFunc(module=module, name=name, typeidx=typeidx)
        elif kind == 0x01:  # table
            elemtype = reader.read_byte()
            if elemtype != 0x70:
                raise DecodeError(f"Unsupported table elemtype: 0x{elemtype:02X}", code="unsupported_table_elemtype")
            min_val, max_val = decode_limits(reader)
            return ImportTable(module=module, name=name, type=TableType(limits=TableLimits(min=min_val, max=max_val)))
        elif kind == 0x02:  # memory
            min_val, max_val = decode_limits(reader)
            return ImportMemory(module=module, name=name, type=MemoryType(limits=MemoryLimits(min=min_val, max=max_val)))
        elif kind == 0x03:  # global
            valtype = decode_valtype(reader)
            mut = reader.read_byte()
            if mut not in (0x00, 0x01):
                raise DecodeError(f"Bad mutability: 0x{mut:02X}", code="bad_mutability")
            return ImportGlobal(module=module, name=name, type=GlobalType(valtype=valtype, mutable=(mut == 0x01)))
        else:
            raise DecodeError(f"Unknown import kind: 0x{kind:02X}")

    return reader.read_vector(read_import, reader.limits.max_vector_length)


def decode_function_section(reader: BinaryReader) -> List[int]:
    return reader.read_vector(lambda: reader.read_u32(), reader.limits.max_vector_length)


def decode_table_section(reader: BinaryReader) -> List[TableType]:
    def read_table() -> TableType:
        elemtype = reader.read_byte()
        if elemtype != 0x70:
            raise DecodeError(f"Unsupported table elemtype: 0x{elemtype:02X}", code="unsupported_table_elemtype")
        min_val, max_val = decode_limits(reader)
        return TableType(limits=TableLimits(min=min_val, max=max_val))

    return reader.read_vector(read_table, reader.limits.max_vector_length)


def decode_memory_section(reader: BinaryReader) -> List[MemoryType]:
    def read_memory() -> MemoryType:
        min_val, max_val = decode_limits(reader)
        return MemoryType(limits=MemoryLimits(min=min_val, max=max_val))

    return reader.read_vector(read_memory, reader.limits.max_vector_length)


def decode_global_section(reader: BinaryReader) -> List[Global]:
    def read_global() -> Global:
        valtype = decode_valtype(reader)
        mut = reader.read_byte()
        if mut not in (0x00, 0x01):
            raise DecodeError(f"Bad mutability: 0x{mut:02X}", code="bad_mutability")
        init_expr = decode_expression(reader, reader.limits.max_function_body_bytes)
        return Global(type=GlobalType(valtype=valtype, mutable=(mut == 0x01)), init=init_expr)

    return reader.read_vector(read_global, reader.limits.max_vector_length)


def decode_export_section(reader: BinaryReader) -> List[Export]:
    def read_export() -> Export:
        name = reader.read_name()
        kind = reader.read_byte()
        index = reader.read_u32()
        return Export(name=name, kind=kind, index=index)

    return reader.read_vector(read_export, reader.limits.max_vector_length)


def decode_start_section(reader: BinaryReader) -> int:
    return reader.read_u32()


def decode_element_section(reader: BinaryReader) -> List[Element]:
    def read_element() -> Element:
        tableidx = reader.read_u32()
        if tableidx != 0:
            raise DecodeError(f"Unsupported element form: tableidx={tableidx}", code="unsupported_element_form")

        # offset_expr must be exactly: i32.const <val> ; end
        offset_expr = decode_expression(reader, reader.limits.max_function_body_bytes)
        if len(offset_expr.instructions) != 2:
            raise DecodeError("Unsupported element form: offset must be i32.const + end", code="unsupported_element_form")
        if not isinstance(offset_expr.instructions[0], I32Const):
            raise DecodeError("Unsupported element form: offset must be i32.const + end", code="unsupported_element_form")
        if not isinstance(offset_expr.instructions[1], End):
            raise DecodeError("Unsupported element form: offset must be i32.const + end", code="unsupported_element_form")

        init = reader.read_vector(lambda: reader.read_u32(), reader.limits.max_vector_length)
        return Element(tableidx=tableidx, offset=offset_expr, init=init)

    return reader.read_vector(read_element, reader.limits.max_vector_length)


def decode_code_section(reader: BinaryReader) -> List[FuncBody]:
    def read_func_body() -> FuncBody:
        body_size = reader.read_u32()
        if body_size > reader.limits.max_function_body_bytes:
            raise DecodeError(f"Function body too large: {body_size}", offset=reader.pos)

        body_start = reader.pos

        # Read locals
        def read_local_decl() -> LocalDecl:
            count = reader.read_u32()
            valtype = decode_valtype(reader)
            return LocalDecl(count=count, valtype=valtype)

        locals = reader.read_vector(read_local_decl, reader.limits.max_vector_length)

        # Validate total locals count
        total_locals = sum(decl.count for decl in locals)
        if total_locals > reader.limits.max_locals_per_function:
            raise DecodeError(f"Too many locals: {total_locals}", offset=reader.pos)

        # Read expression
        expr = decode_expression(reader, reader.limits.max_function_body_bytes)

        # Check exact body size
        body_end = reader.pos
        actual_size = body_end - body_start
        if actual_size != body_size:
            raise DecodeError(f"Function body size mismatch: expected {body_size}, got {actual_size}",
                            offset=body_start, code="section_size_mismatch")

        return FuncBody(locals=locals, expr=expr)

    return reader.read_vector(read_func_body, reader.limits.max_vector_length)


def decode_data_section(reader: BinaryReader) -> List[Data]:
    def read_data() -> Data:
        memidx = reader.read_u32()
        if memidx != 0:
            raise DecodeError(f"Unsupported data form: memidx={memidx}", code="unsupported_data_form")

        # offset_expr must be exactly: i32.const <val> ; end
        offset_expr = decode_expression(reader, reader.limits.max_function_body_bytes)
        if len(offset_expr.instructions) != 2:
            raise DecodeError("Unsupported data form: offset must be i32.const + end", code="unsupported_data_form")
        if not isinstance(offset_expr.instructions[0], I32Const):
            raise DecodeError("Unsupported data form: offset must be i32.const + end", code="unsupported_data_form")
        if not isinstance(offset_expr.instructions[1], End):
            raise DecodeError("Unsupported data form: offset must be i32.const + end", code="unsupported_data_form")

        byte_len = reader.read_u32()
        if byte_len > reader.limits.max_section_bytes:
            raise DecodeError(f"Data segment too large: {byte_len}", offset=reader.pos)
        init_bytes = reader.read_bytes(byte_len)
        return Data(memidx=memidx, offset=offset_expr, init=init_bytes)

    return reader.read_vector(read_data, reader.limits.max_vector_length)


def decode_data_count_section(reader: BinaryReader) -> int:
    return reader.read_u32()


def decode_custom_section(reader: BinaryReader, payload_len: int) -> CustomSection:
    if payload_len > reader.limits.max_custom_section_bytes:
        raise DecodeError(f"Custom section too large: {payload_len}", offset=reader.pos)

    start_pos = reader.pos
    name = reader.read_name()
    name_bytes_consumed = reader.pos - start_pos
    data_len = payload_len - name_bytes_consumed

    if data_len < 0:
        raise DecodeError("Custom section name exceeds payload length", offset=start_pos)

    data = reader.read_bytes(data_len)
    return CustomSection(name=name, data=data)


# ----------------------------
# Main decoder
# ----------------------------

def decode_module(data: bytes, *, limits: Limits = Limits()) -> Module:
    """
    Decode a WASM binary module (subset) into a Module AST.

    Raises:
        DecodeError: on malformed input or unsupported forms.
    """
    # Check module size limit
    if len(data) > limits.max_module_bytes:
        raise DecodeError(f"Module too large: {len(data)} exceeds {limits.max_module_bytes}")

    reader = BinaryReader(data, limits)

    # Check preamble
    magic = reader.read_bytes(4)
    if magic != b'\x00asm':
        raise DecodeError("Invalid magic number")

    version = reader.read_bytes(4)
    if version != b'\x01\x00\x00\x00':
        raise DecodeError("Invalid version")

    # Initialize module components
    types: List[FuncType] = []
    imports: List[Import] = []
    functions: List[int] = []
    tables: List[TableType] = []
    memories: List[MemoryType] = []
    globals: List[Global] = []
    exports: List[Export] = []
    start: Optional[int] = None
    elements: List[Element] = []
    code: List[FuncBody] = []
    data_segments: List[Data] = []
    data_count: Optional[int] = None
    customs: List[CustomSection] = []

    # Track last non-custom section for ordering
    last_section_id = -1

    # Read sections
    while not reader.eof():
        section_id = reader.read_byte()
        payload_len = reader.read_u32()

        if payload_len > limits.max_section_bytes and section_id != 0:
            raise DecodeError(f"Section {section_id} payload too large: {payload_len}", offset=reader.pos)

        section_start = reader.pos

        # Custom sections can appear anywhere
        if section_id == 0:
            custom = decode_custom_section(reader, payload_len)
            customs.append(custom)
        else:
            # Check section ordering
            if section_id <= last_section_id:
                raise DecodeError(f"Section {section_id} out of order (last was {last_section_id})",
                                offset=section_start - 5, code="section_order")
            last_section_id = section_id

            # Decode based on section ID
            if section_id == 1:  # Type
                types = decode_type_section(reader)
            elif section_id == 2:  # Import
                imports = decode_import_section(reader)
            elif section_id == 3:  # Function
                functions = decode_function_section(reader)
            elif section_id == 4:  # Table
                tables = decode_table_section(reader)
            elif section_id == 5:  # Memory
                memories = decode_memory_section(reader)
            elif section_id == 6:  # Global
                globals = decode_global_section(reader)
            elif section_id == 7:  # Export
                exports = decode_export_section(reader)
            elif section_id == 8:  # Start
                start = decode_start_section(reader)
            elif section_id == 9:  # Element
                elements = decode_element_section(reader)
            elif section_id == 10:  # Code
                code = decode_code_section(reader)
            elif section_id == 11:  # Data
                data_segments = decode_data_section(reader)
            elif section_id == 12:  # Data Count
                data_count = decode_data_count_section(reader)
            else:
                raise DecodeError(f"Unknown section id: {section_id}", offset=section_start - 5, code="unknown_section_id")

        # Verify we consumed exactly the payload
        section_end = reader.pos
        actual_len = section_end - section_start
        if actual_len != payload_len:
            raise DecodeError(f"Section {section_id} size mismatch: expected {payload_len}, got {actual_len}",
                            offset=section_start, code="section_size_mismatch")

    return Module(
        raw_size=len(data),
        types=types,
        imports=imports,
        functions=functions,
        tables=tables,
        memories=memories,
        globals=globals,
        exports=exports,
        start=start,
        elements=elements,
        code=code,
        data=data_segments,
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
    errors: List[ValidationError] = []

    # Compute index spaces
    imported_funcs = sum(1 for imp in module.imports if isinstance(imp, ImportFunc))
    imported_tables = sum(1 for imp in module.imports if isinstance(imp, ImportTable))
    imported_mems = sum(1 for imp in module.imports if isinstance(imp, ImportMemory))
    imported_globals = sum(1 for imp in module.imports if isinstance(imp, ImportGlobal))

    funcs_total = imported_funcs + len(module.functions)
    tables_total = imported_tables + len(module.tables)
    mems_total = imported_mems + len(module.memories)
    globals_total = imported_globals + len(module.globals)

    # Validate limits (min <= max)
    for i, table in enumerate(module.tables):
        if table.limits.max is not None and table.limits.min > table.limits.max:
            errors.append(ValidationError(
                code="limits_min_gt_max",
                message=f"Table {i}: min ({table.limits.min}) > max ({table.limits.max})",
                context=f"table[{i}]"
            ))

    for i, memory in enumerate(module.memories):
        if memory.limits.max is not None and memory.limits.min > memory.limits.max:
            errors.append(ValidationError(
                code="limits_min_gt_max",
                message=f"Memory {i}: min ({memory.limits.min}) > max ({memory.limits.max})",
                context=f"memory[{i}]"
            ))

    for imp in module.imports:
        if isinstance(imp, ImportTable):
            if imp.type.limits.max is not None and imp.type.limits.min > imp.type.limits.max:
                errors.append(ValidationError(
                    code="limits_min_gt_max",
                    message=f"Import table {imp.name}: min > max",
                    context=f"import.{imp.module}.{imp.name}"
                ))
        elif isinstance(imp, ImportMemory):
            if imp.type.limits.max is not None and imp.type.limits.min > imp.type.limits.max:
                errors.append(ValidationError(
                    code="limits_min_gt_max",
                    message=f"Import memory {imp.name}: min > max",
                    context=f"import.{imp.module}.{imp.name}"
                ))

    # Validate type indices in imports
    for imp in module.imports:
        if isinstance(imp, ImportFunc):
            if imp.typeidx >= len(module.types):
                errors.append(ValidationError(
                    code="type_index_out_of_range",
                    message=f"Import func {imp.name}: type index {imp.typeidx} out of range (>= {len(module.types)})",
                    context=f"import.{imp.module}.{imp.name}"
                ))

    # Validate type indices in functions
    for i, typeidx in enumerate(module.functions):
        if typeidx >= len(module.types):
            errors.append(ValidationError(
                code="type_index_out_of_range",
                message=f"Function {i}: type index {typeidx} out of range (>= {len(module.types)})",
                context=f"function[{i}]"
            ))

    # Validate function/code count match
    if len(module.functions) != len(module.code):
        errors.append(ValidationError(
            code="func_code_count_mismatch",
            message=f"Function count ({len(module.functions)}) != code count ({len(module.code)})"
        ))

    # Validate export names are unique
    export_names = [exp.name for exp in module.exports]
    # Compare as bytes for uniqueness
    export_names_bytes = [exp.name.encode('utf-8') if isinstance(exp.name, str) else exp.name for exp in module.exports]
    if len(export_names_bytes) != len(set(export_names_bytes)):
        # Find duplicates
        seen = set()
        for name in export_names:
            name_bytes = name.encode('utf-8') if isinstance(name, str) else name
            if name_bytes in seen:
                errors.append(ValidationError(
                    code="duplicate_export_name",
                    message=f"Duplicate export name: {name}"
                ))
            seen.add(name_bytes)

    # Validate export indices
    for exp in module.exports:
        if exp.kind == 0:  # func
            if exp.index >= funcs_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export {exp.name}: func index {exp.index} >= {funcs_total}"
                ))
        elif exp.kind == 1:  # table
            if exp.index >= tables_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export {exp.name}: table index {exp.index} >= {tables_total}"
                ))
        elif exp.kind == 2:  # memory
            if exp.index >= mems_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export {exp.name}: memory index {exp.index} >= {mems_total}"
                ))
        elif exp.kind == 3:  # global
            if exp.index >= globals_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export {exp.name}: global index {exp.index} >= {globals_total}"
                ))

    # Validate start function
    if module.start is not None:
        if module.start >= funcs_total:
            errors.append(ValidationError(
                code="index_out_of_range",
                message=f"Start function index {module.start} >= {funcs_total}"
            ))
        else:
            # Find the type of the start function
            if module.start < imported_funcs:
                # It's an imported function
                func_imports = [imp for imp in module.imports if isinstance(imp, ImportFunc)]
                if module.start < len(func_imports):
                    typeidx = func_imports[module.start].typeidx
                    if typeidx < len(module.types):
                        func_type = module.types[typeidx]
                        if len(func_type.params) != 0 or len(func_type.results) != 0:
                            errors.append(ValidationError(
                                code="bad_start_signature",
                                message=f"Start function must have signature [] -> [], got {len(func_type.params)} params, {len(func_type.results)} results"
                            ))
            else:
                # It's a defined function
                func_idx = module.start - imported_funcs
                if func_idx < len(module.functions):
                    typeidx = module.functions[func_idx]
                    if typeidx < len(module.types):
                        func_type = module.types[typeidx]
                        if len(func_type.params) != 0 or len(func_type.results) != 0:
                            errors.append(ValidationError(
                                code="bad_start_signature",
                                message=f"Start function must have signature [] -> [], got {len(func_type.params)} params, {len(func_type.results)} results"
                            ))

    # Validate element segments
    for i, elem in enumerate(module.elements):
        for funcidx in elem.init:
            if funcidx >= funcs_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Element segment {i}: funcidx {funcidx} >= {funcs_total}"
                ))

    # Validate local indices in function bodies
    for func_idx, func_body in enumerate(module.code):
        # Get function type to know param count
        if func_idx < len(module.functions):
            typeidx = module.functions[func_idx]
            if typeidx < len(module.types):
                func_type = module.types[typeidx]
                num_params = len(func_type.params)
                num_locals = sum(decl.count for decl in func_body.locals)
                total_locals = num_params + num_locals

                # Check local indices in instructions
                for instr in func_body.expr.instructions:
                    if isinstance(instr, (LocalGet, LocalSet)):
                        if instr.localidx >= total_locals:
                            errors.append(ValidationError(
                                code="local_index_out_of_range",
                                message=f"Function {func_idx}: local index {instr.localidx} >= {total_locals}",
                                context=f"function[{func_idx}]"
                            ))
                    elif isinstance(instr, Call):
                        if instr.funcidx >= funcs_total:
                            errors.append(ValidationError(
                                code="index_out_of_range",
                                message=f"Function {func_idx}: call funcidx {instr.funcidx} >= {funcs_total}",
                                context=f"function[{func_idx}]"
                            ))

    # Validate data count
    if module.data_count is not None:
        if module.data_count != len(module.data):
            errors.append(ValidationError(
                code="data_count_mismatch",
                message=f"Data count section ({module.data_count}) != actual data segments ({len(module.data)})"
            ))

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

