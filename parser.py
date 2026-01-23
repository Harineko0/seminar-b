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
class MemoryLimits:
    min: int
    max: Optional[int] = None


@dataclass(frozen=True)
class GlobalType:
    valtype: ValType
    mutable: bool


class ImportKind(Enum):
    FUNC = 0
    TABLE = 1
    MEMORY = 2
    GLOBAL = 3


@dataclass(frozen=True)
class Import:
    module: bytes
    name: bytes
    kind: ImportKind
    desc: Union[int, TableLimits, MemoryLimits, GlobalType]  # typeidx for func, limits for table/mem, GlobalType for global


class ExportKind(Enum):
    FUNC = 0
    TABLE = 1
    MEMORY = 2
    GLOBAL = 3


@dataclass(frozen=True)
class Export:
    name: bytes
    kind: ExportKind
    index: int


# Instructions
@dataclass(frozen=True)
class Instr:
    pass


@dataclass(frozen=True)
class I32Const(Instr):
    value: int  # s32


@dataclass(frozen=True)
class LocalGet(Instr):
    localidx: int


@dataclass(frozen=True)
class LocalSet(Instr):
    localidx: int


@dataclass(frozen=True)
class I32Add(Instr):
    pass


@dataclass(frozen=True)
class Call(Instr):
    funcidx: int


@dataclass(frozen=True)
class End(Instr):
    pass


@dataclass(frozen=True)
class Expr:
    instructions: List[Instr]


@dataclass(frozen=True)
class Global:
    type: GlobalType
    init: Expr


@dataclass(frozen=True)
class ElementSegment:
    tableidx: int
    offset: Expr
    init: List[int]  # funcidx list


@dataclass(frozen=True)
class LocalDecl:
    count: int
    valtype: ValType


@dataclass(frozen=True)
class FuncBody:
    locals: List[LocalDecl]
    expr: Expr


@dataclass(frozen=True)
class DataSegment:
    memidx: int
    offset: Expr
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
    function_types: List[int] = field(default_factory=list)  # typeidx for each defined function
    tables: List[TableLimits] = field(default_factory=list)
    memories: List[MemoryLimits] = field(default_factory=list)
    globals: List[Global] = field(default_factory=list)
    exports: List[Export] = field(default_factory=list)
    start: Optional[int] = None
    elements: List[ElementSegment] = field(default_factory=list)
    code: List[FuncBody] = field(default_factory=list)
    datas: List[DataSegment] = field(default_factory=list)
    data_count: Optional[int] = None
    customs: List[CustomSection] = field(default_factory=list)


# ----------------------------
# Binary decoder internals
# ----------------------------

class BinaryReader:
    """Stream reader with bounds checking and limit enforcement."""

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
            raise DecodeError("Unexpected end of data", offset=self.pos)
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_bytes(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise DecodeError("Unexpected end of data", offset=self.pos)
        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result

    def peek_byte(self) -> Optional[int]:
        if self.pos >= len(self.data):
            return None
        return self.data[self.pos]

    def read_u32_leb128(self) -> int:
        """Decode unsigned LEB128 as u32."""
        result = 0
        shift = 0
        while True:
            if shift > 28:  # 32 bits / 7 bits per byte = max 5 bytes, but need to check overflow
                raise DecodeError("LEB128 u32 overflow", offset=self.pos)
            b = self.read_byte()
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                # Check for overlong encoding
                if shift > 0 and (b & 0x7F) == 0:
                    # Last byte is all zeros (except continuation bit) - could be overlong
                    pass  # Actually, this is allowed in practice
                # Check if result fits in u32
                if result > 0xFFFFFFFF:
                    raise DecodeError("LEB128 u32 overflow", offset=self.pos)
                return result
            shift += 7

    def read_s32_leb128(self) -> int:
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
                # Check range [-2^31, 2^31-1]
                if result < -2147483648 or result > 2147483647:
                    raise DecodeError("LEB128 s32 overflow", offset=self.pos)
                return result

    def read_name(self) -> bytes:
        """Read a name (length-prefixed byte string)."""
        length = self.read_u32_leb128()
        return self.read_bytes(length)

    def read_valtype(self) -> ValType:
        """Read a value type."""
        b = self.read_byte()
        if b == 0x7F:
            return ValType.I32
        elif b == 0x7E:
            return ValType.I64
        else:
            raise DecodeError(f"Unsupported valtype: 0x{b:02X}", offset=self.pos - 1, code="unsupported_valtype")

    def read_vec(self, reader_func, limit_name: Optional[str] = None):
        """Read a vector of elements."""
        n = self.read_u32_leb128()
        if limit_name == "vector" and n > self.limits.max_vector_length:
            raise DecodeError(f"Vector length {n} exceeds limit {self.limits.max_vector_length}", offset=self.pos)
        if limit_name == "locals" and n > self.limits.max_locals_per_function:
            raise DecodeError(f"Locals count {n} exceeds limit {self.limits.max_locals_per_function}", offset=self.pos)
        result = []
        for _ in range(n):
            result.append(reader_func())
        return result


def decode_limits(reader: BinaryReader) -> Union[TableLimits, MemoryLimits]:
    """Decode limits (used for table and memory)."""
    flags = reader.read_byte()
    if flags == 0x00:
        min_val = reader.read_u32_leb128()
        return TableLimits(min=min_val, max=None)
    elif flags == 0x01:
        min_val = reader.read_u32_leb128()
        max_val = reader.read_u32_leb128()
        return TableLimits(min=min_val, max=max_val)
    else:
        raise DecodeError(f"Bad limits flag: 0x{flags:02X}", code="bad_limits_flag")


def decode_expr(reader: BinaryReader, check_end: bool = True) -> Expr:
    """Decode an expression (sequence of instructions ending with 'end')."""
    instructions = []
    while True:
        opcode = reader.read_byte()

        if opcode == 0x0B:  # end
            instructions.append(End())
            break
        elif opcode == 0x41:  # i32.const
            value = reader.read_s32_leb128()
            instructions.append(I32Const(value=value))
        elif opcode == 0x20:  # local.get
            localidx = reader.read_u32_leb128()
            instructions.append(LocalGet(localidx=localidx))
        elif opcode == 0x21:  # local.set
            localidx = reader.read_u32_leb128()
            instructions.append(LocalSet(localidx=localidx))
        elif opcode == 0x6A:  # i32.add
            instructions.append(I32Add())
        elif opcode == 0x10:  # call
            funcidx = reader.read_u32_leb128()
            instructions.append(Call(funcidx=funcidx))
        else:
            raise DecodeError(f"Unsupported opcode: 0x{opcode:02X}", offset=reader.pos - 1, code="unsupported_opcode")

    if check_end and not instructions:
        raise DecodeError("Expression cannot be empty", code="missing_end")

    if check_end and not isinstance(instructions[-1], End):
        raise DecodeError("Expression must end with 'end'", code="missing_end")

    return Expr(instructions=instructions)


def decode_type_section(reader: BinaryReader) -> List[FuncType]:
    """Decode type section."""
    return reader.read_vec(lambda: decode_functype(reader), limit_name="vector")


def decode_functype(reader: BinaryReader) -> FuncType:
    """Decode a function type."""
    tag = reader.read_byte()
    if tag != 0x60:
        raise DecodeError(f"Expected functype tag 0x60, got 0x{tag:02X}", offset=reader.pos - 1)

    params = reader.read_vec(lambda: reader.read_valtype(), limit_name="vector")
    results = reader.read_vec(lambda: reader.read_valtype(), limit_name="vector")

    return FuncType(params=params, results=results)


def decode_import_section(reader: BinaryReader) -> List[Import]:
    """Decode import section."""
    return reader.read_vec(lambda: decode_import(reader), limit_name="vector")


def decode_import(reader: BinaryReader) -> Import:
    """Decode a single import."""
    module = reader.read_name()
    name = reader.read_name()
    kind_byte = reader.read_byte()

    if kind_byte == 0:  # func
        typeidx = reader.read_u32_leb128()
        return Import(module=module, name=name, kind=ImportKind.FUNC, desc=typeidx)
    elif kind_byte == 1:  # table
        elemtype = reader.read_byte()
        if elemtype != 0x70:  # funcref
            raise DecodeError(f"Unsupported table elemtype: 0x{elemtype:02X}", code="unsupported_table_elemtype")
        limits = decode_limits(reader)
        return Import(module=module, name=name, kind=ImportKind.TABLE, desc=limits)
    elif kind_byte == 2:  # memory
        limits = decode_limits(reader)
        return Import(module=module, name=name, kind=ImportKind.MEMORY, desc=limits)
    elif kind_byte == 3:  # global
        valtype = reader.read_valtype()
        mut_byte = reader.read_byte()
        if mut_byte == 0x00:
            mutable = False
        elif mut_byte == 0x01:
            mutable = True
        else:
            raise DecodeError(f"Bad mutability byte: 0x{mut_byte:02X}", code="bad_mutability")
        global_type = GlobalType(valtype=valtype, mutable=mutable)
        return Import(module=module, name=name, kind=ImportKind.GLOBAL, desc=global_type)
    else:
        raise DecodeError(f"Unknown import kind: {kind_byte}", offset=reader.pos - 1)


def decode_function_section(reader: BinaryReader) -> List[int]:
    """Decode function section (list of type indices)."""
    return reader.read_vec(lambda: reader.read_u32_leb128(), limit_name="vector")


def decode_table_section(reader: BinaryReader) -> List[TableLimits]:
    """Decode table section."""
    return reader.read_vec(lambda: decode_table(reader), limit_name="vector")


def decode_table(reader: BinaryReader) -> TableLimits:
    """Decode a table entry."""
    elemtype = reader.read_byte()
    if elemtype != 0x70:  # funcref
        raise DecodeError(f"Unsupported table elemtype: 0x{elemtype:02X}", code="unsupported_table_elemtype")
    return decode_limits(reader)


def decode_memory_section(reader: BinaryReader) -> List[MemoryLimits]:
    """Decode memory section."""
    return reader.read_vec(lambda: decode_limits(reader), limit_name="vector")


def decode_global_section(reader: BinaryReader) -> List[Global]:
    """Decode global section."""
    return reader.read_vec(lambda: decode_global(reader), limit_name="vector")


def decode_global(reader: BinaryReader) -> Global:
    """Decode a global entry."""
    valtype = reader.read_valtype()
    mut_byte = reader.read_byte()
    if mut_byte == 0x00:
        mutable = False
    elif mut_byte == 0x01:
        mutable = True
    else:
        raise DecodeError(f"Bad mutability byte: 0x{mut_byte:02X}", code="bad_mutability")

    global_type = GlobalType(valtype=valtype, mutable=mutable)
    init_expr = decode_expr(reader)

    return Global(type=global_type, init=init_expr)


def decode_export_section(reader: BinaryReader) -> List[Export]:
    """Decode export section."""
    return reader.read_vec(lambda: decode_export(reader), limit_name="vector")


def decode_export(reader: BinaryReader) -> Export:
    """Decode a single export."""
    name = reader.read_name()
    kind_byte = reader.read_byte()
    index = reader.read_u32_leb128()

    if kind_byte == 0:
        kind = ExportKind.FUNC
    elif kind_byte == 1:
        kind = ExportKind.TABLE
    elif kind_byte == 2:
        kind = ExportKind.MEMORY
    elif kind_byte == 3:
        kind = ExportKind.GLOBAL
    else:
        raise DecodeError(f"Unknown export kind: {kind_byte}", offset=reader.pos - 1)

    return Export(name=name, kind=kind, index=index)


def decode_start_section(reader: BinaryReader) -> int:
    """Decode start section."""
    return reader.read_u32_leb128()


def decode_element_section(reader: BinaryReader) -> List[ElementSegment]:
    """Decode element section (subset only)."""
    return reader.read_vec(lambda: decode_element(reader), limit_name="vector")


def decode_element(reader: BinaryReader) -> ElementSegment:
    """Decode an element segment (active mode for table 0 only)."""
    tableidx = reader.read_u32_leb128()
    if tableidx != 0:
        raise DecodeError(f"Unsupported element form: tableidx={tableidx}, only 0 supported", code="unsupported_element_form")

    # Decode offset expr - must be exactly i32.const + end
    offset_expr = decode_expr(reader)
    if len(offset_expr.instructions) != 2:
        raise DecodeError("Element offset must be i32.const followed by end", code="unsupported_element_form")
    if not isinstance(offset_expr.instructions[0], I32Const) or not isinstance(offset_expr.instructions[1], End):
        raise DecodeError("Element offset must be i32.const followed by end", code="unsupported_element_form")

    # Read init vector
    init = reader.read_vec(lambda: reader.read_u32_leb128(), limit_name="vector")

    return ElementSegment(tableidx=tableidx, offset=offset_expr, init=init)


def decode_code_section(reader: BinaryReader) -> List[FuncBody]:
    """Decode code section."""
    return reader.read_vec(lambda: decode_funcbody(reader), limit_name="vector")


def decode_funcbody(reader: BinaryReader) -> FuncBody:
    """Decode a function body."""
    body_size = reader.read_u32_leb128()
    if body_size > reader.limits.max_function_body_bytes:
        raise DecodeError(f"Function body size {body_size} exceeds limit {reader.limits.max_function_body_bytes}", offset=reader.pos)

    start_pos = reader.pos

    # Decode locals
    locals = reader.read_vec(lambda: decode_local_decl(reader), limit_name="vector")

    # Count total locals
    total_locals = sum(ld.count for ld in locals)
    if total_locals > reader.limits.max_locals_per_function:
        raise DecodeError(f"Total locals {total_locals} exceeds limit {reader.limits.max_locals_per_function}", offset=reader.pos)

    # Decode expression
    expr = decode_expr(reader)

    # Check that we consumed exactly body_size bytes
    bytes_read = reader.pos - start_pos
    if bytes_read != body_size:
        raise DecodeError(f"Function body size mismatch: expected {body_size}, read {bytes_read}", code="section_size_mismatch")

    return FuncBody(locals=locals, expr=expr)


def decode_local_decl(reader: BinaryReader) -> LocalDecl:
    """Decode a local declaration."""
    count = reader.read_u32_leb128()
    valtype = reader.read_valtype()
    return LocalDecl(count=count, valtype=valtype)


def decode_data_section(reader: BinaryReader) -> List[DataSegment]:
    """Decode data section (subset only)."""
    return reader.read_vec(lambda: decode_data(reader), limit_name="vector")


def decode_data(reader: BinaryReader) -> DataSegment:
    """Decode a data segment (active mode for memory 0 only)."""
    memidx = reader.read_u32_leb128()
    if memidx != 0:
        raise DecodeError(f"Unsupported data form: memidx={memidx}, only 0 supported", code="unsupported_data_form")

    # Decode offset expr - must be exactly i32.const + end
    offset_expr = decode_expr(reader)
    if len(offset_expr.instructions) != 2:
        raise DecodeError("Data offset must be i32.const followed by end", code="unsupported_data_form")
    if not isinstance(offset_expr.instructions[0], I32Const) or not isinstance(offset_expr.instructions[1], End):
        raise DecodeError("Data offset must be i32.const followed by end", code="unsupported_data_form")

    # Read data bytes
    data = reader.read_name()  # Same encoding as name (length-prefixed)

    return DataSegment(memidx=memidx, offset=offset_expr, data=data)


def decode_data_count_section(reader: BinaryReader) -> int:
    """Decode data count section."""
    return reader.read_u32_leb128()


def decode_custom_section(reader: BinaryReader, payload_len: int) -> CustomSection:
    """Decode custom section."""
    if payload_len > reader.limits.max_custom_section_bytes:
        raise DecodeError(f"Custom section size {payload_len} exceeds limit {reader.limits.max_custom_section_bytes}", offset=reader.pos)

    start_pos = reader.pos
    name = reader.read_name()
    name_bytes = reader.pos - start_pos
    data_len = payload_len - name_bytes
    data = reader.read_bytes(data_len)

    return CustomSection(name=name, data=data)


# ----------------------------
# Public API functions
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
        raise DecodeError(f"Invalid magic bytes: {magic.hex()}")

    version = reader.read_bytes(4)
    if version != b'\x01\x00\x00\x00':
        raise DecodeError(f"Invalid version: {version.hex()}")

    # Track which sections we've seen
    section_order = {
        1: "type", 2: "import", 3: "function", 4: "table", 5: "memory",
        6: "global", 7: "export", 8: "start", 9: "element", 10: "code",
        11: "data", 12: "datacount"
    }
    seen_sections = set()
    last_section_id = -1

    module = Module(raw_size=len(data))
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
    datas = []
    data_count = None
    customs = []

    # Read sections
    while not reader.eof():
        section_id = reader.read_byte()
        payload_len = reader.read_u32_leb128()

        if payload_len > limits.max_section_bytes and section_id != 0:
            raise DecodeError(f"Section {section_id} payload size {payload_len} exceeds limit {limits.max_section_bytes}", offset=reader.pos)

        # Check section ordering for non-custom sections
        if section_id != 0:
            if section_id in seen_sections:
                raise DecodeError(f"Duplicate section {section_id}", code="section_order")
            if section_id < last_section_id:
                raise DecodeError(f"Section {section_id} appears out of order", code="section_order")
            if section_id not in section_order:
                raise DecodeError(f"Unknown section id: {section_id}", code="decode_error")
            seen_sections.add(section_id)
            last_section_id = section_id

        # Parse section payload
        section_start = reader.pos

        if section_id == 0:  # Custom
            custom = decode_custom_section(reader, payload_len)
            customs.append(custom)
        elif section_id == 1:  # Type
            types = decode_type_section(reader)
        elif section_id == 2:  # Import
            imports = decode_import_section(reader)
        elif section_id == 3:  # Function
            function_types = decode_function_section(reader)
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
            datas = decode_data_section(reader)
        elif section_id == 12:  # DataCount
            data_count = decode_data_count_section(reader)

        # Check that we consumed exactly the payload
        bytes_read = reader.pos - section_start
        if bytes_read != payload_len:
            raise DecodeError(f"Section {section_id} payload size mismatch: expected {payload_len}, read {bytes_read}", code="section_size_mismatch")

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
        datas=datas,
        data_count=data_count,
        customs=customs
    )


def validate_module(module: Module) -> List[ValidationError]:
    """
    Perform structural validation on a decoded module.

    Returns:
        List[ValidationError]: empty if valid.
    """
    errors = []

    # Compute index spaces
    imported_funcs = sum(1 for imp in module.imports if imp.kind == ImportKind.FUNC)
    imported_tables = sum(1 for imp in module.imports if imp.kind == ImportKind.TABLE)
    imported_mems = sum(1 for imp in module.imports if imp.kind == ImportKind.MEMORY)
    imported_globals = sum(1 for imp in module.imports if imp.kind == ImportKind.GLOBAL)

    defined_funcs = len(module.function_types)
    defined_tables = len(module.tables)
    defined_mems = len(module.memories)
    defined_globals = len(module.globals)

    funcs_total = imported_funcs + defined_funcs
    tables_total = imported_tables + defined_tables
    mems_total = imported_mems + defined_mems
    globals_total = imported_globals + defined_globals

    # Validate table and memory limits
    for i, table in enumerate(module.tables):
        if table.max is not None and table.min > table.max:
            errors.append(ValidationError(
                code="limits_min_gt_max",
                message=f"Table {i}: min ({table.min}) > max ({table.max})"
            ))

    for table in [imp.desc for imp in module.imports if imp.kind == ImportKind.TABLE]:
        if table.max is not None and table.min > table.max:
            errors.append(ValidationError(
                code="limits_min_gt_max",
                message=f"Imported table: min ({table.min}) > max ({table.max})"
            ))

    for i, mem in enumerate(module.memories):
        if mem.max is not None and mem.min > mem.max:
            errors.append(ValidationError(
                code="limits_min_gt_max",
                message=f"Memory {i}: min ({mem.min}) > max ({mem.max})"
            ))

    for mem in [imp.desc for imp in module.imports if imp.kind == ImportKind.MEMORY]:
        if mem.max is not None and mem.min > mem.max:
            errors.append(ValidationError(
                code="limits_min_gt_max",
                message=f"Imported memory: min ({mem.min}) > max ({mem.max})"
            ))

    # Validate type indices in imports
    for i, imp in enumerate(module.imports):
        if imp.kind == ImportKind.FUNC:
            typeidx = imp.desc
            if typeidx >= len(module.types):
                errors.append(ValidationError(
                    code="type_index_out_of_range",
                    message=f"Import {i} function typeidx {typeidx} >= {len(module.types)}"
                ))

    # Validate type indices in function section
    for i, typeidx in enumerate(module.function_types):
        if typeidx >= len(module.types):
            errors.append(ValidationError(
                code="type_index_out_of_range",
                message=f"Function {i} typeidx {typeidx} >= {len(module.types)}"
            ))

    # Validate export indices
    export_names_seen = set()
    for exp in module.exports:
        # Check for duplicate names
        if exp.name in export_names_seen:
            errors.append(ValidationError(
                code="duplicate_export_name",
                message=f"Duplicate export name: {exp.name!r}"
            ))
        export_names_seen.add(exp.name)

        # Check index ranges
        if exp.kind == ExportKind.FUNC:
            if exp.index >= funcs_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export '{exp.name!r}' func index {exp.index} >= {funcs_total}"
                ))
        elif exp.kind == ExportKind.TABLE:
            if exp.index >= tables_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export '{exp.name!r}' table index {exp.index} >= {tables_total}"
                ))
        elif exp.kind == ExportKind.MEMORY:
            if exp.index >= mems_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export '{exp.name!r}' memory index {exp.index} >= {mems_total}"
                ))
        elif exp.kind == ExportKind.GLOBAL:
            if exp.index >= globals_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export '{exp.name!r}' global index {exp.index} >= {globals_total}"
                ))

    # Validate start function
    if module.start is not None:
        if module.start >= funcs_total:
            errors.append(ValidationError(
                code="index_out_of_range",
                message=f"Start function index {module.start} >= {funcs_total}"
            ))
        else:
            # Check start function signature
            if module.start < imported_funcs:
                # It's an imported function
                func_imports = [imp for imp in module.imports if imp.kind == ImportKind.FUNC]
                typeidx = func_imports[module.start].desc
            else:
                # It's a defined function
                typeidx = module.function_types[module.start - imported_funcs]

            if typeidx < len(module.types):
                func_type = module.types[typeidx]
                if func_type.params or func_type.results:
                    errors.append(ValidationError(
                        code="bad_start_signature",
                        message=f"Start function must have type [] -> [], got {func_type}"
                    ))

    # Validate element segments
    for i, elem in enumerate(module.elements):
        for funcidx in elem.init:
            if funcidx >= funcs_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Element segment {i} funcidx {funcidx} >= {funcs_total}"
                ))

    # Validate code section count
    if len(module.code) != len(module.function_types):
        errors.append(ValidationError(
            code="func_code_count_mismatch",
            message=f"Code count {len(module.code)} != function count {len(module.function_types)}"
        ))

    # Validate function bodies
    for func_idx, (typeidx, body) in enumerate(zip(module.function_types, module.code)):
        if typeidx >= len(module.types):
            continue  # Already reported

        func_type = module.types[typeidx]
        num_params = len(func_type.params)

        # Count locals
        num_locals = sum(ld.count for ld in body.locals)
        total_locals = num_params + num_locals

        # Validate local indices in instructions
        for instr in body.expr.instructions:
            if isinstance(instr, (LocalGet, LocalSet)):
                if instr.localidx >= total_locals:
                    errors.append(ValidationError(
                        code="local_index_out_of_range",
                        message=f"Function {imported_funcs + func_idx} local index {instr.localidx} >= {total_locals}"
                    ))
            elif isinstance(instr, Call):
                if instr.funcidx >= funcs_total:
                    errors.append(ValidationError(
                        code="index_out_of_range",
                        message=f"Function {imported_funcs + func_idx} call index {instr.funcidx} >= {funcs_total}"
                    ))

    # Validate data count
    if module.data_count is not None:
        if module.data_count != len(module.datas):
            errors.append(ValidationError(
                code="data_count_mismatch",
                message=f"Data count section value {module.data_count} != actual data segments {len(module.datas)}"
            ))

    return errors


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

