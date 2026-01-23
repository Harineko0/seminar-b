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
# AST Types
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
class ImportMemory:
    module: bytes
    name: bytes
    limits: MemoryLimits


@dataclass(frozen=True)
class ImportGlobal:
    module: bytes
    name: bytes
    globaltype: GlobalType


ImportDesc = Union[ImportFunc, ImportTable, ImportMemory, ImportGlobal]


@dataclass(frozen=True)
class Export:
    name: bytes
    kind: int  # 0=func, 1=table, 2=mem, 3=global
    index: int


@dataclass(frozen=True)
class Instruction:
    opcode: int
    immediate: Optional[int] = None


@dataclass(frozen=True)
class Expression:
    instructions: List[Instruction]


@dataclass(frozen=True)
class LocalDecl:
    count: int
    valtype: ValType


@dataclass(frozen=True)
class FunctionBody:
    locals: List[LocalDecl]
    expr: Expression


@dataclass(frozen=True)
class Global:
    globaltype: GlobalType
    init_expr: Expression


@dataclass(frozen=True)
class ElementSegment:
    tableidx: int
    offset: int
    init: List[int]


@dataclass(frozen=True)
class DataSegment:
    memidx: int
    offset: int
    data: bytes


@dataclass(frozen=True)
class CustomSection:
    name: bytes
    data: bytes


@dataclass(frozen=True)
class Module:
    """Decoded AST for a WASM module."""
    raw_size: int
    types: List[FuncType] = field(default_factory=list)
    imports: List[ImportDesc] = field(default_factory=list)
    function_type_indices: List[int] = field(default_factory=list)
    tables: List[TableLimits] = field(default_factory=list)
    memories: List[MemoryLimits] = field(default_factory=list)
    globals: List[Global] = field(default_factory=list)
    exports: List[Export] = field(default_factory=list)
    start: Optional[int] = None
    elements: List[ElementSegment] = field(default_factory=list)
    code: List[FunctionBody] = field(default_factory=list)
    datas: List[DataSegment] = field(default_factory=list)
    datacount: Optional[int] = None
    customs: List[CustomSection] = field(default_factory=list)


# ----------------------------
# Binary Decoder
# ----------------------------

class BinaryReader:
    """Low-level binary reader with LEB128 support."""

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

    def read_u32(self) -> int:
        """Read unsigned LEB128 as u32."""
        result = 0
        shift = 0
        for _ in range(5):  # Max 5 bytes for u32
            if self.pos >= len(self.data):
                raise DecodeError("Truncated LEB128", offset=self.pos)
            b = self.read_byte()
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                # Check for value overflow
                if result >= 2**32:
                    raise DecodeError("LEB128 value too large for u32", offset=self.pos)
                return result
            shift += 7
            # Check if we're about to overflow
            if shift > 32:
                raise DecodeError("LEB128 value too large for u32", offset=self.pos)
        raise DecodeError("LEB128 value too large for u32", offset=self.pos)

    def read_s32(self) -> int:
        """Read signed LEB128 as s32."""
        result = 0
        shift = 0
        for _ in range(5):  # Max 5 bytes for s32
            if self.pos >= len(self.data):
                raise DecodeError("Truncated LEB128", offset=self.pos)
            b = self.read_byte()
            result |= (b & 0x7F) << shift
            shift += 7
            if (b & 0x80) == 0:
                # Sign extend
                if shift < 32 and (b & 0x40):
                    result |= -(1 << shift)
                # Validate range
                if result < -(2**31) or result >= 2**31:
                    raise DecodeError("LEB128 value out of s32 range", offset=self.pos)
                return result
        raise DecodeError("LEB128 value too large for s32", offset=self.pos)

    def read_name(self) -> bytes:
        """Read a name (length-prefixed bytes)."""
        length = self.read_u32()
        return self.read_bytes(length)

    def read_vec_length(self, limit: Optional[int] = None) -> int:
        """Read vector length with optional limit check."""
        n = self.read_u32()
        max_len = limit if limit is not None else self.limits.max_vector_length
        if n > max_len:
            raise DecodeError(f"Vector length {n} exceeds limit {max_len}", offset=self.pos)
        return n


def decode_valtype(reader: BinaryReader) -> ValType:
    """Decode a value type."""
    b = reader.read_byte()
    if b == 0x7F:
        return ValType.I32
    elif b == 0x7E:
        return ValType.I64
    else:
        raise DecodeError(f"Unsupported valtype 0x{b:02X}", offset=reader.pos - 1, code="unsupported_valtype")


def decode_functype(reader: BinaryReader) -> FuncType:
    """Decode a function type."""
    tag = reader.read_byte()
    if tag != 0x60:
        raise DecodeError(f"Expected functype tag 0x60, got 0x{tag:02X}", offset=reader.pos - 1)

    # Params
    param_count = reader.read_vec_length()
    params = [decode_valtype(reader) for _ in range(param_count)]

    # Results
    result_count = reader.read_vec_length()
    results = [decode_valtype(reader) for _ in range(result_count)]

    return FuncType(params=params, results=results)


def decode_limits(reader: BinaryReader) -> Union[TableLimits, MemoryLimits]:
    """Decode limits (for table or memory)."""
    flags = reader.read_byte()
    if flags == 0x00:
        min_val = reader.read_u32()
        return TableLimits(min=min_val, max=None)
    elif flags == 0x01:
        min_val = reader.read_u32()
        max_val = reader.read_u32()
        return TableLimits(min=min_val, max=max_val)
    else:
        raise DecodeError(f"Bad limits flag 0x{flags:02X}", offset=reader.pos - 1, code="bad_limits_flag")


def decode_expression(reader: BinaryReader, expected_end_pos: Optional[int] = None) -> Expression:
    """Decode an expression (sequence of instructions ending with 'end')."""
    instructions: List[Instruction] = []

    while True:
        if expected_end_pos is not None and reader.pos >= expected_end_pos:
            raise DecodeError("Missing end opcode in expression", offset=reader.pos, code="missing_end")

        opcode = reader.read_byte()

        if opcode == 0x0B:  # end
            instructions.append(Instruction(opcode=opcode))
            break
        elif opcode == 0x41:  # i32.const
            immediate = reader.read_s32()
            instructions.append(Instruction(opcode=opcode, immediate=immediate))
        elif opcode == 0x20:  # local.get
            localidx = reader.read_u32()
            instructions.append(Instruction(opcode=opcode, immediate=localidx))
        elif opcode == 0x21:  # local.set
            localidx = reader.read_u32()
            instructions.append(Instruction(opcode=opcode, immediate=localidx))
        elif opcode == 0x6A:  # i32.add
            instructions.append(Instruction(opcode=opcode))
        elif opcode == 0x10:  # call
            funcidx = reader.read_u32()
            instructions.append(Instruction(opcode=opcode, immediate=funcidx))
        else:
            raise DecodeError(f"Unsupported opcode 0x{opcode:02X}", offset=reader.pos - 1, code="unsupported_opcode")

    # Check for trailing bytes if expected_end_pos is set
    if expected_end_pos is not None and reader.pos < expected_end_pos:
        raise DecodeError("Trailing bytes in expression", offset=reader.pos, code="trailing_bytes_in_expr")

    return Expression(instructions=instructions)


def decode_type_section(reader: BinaryReader) -> List[FuncType]:
    """Decode the type section."""
    count = reader.read_vec_length()
    return [decode_functype(reader) for _ in range(count)]


def decode_import_section(reader: BinaryReader) -> List[ImportDesc]:
    """Decode the import section."""
    count = reader.read_vec_length()
    imports: List[ImportDesc] = []

    for _ in range(count):
        module = reader.read_name()
        name = reader.read_name()
        kind = reader.read_byte()

        if kind == 0:  # func
            typeidx = reader.read_u32()
            imports.append(ImportFunc(module=module, name=name, typeidx=typeidx))
        elif kind == 1:  # table
            elemtype = reader.read_byte()
            if elemtype != 0x70:
                raise DecodeError(f"Unsupported table elemtype 0x{elemtype:02X}",
                                offset=reader.pos - 1, code="unsupported_table_elemtype")
            limits = decode_limits(reader)
            imports.append(ImportTable(module=module, name=name, limits=limits))
        elif kind == 2:  # memory
            limits = decode_limits(reader)
            imports.append(ImportMemory(module=module, name=name, limits=limits))
        elif kind == 3:  # global
            valtype = decode_valtype(reader)
            mut_byte = reader.read_byte()
            if mut_byte == 0x00:
                mutable = False
            elif mut_byte == 0x01:
                mutable = True
            else:
                raise DecodeError(f"Bad mutability byte 0x{mut_byte:02X}",
                                offset=reader.pos - 1, code="bad_mutability")
            globaltype = GlobalType(valtype=valtype, mutable=mutable)
            imports.append(ImportGlobal(module=module, name=name, globaltype=globaltype))
        else:
            raise DecodeError(f"Unknown import kind {kind}", offset=reader.pos - 1)

    return imports


def decode_function_section(reader: BinaryReader) -> List[int]:
    """Decode the function section (type indices)."""
    count = reader.read_vec_length()
    return [reader.read_u32() for _ in range(count)]


def decode_table_section(reader: BinaryReader) -> List[TableLimits]:
    """Decode the table section."""
    count = reader.read_vec_length()
    tables: List[TableLimits] = []

    for _ in range(count):
        elemtype = reader.read_byte()
        if elemtype != 0x70:
            raise DecodeError(f"Unsupported table elemtype 0x{elemtype:02X}",
                            offset=reader.pos - 1, code="unsupported_table_elemtype")
        limits = decode_limits(reader)
        tables.append(limits)

    return tables


def decode_memory_section(reader: BinaryReader) -> List[MemoryLimits]:
    """Decode the memory section."""
    count = reader.read_vec_length()
    return [decode_limits(reader) for _ in range(count)]


def decode_global_section(reader: BinaryReader) -> List[Global]:
    """Decode the global section."""
    count = reader.read_vec_length()
    globals_list: List[Global] = []

    for _ in range(count):
        valtype = decode_valtype(reader)
        mut_byte = reader.read_byte()
        if mut_byte == 0x00:
            mutable = False
        elif mut_byte == 0x01:
            mutable = True
        else:
            raise DecodeError(f"Bad mutability byte 0x{mut_byte:02X}",
                            offset=reader.pos - 1, code="bad_mutability")
        globaltype = GlobalType(valtype=valtype, mutable=mutable)
        init_expr = decode_expression(reader)
        globals_list.append(Global(globaltype=globaltype, init_expr=init_expr))

    return globals_list


def decode_export_section(reader: BinaryReader) -> List[Export]:
    """Decode the export section."""
    count = reader.read_vec_length()
    exports: List[Export] = []

    for _ in range(count):
        name = reader.read_name()
        kind = reader.read_byte()
        index = reader.read_u32()
        exports.append(Export(name=name, kind=kind, index=index))

    return exports


def decode_start_section(reader: BinaryReader) -> int:
    """Decode the start section."""
    return reader.read_u32()


def decode_element_section(reader: BinaryReader) -> List[ElementSegment]:
    """Decode the element section (restricted form only)."""
    count = reader.read_vec_length()
    elements: List[ElementSegment] = []

    for _ in range(count):
        tableidx = reader.read_u32()
        if tableidx != 0:
            raise DecodeError(f"Unsupported element form: tableidx={tableidx}",
                            offset=reader.pos, code="unsupported_element_form")

        # Decode offset expression - must be exactly i32.const + end
        expr_start = reader.pos
        opcode = reader.read_byte()
        if opcode != 0x41:  # i32.const
            raise DecodeError("Element offset must be i32.const",
                            offset=reader.pos - 1, code="unsupported_element_form")
        offset = reader.read_s32()
        end_opcode = reader.read_byte()
        if end_opcode != 0x0B:
            raise DecodeError("Element offset must end with end opcode",
                            offset=reader.pos - 1, code="unsupported_element_form")

        # Decode init vector
        init_count = reader.read_vec_length()
        init = [reader.read_u32() for _ in range(init_count)]

        elements.append(ElementSegment(tableidx=tableidx, offset=offset, init=init))

    return elements


def decode_code_section(reader: BinaryReader, limits: Limits) -> List[FunctionBody]:
    """Decode the code section."""
    count = reader.read_vec_length()
    code_bodies: List[FunctionBody] = []

    for _ in range(count):
        body_size = reader.read_u32()
        if body_size > limits.max_function_body_bytes:
            raise DecodeError(f"Function body size {body_size} exceeds limit", offset=reader.pos)

        body_start = reader.pos
        body_end = body_start + body_size

        if body_end > len(reader.data):
            raise DecodeError("Function body exceeds module size", offset=reader.pos)

        # Decode locals
        local_decl_count = reader.read_vec_length()
        locals: List[LocalDecl] = []
        total_locals = 0

        for _ in range(local_decl_count):
            count_val = reader.read_u32()
            valtype = decode_valtype(reader)
            locals.append(LocalDecl(count=count_val, valtype=valtype))
            total_locals += count_val
            if total_locals > limits.max_locals_per_function:
                raise DecodeError(f"Total locals {total_locals} exceeds limit", offset=reader.pos)

        # Decode expression
        expr = decode_expression(reader, expected_end_pos=body_end)

        # Verify exact match
        if reader.pos != body_end:
            raise DecodeError("Section size mismatch in function body",
                            offset=reader.pos, code="section_size_mismatch")

        code_bodies.append(FunctionBody(locals=locals, expr=expr))

    return code_bodies


def decode_data_section(reader: BinaryReader) -> List[DataSegment]:
    """Decode the data section (restricted form only)."""
    count = reader.read_vec_length()
    datas: List[DataSegment] = []

    for _ in range(count):
        memidx = reader.read_u32()
        if memidx != 0:
            raise DecodeError(f"Unsupported data form: memidx={memidx}",
                            offset=reader.pos, code="unsupported_data_form")

        # Decode offset expression - must be exactly i32.const + end
        opcode = reader.read_byte()
        if opcode != 0x41:  # i32.const
            raise DecodeError("Data offset must be i32.const",
                            offset=reader.pos - 1, code="unsupported_data_form")
        offset = reader.read_s32()
        end_opcode = reader.read_byte()
        if end_opcode != 0x0B:
            raise DecodeError("Data offset must end with end opcode",
                            offset=reader.pos - 1, code="unsupported_data_form")

        # Decode data bytes
        data_len = reader.read_u32()
        data = reader.read_bytes(data_len)

        datas.append(DataSegment(memidx=memidx, offset=offset, data=data))

    return datas


def decode_datacount_section(reader: BinaryReader) -> int:
    """Decode the data count section."""
    return reader.read_u32()


def decode_custom_section(reader: BinaryReader, payload_len: int, limits: Limits) -> CustomSection:
    """Decode a custom section."""
    if payload_len > limits.max_custom_section_bytes:
        raise DecodeError(f"Custom section size {payload_len} exceeds limit", offset=reader.pos)

    name = reader.read_name()
    remaining = payload_len - (reader.pos - (reader.pos - payload_len))
    # Calculate how much we read for the name
    name_len = len(name)
    # We need to track how many bytes the length encoding took
    # Approximate: for small names, 1 byte; for larger, use actual
    start_after_len = reader.pos - name_len
    name_encoding_size = name_len + 1  # Simplification
    remaining = payload_len - name_encoding_size - name_len

    if remaining < 0:
        remaining = 0
    if remaining > len(reader.data) - reader.pos:
        remaining = len(reader.data) - reader.pos

    data = reader.read_bytes(remaining)
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

    # Track section order
    last_section_id = -1
    seen_sections = set()

    # Module components
    types: List[FuncType] = []
    imports: List[ImportDesc] = []
    function_type_indices: List[int] = []
    tables: List[TableLimits] = []
    memories: List[MemoryLimits] = []
    globals: List[Global] = []
    exports: List[Export] = []
    start: Optional[int] = None
    elements: List[ElementSegment] = []
    code: List[FunctionBody] = []
    datas: List[DataSegment] = []
    datacount: Optional[int] = None
    customs: List[CustomSection] = []

    # Parse sections
    while not reader.eof():
        section_id = reader.read_byte()
        payload_len = reader.read_u32()

        if payload_len > limits.max_section_bytes and section_id != 0:
            raise DecodeError(f"Section {section_id} payload size {payload_len} exceeds limit",
                            offset=reader.pos)

        section_start = reader.pos
        section_end = section_start + payload_len

        if section_end > len(data):
            raise DecodeError(f"Section {section_id} extends beyond module", offset=reader.pos)

        # Custom sections can appear anywhere
        if section_id == 0:
            custom = decode_custom_section(reader, payload_len, limits)
            customs.append(custom)
            # Adjust position to section end
            reader.pos = section_end
            continue

        # Check section ordering
        if section_id in seen_sections:
            raise DecodeError(f"Duplicate section {section_id}",
                            offset=reader.pos, code="section_order")
        if section_id < last_section_id:
            raise DecodeError(f"Section {section_id} out of order (after {last_section_id})",
                            offset=reader.pos, code="section_order")

        seen_sections.add(section_id)
        last_section_id = section_id

        # Decode section
        if section_id == 1:  # type
            types = decode_type_section(reader)
        elif section_id == 2:  # import
            imports = decode_import_section(reader)
        elif section_id == 3:  # function
            function_type_indices = decode_function_section(reader)
        elif section_id == 4:  # table
            tables = decode_table_section(reader)
        elif section_id == 5:  # memory
            memories = decode_memory_section(reader)
        elif section_id == 6:  # global
            globals = decode_global_section(reader)
        elif section_id == 7:  # export
            exports = decode_export_section(reader)
        elif section_id == 8:  # start
            start = decode_start_section(reader)
        elif section_id == 9:  # element
            elements = decode_element_section(reader)
        elif section_id == 10:  # code
            code = decode_code_section(reader, limits)
        elif section_id == 11:  # data
            datas = decode_data_section(reader)
        elif section_id == 12:  # datacount
            datacount = decode_datacount_section(reader)
        else:
            raise DecodeError(f"Unknown section id {section_id}",
                            offset=reader.pos, code="unknown_section_id")

        # Verify section payload was fully consumed
        if reader.pos != section_end:
            raise DecodeError(f"Section {section_id} size mismatch",
                            offset=reader.pos, code="section_size_mismatch")

    return Module(
        raw_size=len(data),
        types=types,
        imports=imports,
        function_type_indices=function_type_indices,
        tables=tables,
        memories=memories,
        globals=globals,
        exports=exports,
        start=start,
        elements=elements,
        code=code,
        datas=datas,
        datacount=datacount,
        customs=customs
    )


def validate_module(module: Module) -> List[ValidationError]:
    """
    Perform structural validation on a decoded module.

    Returns:
        List[ValidationError]: empty if valid.
    """
    errors: List[ValidationError] = []

    # Count index spaces
    imported_funcs = sum(1 for imp in module.imports if isinstance(imp, ImportFunc))
    imported_tables = sum(1 for imp in module.imports if isinstance(imp, ImportTable))
    imported_mems = sum(1 for imp in module.imports if isinstance(imp, ImportMemory))
    imported_globals = sum(1 for imp in module.imports if isinstance(imp, ImportGlobal))

    defined_funcs = len(module.function_type_indices)
    defined_tables = len(module.tables)
    defined_mems = len(module.memories)
    defined_globals = len(module.globals)

    funcs_total = imported_funcs + defined_funcs
    tables_total = imported_tables + defined_tables
    mems_total = imported_mems + defined_mems
    globals_total = imported_globals + defined_globals

    # Validate type indices in imports
    for imp in module.imports:
        if isinstance(imp, ImportFunc):
            if imp.typeidx >= len(module.types):
                errors.append(ValidationError(
                    code="type_index_out_of_range",
                    message=f"Import function type index {imp.typeidx} out of range (types count: {len(module.types)})",
                    context=f"import {imp.module.decode('utf-8', errors='replace')}.{imp.name.decode('utf-8', errors='replace')}"
                ))

    # Validate type indices in function section
    for i, typeidx in enumerate(module.function_type_indices):
        if typeidx >= len(module.types):
            errors.append(ValidationError(
                code="type_index_out_of_range",
                message=f"Function {imported_funcs + i} type index {typeidx} out of range (types count: {len(module.types)})",
                context=f"function {imported_funcs + i}"
            ))

    # Validate limits
    for i, table in enumerate(module.tables):
        if table.max is not None and table.min > table.max:
            errors.append(ValidationError(
                code="limits_min_gt_max",
                message=f"Table {imported_tables + i} min ({table.min}) > max ({table.max})"
            ))

    for imp in module.imports:
        if isinstance(imp, ImportTable):
            if imp.limits.max is not None and imp.limits.min > imp.limits.max:
                errors.append(ValidationError(
                    code="limits_min_gt_max",
                    message=f"Import table {imp.module}.{imp.name} min > max"
                ))

    for i, mem in enumerate(module.memories):
        if mem.max is not None and mem.min > mem.max:
            errors.append(ValidationError(
                code="limits_min_gt_max",
                message=f"Memory {imported_mems + i} min ({mem.min}) > max ({mem.max})"
            ))

    for imp in module.imports:
        if isinstance(imp, ImportMemory):
            if imp.limits.max is not None and imp.limits.min > imp.limits.max:
                errors.append(ValidationError(
                    code="limits_min_gt_max",
                    message=f"Import memory {imp.module}.{imp.name} min > max"
                ))

    # Validate export names are unique
    export_names = {}
    for exp in module.exports:
        if exp.name in export_names:
            errors.append(ValidationError(
                code="duplicate_export_name",
                message=f"Duplicate export name: {exp.name.decode('utf-8', errors='replace')}"
            ))
        export_names[exp.name] = True

    # Validate export indices
    for exp in module.exports:
        if exp.kind == 0:  # func
            if exp.index >= funcs_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export function index {exp.index} out of range (total: {funcs_total})",
                    context=f"export {exp.name.decode('utf-8', errors='replace')}"
                ))
        elif exp.kind == 1:  # table
            if exp.index >= tables_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export table index {exp.index} out of range (total: {tables_total})",
                    context=f"export {exp.name.decode('utf-8', errors='replace')}"
                ))
        elif exp.kind == 2:  # mem
            if exp.index >= mems_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export memory index {exp.index} out of range (total: {mems_total})",
                    context=f"export {exp.name.decode('utf-8', errors='replace')}"
                ))
        elif exp.kind == 3:  # global
            if exp.index >= globals_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export global index {exp.index} out of range (total: {globals_total})",
                    context=f"export {exp.name.decode('utf-8', errors='replace')}"
                ))

    # Validate start function
    if module.start is not None:
        if module.start >= funcs_total:
            errors.append(ValidationError(
                code="index_out_of_range",
                message=f"Start function index {module.start} out of range (total: {funcs_total})"
            ))
        else:
            # Check start function signature
            if module.start < imported_funcs:
                # It's an import
                imp = [imp for imp in module.imports if isinstance(imp, ImportFunc)][module.start]
                typeidx = imp.typeidx
            else:
                typeidx = module.function_type_indices[module.start - imported_funcs]

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
                    message=f"Element segment {i} func index {funcidx} out of range (total: {funcs_total})"
                ))

    # Validate code section count matches function section
    if len(module.code) != len(module.function_type_indices):
        errors.append(ValidationError(
            code="func_code_count_mismatch",
            message=f"Code section has {len(module.code)} entries, function section has {len(module.function_type_indices)}"
        ))

    # Validate local and call indices in code
    for func_idx, body in enumerate(module.code):
        # Calculate total locals for this function
        if func_idx < len(module.function_type_indices):
            typeidx = module.function_type_indices[func_idx]
            if typeidx < len(module.types):
                func_type = module.types[typeidx]
                num_params = len(func_type.params)
            else:
                num_params = 0
        else:
            num_params = 0

        num_locals = sum(decl.count for decl in body.locals)
        total_locals = num_params + num_locals

        # Check instructions
        for instr in body.expr.instructions:
            if instr.opcode in [0x20, 0x21]:  # local.get, local.set
                if instr.immediate is not None and instr.immediate >= total_locals:
                    errors.append(ValidationError(
                        code="local_index_out_of_range",
                        message=f"Function {imported_funcs + func_idx} local index {instr.immediate} out of range (total locals: {total_locals})"
                    ))
            elif instr.opcode == 0x10:  # call
                if instr.immediate is not None and instr.immediate >= funcs_total:
                    errors.append(ValidationError(
                        code="index_out_of_range",
                        message=f"Function {imported_funcs + func_idx} call index {instr.immediate} out of range (total funcs: {funcs_total})"
                    ))

    # Validate data count
    if module.datacount is not None:
        if module.datacount != len(module.datas):
            errors.append(ValidationError(
                code="data_count_mismatch",
                message=f"Data count section specifies {module.datacount}, but data section has {len(module.datas)} segments"
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
