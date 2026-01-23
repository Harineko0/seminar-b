"""
parser.py - Public API surface for WASM binary module parsing + structural validation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List, Union
from enum import IntEnum


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
# AST types
# ----------------------------

class ValType(IntEnum):
    """Value types supported in this WASM subset."""
    I32 = 0x7F
    I64 = 0x7E


@dataclass(frozen=True)
class FuncType:
    """Function type signature."""
    params: List[ValType]
    results: List[ValType]


@dataclass(frozen=True)
class TableLimits:
    """Table or memory limits."""
    min: int
    max: Optional[int] = None


@dataclass(frozen=True)
class TableType:
    """Table type (only funcref supported)."""
    elemtype: int  # 0x70 for funcref
    limits: TableLimits


@dataclass(frozen=True)
class MemoryType:
    """Memory type."""
    limits: TableLimits


@dataclass(frozen=True)
class GlobalType:
    """Global type."""
    valtype: ValType
    mutable: bool


@dataclass(frozen=True)
class Import:
    """Import entry."""
    module: str  # name as string (decoded from UTF-8 with replacement)
    name: str    # name as string
    kind: int      # 0=func, 1=table, 2=mem, 3=global
    desc: Union[int, TableType, MemoryType, GlobalType]  # depends on kind


@dataclass(frozen=True)
class Export:
    """Export entry."""
    name: str  # name as string (decoded from UTF-8 with replacement)
    kind: int    # 0=func, 1=table, 2=mem, 3=global
    index: int


@dataclass(frozen=True)
class Instruction:
    """Single instruction."""
    opcode: int
    immediate: Optional[int] = None  # for i32.const, local.get/set, call


@dataclass(frozen=True)
class Expression:
    """Expression (instruction sequence ending with 'end')."""
    instructions: List[Instruction]


@dataclass(frozen=True)
class Global:
    """Global definition."""
    type: GlobalType
    init: Expression


@dataclass(frozen=True)
class LocalDecl:
    """Local variable declaration (count + type)."""
    count: int
    valtype: ValType


@dataclass(frozen=True)
class FuncBody:
    """Function body (locals + expression)."""
    locals: List[LocalDecl]
    expr: Expression


@dataclass(frozen=True)
class ElementSegment:
    """Element segment (subset: active mode only for table 0)."""
    tableidx: int
    offset: Expression
    init: List[int]  # funcidx list


@dataclass(frozen=True)
class DataSegment:
    """Data segment (subset: active mode only for mem 0)."""
    memidx: int
    offset: Expression
    data: bytes


@dataclass(frozen=True)
class CustomSection:
    """Custom section."""
    name: str  # name as string
    data: bytes


@dataclass(frozen=True)
class Module:
    """Decoded WASM module AST."""
    raw_size: int
    types: List[FuncType] = field(default_factory=list)
    imports: List[Import] = field(default_factory=list)
    functions: List[int] = field(default_factory=list)  # typeidx list
    tables: List[TableType] = field(default_factory=list)
    memories: List[MemoryType] = field(default_factory=list)
    globals: List[Global] = field(default_factory=list)
    exports: List[Export] = field(default_factory=list)
    start: Optional[int] = None
    elements: List[ElementSegment] = field(default_factory=list)
    code: List[FuncBody] = field(default_factory=list)
    data: List[DataSegment] = field(default_factory=list)
    data_count: Optional[int] = None
    customs: List[CustomSection] = field(default_factory=list)


# ----------------------------
# Internal decoder
# ----------------------------

class BinaryDecoder:
    """Byte stream decoder with bounds checking."""

    def __init__(self, data: bytes, limits: Limits):
        self.data = data
        self.pos = 0
        self.limits = limits

    def eof(self) -> bool:
        """Check if at end of data."""
        return self.pos >= len(self.data)

    def remaining(self) -> int:
        """Bytes remaining."""
        return len(self.data) - self.pos

    def read_byte(self) -> int:
        """Read a single byte."""
        if self.pos >= len(self.data):
            raise DecodeError("Unexpected end of input (truncated)", offset=self.pos)
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_bytes(self, n: int) -> bytes:
        """Read n bytes."""
        if self.pos + n > len(self.data):
            raise DecodeError(f"Unexpected end of input (need {n} bytes)", offset=self.pos)
        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result

    def read_u32(self) -> int:
        """Decode unsigned LEB128 u32."""
        result = 0
        shift = 0
        start_pos = self.pos

        while True:
            if self.pos >= len(self.data):
                raise DecodeError("Truncated LEB128 integer", offset=start_pos)

            byte = self.data[self.pos]
            self.pos += 1

            result |= (byte & 0x7F) << shift

            if (byte & 0x80) == 0:
                break

            shift += 7

            # Check for overlong encoding or overflow
            if shift >= 35:  # 5 bytes max for u32
                raise DecodeError("LEB128 integer too large for u32", offset=start_pos)

        if result > 0xFFFFFFFF:
            raise DecodeError("LEB128 integer exceeds u32 range", offset=start_pos)

        return result

    def read_s32(self) -> int:
        """Decode signed LEB128 s32."""
        result = 0
        shift = 0
        start_pos = self.pos
        byte = 0

        while True:
            if self.pos >= len(self.data):
                raise DecodeError("Truncated LEB128 integer", offset=start_pos)

            byte = self.data[self.pos]
            self.pos += 1

            result |= (byte & 0x7F) << shift
            shift += 7

            if (byte & 0x80) == 0:
                break

            if shift >= 35:  # 5 bytes max
                raise DecodeError("LEB128 integer too large for s32", offset=start_pos)

        # Sign extend
        if shift < 32 and (byte & 0x40):
            result |= -(1 << shift)

        # Check range
        if result < -0x80000000 or result > 0x7FFFFFFF:
            raise DecodeError("LEB128 integer exceeds s32 range", offset=start_pos)

        return result

    def read_name(self) -> bytes:
        """Read a name (length-prefixed byte string)."""
        length = self.read_u32()
        return self.read_bytes(length)

    def read_vector(self, item_reader, max_len: Optional[int] = None):
        """Read a vector (count + items)."""
        count = self.read_u32()

        if max_len is None:
            max_len = self.limits.max_vector_length

        if count > max_len:
            raise DecodeError(f"Vector length {count} exceeds limit {max_len}", offset=self.pos)

        items = []
        for _ in range(count):
            items.append(item_reader())
        return items


# ----------------------------
# Section decoders
# ----------------------------

def decode_valtype(decoder: BinaryDecoder) -> ValType:
    """Decode a value type."""
    byte = decoder.read_byte()
    if byte == 0x7F:
        return ValType.I32
    elif byte == 0x7E:
        return ValType.I64
    else:
        raise DecodeError(f"Unsupported valtype: 0x{byte:02x}", code="unsupported_valtype")


def decode_functype(decoder: BinaryDecoder) -> FuncType:
    """Decode a function type."""
    tag = decoder.read_byte()
    if tag != 0x60:
        raise DecodeError(f"Invalid functype tag: 0x{tag:02x} (expected 0x60)")

    params = decoder.read_vector(lambda: decode_valtype(decoder))
    results = decoder.read_vector(lambda: decode_valtype(decoder))

    return FuncType(params=params, results=results)


def decode_limits(decoder: BinaryDecoder) -> TableLimits:
    """Decode table/memory limits."""
    flags = decoder.read_byte()

    if flags == 0x00:
        min_val = decoder.read_u32()
        return TableLimits(min=min_val, max=None)
    elif flags == 0x01:
        min_val = decoder.read_u32()
        max_val = decoder.read_u32()
        return TableLimits(min=min_val, max=max_val)
    else:
        raise DecodeError(f"Invalid limits flag: 0x{flags:02x}", code="bad_limits_flag")


def decode_tabletype(decoder: BinaryDecoder) -> TableType:
    """Decode table type."""
    elemtype = decoder.read_byte()
    if elemtype != 0x70:  # funcref
        raise DecodeError(f"Unsupported table elemtype: 0x{elemtype:02x}", code="unsupported_table_elemtype")

    limits = decode_limits(decoder)
    return TableType(elemtype=elemtype, limits=limits)


def decode_memtype(decoder: BinaryDecoder) -> MemoryType:
    """Decode memory type."""
    limits = decode_limits(decoder)
    return MemoryType(limits=limits)


def decode_globaltype(decoder: BinaryDecoder) -> GlobalType:
    """Decode global type."""
    valtype = decode_valtype(decoder)
    mut = decoder.read_byte()

    if mut == 0x00:
        mutable = False
    elif mut == 0x01:
        mutable = True
    else:
        raise DecodeError(f"Invalid mutability: 0x{mut:02x}", code="bad_mutability")

    return GlobalType(valtype=valtype, mutable=mutable)


def decode_expression(decoder: BinaryDecoder, limits: Limits) -> Expression:
    """Decode an expression (restricted instruction set)."""
    instructions = []

    while True:
        opcode = decoder.read_byte()

        if opcode == 0x0B:  # end
            instructions.append(Instruction(opcode=opcode))
            break
        elif opcode == 0x41:  # i32.const
            value = decoder.read_s32()
            instructions.append(Instruction(opcode=opcode, immediate=value))
        elif opcode == 0x20:  # local.get
            localidx = decoder.read_u32()
            instructions.append(Instruction(opcode=opcode, immediate=localidx))
        elif opcode == 0x21:  # local.set
            localidx = decoder.read_u32()
            instructions.append(Instruction(opcode=opcode, immediate=localidx))
        elif opcode == 0x6A:  # i32.add
            instructions.append(Instruction(opcode=opcode))
        elif opcode == 0x10:  # call
            funcidx = decoder.read_u32()
            instructions.append(Instruction(opcode=opcode, immediate=funcidx))
        else:
            raise DecodeError(f"Unsupported opcode: 0x{opcode:02x}", code="unsupported_opcode")

    return Expression(instructions=instructions)


def decode_import(decoder: BinaryDecoder, limits: Limits) -> Import:
    """Decode an import."""
    module_bytes = decoder.read_name()
    name_bytes = decoder.read_name()
    kind = decoder.read_byte()

    # Decode names as strings
    module = module_bytes.decode('utf-8', errors='replace')
    name = name_bytes.decode('utf-8', errors='replace')

    if kind == 0:  # func
        typeidx = decoder.read_u32()
        desc = typeidx
    elif kind == 1:  # table
        desc = decode_tabletype(decoder)
    elif kind == 2:  # mem
        desc = decode_memtype(decoder)
    elif kind == 3:  # global
        desc = decode_globaltype(decoder)
    else:
        raise DecodeError(f"Unknown import kind: {kind}")

    return Import(module=module, name=name, kind=kind, desc=desc)


def decode_export(decoder: BinaryDecoder) -> Export:
    """Decode an export."""
    name_bytes = decoder.read_name()
    kind = decoder.read_byte()
    index = decoder.read_u32()

    # Decode name as string
    name = name_bytes.decode('utf-8', errors='replace')

    return Export(name=name, kind=kind, index=index)


def decode_global(decoder: BinaryDecoder, limits: Limits) -> Global:
    """Decode a global."""
    globaltype = decode_globaltype(decoder)
    init_expr = decode_expression(decoder, limits)

    return Global(type=globaltype, init=init_expr)


def decode_element(decoder: BinaryDecoder, limits: Limits) -> ElementSegment:
    """Decode an element segment (subset: active mode for table 0 only)."""
    tableidx = decoder.read_u32()

    if tableidx != 0:
        raise DecodeError(f"Unsupported element tableidx: {tableidx} (only 0 supported)", code="unsupported_element_form")

    # Decode offset expression - must be i32.const + end
    offset_expr = decode_expression(decoder, limits)

    # Validate it's i32.const + end
    if len(offset_expr.instructions) != 2:
        raise DecodeError("Element offset must be i32.const + end", code="unsupported_element_form")
    if offset_expr.instructions[0].opcode != 0x41:  # i32.const
        raise DecodeError("Element offset must start with i32.const", code="unsupported_element_form")
    if offset_expr.instructions[1].opcode != 0x0B:  # end
        raise DecodeError("Element offset must end with end", code="unsupported_element_form")

    # Read funcidx vector
    init = decoder.read_vector(lambda: decoder.read_u32())

    return ElementSegment(tableidx=tableidx, offset=offset_expr, init=init)


def decode_data(decoder: BinaryDecoder, limits: Limits) -> DataSegment:
    """Decode a data segment (subset: active mode for mem 0 only)."""
    memidx = decoder.read_u32()

    if memidx != 0:
        raise DecodeError(f"Unsupported data memidx: {memidx} (only 0 supported)", code="unsupported_data_form")

    # Decode offset expression - must be i32.const + end
    offset_expr = decode_expression(decoder, limits)

    # Validate it's i32.const + end
    if len(offset_expr.instructions) != 2:
        raise DecodeError("Data offset must be i32.const + end", code="unsupported_data_form")
    if offset_expr.instructions[0].opcode != 0x41:  # i32.const
        raise DecodeError("Data offset must start with i32.const", code="unsupported_data_form")
    if offset_expr.instructions[1].opcode != 0x0B:  # end
        raise DecodeError("Data offset must end with end", code="unsupported_data_form")

    # Read data bytes
    byte_len = decoder.read_u32()
    data = decoder.read_bytes(byte_len)

    return DataSegment(memidx=memidx, offset=offset_expr, data=data)


def decode_funcbody(decoder: BinaryDecoder, limits: Limits) -> FuncBody:
    """Decode a function body."""
    body_size = decoder.read_u32()

    if body_size > limits.max_function_body_bytes:
        raise DecodeError(f"Function body size {body_size} exceeds limit {limits.max_function_body_bytes}")

    body_start = decoder.pos
    body_end = body_start + body_size

    # Decode locals
    def read_local_decl():
        count = decoder.read_u32()
        valtype = decode_valtype(decoder)
        return LocalDecl(count=count, valtype=valtype)

    locals = decoder.read_vector(read_local_decl)

    # Calculate total locals
    total_locals = sum(ld.count for ld in locals)
    if total_locals > limits.max_locals_per_function:
        raise DecodeError(f"Total locals {total_locals} exceeds limit {limits.max_locals_per_function}")

    # Decode expression
    expr = decode_expression(decoder, limits)

    # Check body size exactness
    if decoder.pos != body_end:
        raise DecodeError(f"Function body size mismatch: expected {body_size}, consumed {decoder.pos - body_start}", code="section_size_mismatch")

    return FuncBody(locals=locals, expr=expr)


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

    decoder = BinaryDecoder(data, limits)

    # Check magic
    try:
        magic = decoder.read_bytes(4)
        if magic != b"\x00asm":
            raise DecodeError(f"Invalid magic number: {magic!r}")
    except DecodeError as e:
        if "end of input" in e.message.lower():
            raise DecodeError(f"Truncated magic number: {e.message}")
        raise

    # Check version
    version = decoder.read_bytes(4)
    if version != b"\x01\x00\x00\x00":
        raise DecodeError(f"Invalid version: {version!r}")

    # Initialize module
    module = Module(raw_size=len(data))

    # Section parsing state
    types = []
    imports = []
    functions = []
    tables = []
    memories = []
    globals = []
    exports = []
    start = None
    elements = []
    code = []
    data = []
    data_count = None
    customs = []

    last_section_id = -1

    while not decoder.eof():
        section_id = decoder.read_byte()
        payload_len = decoder.read_u32()

        # Check section size limit
        if section_id == 0:  # custom
            if payload_len > limits.max_custom_section_bytes:
                raise DecodeError(f"Custom section size {payload_len} exceeds limit {limits.max_custom_section_bytes}")
        else:
            if payload_len > limits.max_section_bytes:
                raise DecodeError(f"Section {section_id} size {payload_len} exceeds limit {limits.max_section_bytes}")

        payload_start = decoder.pos
        payload_end = payload_start + payload_len

        # Check section ordering (custom can appear anywhere)
        if section_id != 0:
            if section_id <= last_section_id:
                raise DecodeError(f"Section {section_id} out of order (last was {last_section_id})", code="section_order")
            last_section_id = section_id

        # Decode section
        if section_id == 0:  # custom
            name_bytes = decoder.read_name()
            name = name_bytes.decode('utf-8', errors='replace')
            data_bytes = decoder.read_bytes(payload_end - decoder.pos)
            customs.append(CustomSection(name=name, data=data_bytes))

        elif section_id == 1:  # type
            types = decoder.read_vector(lambda: decode_functype(decoder))

        elif section_id == 2:  # import
            imports = decoder.read_vector(lambda: decode_import(decoder, limits))

        elif section_id == 3:  # function
            functions = decoder.read_vector(lambda: decoder.read_u32())

        elif section_id == 4:  # table
            tables = decoder.read_vector(lambda: decode_tabletype(decoder))

        elif section_id == 5:  # memory
            memories = decoder.read_vector(lambda: decode_memtype(decoder))

        elif section_id == 6:  # global
            globals = decoder.read_vector(lambda: decode_global(decoder, limits))

        elif section_id == 7:  # export
            exports = decoder.read_vector(lambda: decode_export(decoder))

        elif section_id == 8:  # start
            start = decoder.read_u32()

        elif section_id == 9:  # element
            elements = decoder.read_vector(lambda: decode_element(decoder, limits))

        elif section_id == 10:  # code
            code = decoder.read_vector(lambda: decode_funcbody(decoder, limits))

        elif section_id == 11:  # data
            data = decoder.read_vector(lambda: decode_data(decoder, limits))

        elif section_id == 12:  # data count
            data_count = decoder.read_u32()

        else:
            raise DecodeError(f"Unknown section id: {section_id}", code="unknown_section_id")

        # Check payload exactness
        if decoder.pos != payload_end:
            if decoder.pos < payload_end:
                raise DecodeError(f"Section {section_id} has {payload_end - decoder.pos} leftover bytes", code="section_size_mismatch")
            else:
                raise DecodeError(f"Section {section_id} decoder overran by {decoder.pos - payload_end} bytes", code="section_size_mismatch")

    # Build final module
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
        data=data,
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
    imported_funcs = sum(1 for imp in module.imports if imp.kind == 0)
    imported_tables = sum(1 for imp in module.imports if imp.kind == 1)
    imported_mems = sum(1 for imp in module.imports if imp.kind == 2)
    imported_globals = sum(1 for imp in module.imports if imp.kind == 3)

    funcs_total = imported_funcs + len(module.functions)
    tables_total = imported_tables + len(module.tables)
    mems_total = imported_mems + len(module.memories)
    globals_total = imported_globals + len(module.globals)

    # Validate limits (tables and memories)
    for i, table in enumerate(module.tables):
        if table.limits.max is not None and table.limits.min > table.limits.max:
            errors.append(ValidationError(
                code="limits_min_gt_max",
                message=f"Table {i}: min {table.limits.min} > max {table.limits.max}"
            ))

    for i, mem in enumerate(module.memories):
        if mem.limits.max is not None and mem.limits.min > mem.limits.max:
            errors.append(ValidationError(
                code="limits_min_gt_max",
                message=f"Memory {i}: min {mem.limits.min} > max {mem.limits.max}"
            ))

    # Validate imported table limits
    for i, imp in enumerate(module.imports):
        if imp.kind == 1:  # table
            table_type = imp.desc
            if table_type.limits.max is not None and table_type.limits.min > table_type.limits.max:
                errors.append(ValidationError(
                    code="limits_min_gt_max",
                    message=f"Imported table {i}: min {table_type.limits.min} > max {table_type.limits.max}"
                ))
        elif imp.kind == 2:  # memory
            mem_type = imp.desc
            if mem_type.limits.max is not None and mem_type.limits.min > mem_type.limits.max:
                errors.append(ValidationError(
                    code="limits_min_gt_max",
                    message=f"Imported memory {i}: min {mem_type.limits.min} > max {mem_type.limits.max}"
                ))

    # Validate type indices in imports
    for i, imp in enumerate(module.imports):
        if imp.kind == 0:  # func import
            typeidx = imp.desc
            if typeidx >= len(module.types):
                errors.append(ValidationError(
                    code="type_index_out_of_range",
                    message=f"Import {i}: type index {typeidx} >= {len(module.types)}"
                ))

    # Validate type indices in functions
    for i, typeidx in enumerate(module.functions):
        if typeidx >= len(module.types):
            errors.append(ValidationError(
                code="type_index_out_of_range",
                message=f"Function {i}: type index {typeidx} >= {len(module.types)}"
            ))

    # Validate function/code linkage
    if len(module.code) != len(module.functions):
        errors.append(ValidationError(
            code="func_code_count_mismatch",
            message=f"Function count {len(module.functions)} != code count {len(module.code)}"
        ))

    # Validate exports
    export_names = []
    for exp in module.exports:
        # Check for duplicate names
        if exp.name in export_names:
            errors.append(ValidationError(
                code="duplicate_export_name",
                message=f"Duplicate export name: {exp.name}"
            ))
        export_names.append(exp.name)

        # Check index ranges
        if exp.kind == 0:  # func
            if exp.index >= funcs_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export func index {exp.index} >= {funcs_total}"
                ))
        elif exp.kind == 1:  # table
            if exp.index >= tables_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export table index {exp.index} >= {tables_total}"
                ))
        elif exp.kind == 2:  # mem
            if exp.index >= mems_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export mem index {exp.index} >= {mems_total}"
                ))
        elif exp.kind == 3:  # global
            if exp.index >= globals_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export global index {exp.index} >= {globals_total}"
                ))

    # Validate start function
    if module.start is not None:
        if module.start >= funcs_total:
            errors.append(ValidationError(
                code="index_out_of_range",
                message=f"Start function index {module.start} >= {funcs_total}"
            ))
        else:
            # Get the start function's type
            if module.start < imported_funcs:
                # It's an import
                func_idx = 0
                for imp in module.imports:
                    if imp.kind == 0:
                        if func_idx == module.start:
                            typeidx = imp.desc
                            break
                        func_idx += 1
            else:
                # It's a defined function
                local_idx = module.start - imported_funcs
                if local_idx < len(module.functions):
                    typeidx = module.functions[local_idx]

            # Check signature
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

    # Validate data count
    if module.data_count is not None:
        if module.data_count != len(module.data):
            errors.append(ValidationError(
                code="data_count_mismatch",
                message=f"Data count {module.data_count} != actual data segments {len(module.data)}"
            ))

    # Validate code bodies
    for func_idx, body in enumerate(module.code):
        global_func_idx = imported_funcs + func_idx

        # Get function type
        if func_idx < len(module.functions):
            typeidx = module.functions[func_idx]
            if typeidx < len(module.types):
                func_type = module.types[typeidx]

                # Calculate total locals (params + locals)
                num_params = len(func_type.params)
                num_locals = sum(ld.count for ld in body.locals)
                total_locals = num_params + num_locals

                # Validate local indices in expression
                for instr in body.expr.instructions:
                    if instr.opcode in (0x20, 0x21):  # local.get, local.set
                        localidx = instr.immediate
                        if localidx >= total_locals:
                            errors.append(ValidationError(
                                code="local_index_out_of_range",
                                message=f"Function {global_func_idx}: local index {localidx} >= {total_locals}"
                            ))
                    elif instr.opcode == 0x10:  # call
                        funcidx = instr.immediate
                        if funcidx >= funcs_total:
                            errors.append(ValidationError(
                                code="index_out_of_range",
                                message=f"Function {global_func_idx}: call funcidx {funcidx} >= {funcs_total}"
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

