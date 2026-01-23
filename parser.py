"""
parser.py - Public API surface for WASM binary module parsing + structural validation.

Implementation is intentionally omitted in this template.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, List


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
    valtype: int  # 0x7F (i32) or 0x7E (i64)
    mutable: bool


@dataclass(frozen=True)
class FuncType:
    params: List[int]  # List of valtypes
    results: List[int]  # List of valtypes


@dataclass(frozen=True)
class Instruction:
    opcode: int
    immediate: Optional[int] = None


@dataclass(frozen=True)
class Expression:
    instructions: List[Instruction]


@dataclass(frozen=True)
class ImportDesc:
    kind: int  # 0=func, 1=table, 2=mem, 3=global
    # For func: typeidx
    # For table: elemtype + limits
    # For mem: limits
    # For global: valtype + mut
    typeidx: Optional[int] = None
    elemtype: Optional[int] = None
    table_limits: Optional[TableLimits] = None
    mem_limits: Optional[MemoryLimits] = None
    global_type: Optional[GlobalType] = None


@dataclass(frozen=True)
class Import:
    module: bytes
    name: bytes
    desc: ImportDesc


@dataclass(frozen=True)
class Table:
    limits: TableLimits


@dataclass(frozen=True)
class Memory:
    limits: MemoryLimits


@dataclass(frozen=True)
class Global:
    type: GlobalType
    init: Expression


@dataclass(frozen=True)
class Export:
    name: bytes
    kind: int  # 0=func, 1=table, 2=mem, 3=global
    index: int


@dataclass(frozen=True)
class Element:
    tableidx: int
    offset: Expression
    init: List[int]  # List of funcidx


@dataclass(frozen=True)
class Code:
    locals: List[tuple[int, int]]  # List of (count, valtype)
    body: Expression


@dataclass(frozen=True)
class Data:
    memidx: int
    offset: Expression
    init: bytes


@dataclass(frozen=True)
class CustomSection:
    name: bytes
    data: bytes


@dataclass(frozen=True)
class Module:
    """Decoded WASM module AST."""
    raw_size: int
    types: List[FuncType]
    imports: List[Import]
    function_types: List[int]  # List of typeidx for defined functions
    tables: List[Table]
    memories: List[Memory]
    globals: List[Global]
    exports: List[Export]
    start: Optional[int]  # Optional funcidx
    elements: List[Element]
    code: List[Code]
    data: List[Data]
    data_count: Optional[int]
    customs: List[CustomSection]


# ----------------------------
# Internal decoder state
# ----------------------------

class _Decoder:
    """Internal state for decoding a WASM module."""

    def __init__(self, data: bytes, limits: Limits):
        self.data = data
        self.limits = limits
        self.pos = 0
        self.seen_sections: set[int] = set()
        self.last_section_id: int = -1

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def peek(self, n: int = 1) -> bytes:
        if self.pos + n > len(self.data):
            raise DecodeError("Unexpected end of input", offset=self.pos, code="truncated")
        return self.data[self.pos:self.pos + n]

    def read_byte(self) -> int:
        if self.pos >= len(self.data):
            raise DecodeError("Unexpected end of input", offset=self.pos, code="truncated")
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_bytes(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise DecodeError(f"Expected {n} bytes, got {self.remaining()}", offset=self.pos, code="truncated")
        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result

    def read_u32_leb128(self) -> int:
        """Decode unsigned LEB128 as u32."""
        result = 0
        shift = 0
        for _ in range(5):  # Max 5 bytes for u32
            if self.pos >= len(self.data):
                raise DecodeError("Truncated LEB128", offset=self.pos, code="truncated_leb")
            b = self.read_byte()
            result |= (b & 0x7F) << shift
            shift += 7
            if (b & 0x80) == 0:
                # Check for overflow
                if result > 0xFFFFFFFF:
                    raise DecodeError("LEB128 value exceeds u32", offset=self.pos, code="leb_overflow")
                return result
        raise DecodeError("LEB128 too long for u32", offset=self.pos, code="leb_overflow")

    def read_s32_leb128(self) -> int:
        """Decode signed LEB128 as s32."""
        result = 0
        shift = 0
        for i in range(5):  # Max 5 bytes for s32
            if self.pos >= len(self.data):
                raise DecodeError("Truncated LEB128", offset=self.pos, code="truncated_leb")
            b = self.read_byte()
            result |= (b & 0x7F) << shift
            shift += 7
            if (b & 0x80) == 0:
                # Sign extend
                if shift < 32 and (b & 0x40):
                    result |= -(1 << shift)
                # Check range
                if result < -2147483648 or result > 2147483647:
                    raise DecodeError("LEB128 value exceeds s32 range", offset=self.pos, code="leb_overflow")
                return result
        raise DecodeError("LEB128 too long for s32", offset=self.pos, code="leb_overflow")

    def read_name(self) -> bytes:
        """Read a name (length-prefixed byte string)."""
        length = self.read_u32_leb128()
        if length > self.limits.max_vector_length:
            raise DecodeError(f"Name length {length} exceeds limit", offset=self.pos, code="limit_exceeded")
        return self.read_bytes(length)

    def read_vec_length(self) -> int:
        """Read vector length and check limit."""
        length = self.read_u32_leb128()
        if length > self.limits.max_vector_length:
            raise DecodeError(f"Vector length {length} exceeds limit", offset=self.pos, code="limit_exceeded")
        return length


# ----------------------------
# Decoder helper functions
# ----------------------------

def _decode_valtype(dec: _Decoder) -> int:
    """Decode a valtype byte (only i32=0x7F and i64=0x7E supported)."""
    vt = dec.read_byte()
    if vt == 0x7F or vt == 0x7E:
        return vt
    raise DecodeError(f"Unsupported valtype 0x{vt:02X}", offset=dec.pos - 1, code="unsupported_valtype")


def _decode_functype(dec: _Decoder) -> FuncType:
    """Decode a function type."""
    tag = dec.read_byte()
    if tag != 0x60:
        raise DecodeError(f"Expected functype tag 0x60, got 0x{tag:02X}", offset=dec.pos - 1, code="bad_functype_tag")

    # Params
    param_count = dec.read_vec_length()
    params = [_decode_valtype(dec) for _ in range(param_count)]

    # Results
    result_count = dec.read_vec_length()
    results = [_decode_valtype(dec) for _ in range(result_count)]

    return FuncType(params=params, results=results)


def _decode_limits(dec: _Decoder) -> tuple[int, Optional[int]]:
    """Decode limits (min, optional max)."""
    flags = dec.read_byte()
    if flags == 0x00:
        min_val = dec.read_u32_leb128()
        return (min_val, None)
    elif flags == 0x01:
        min_val = dec.read_u32_leb128()
        max_val = dec.read_u32_leb128()
        return (min_val, max_val)
    else:
        raise DecodeError(f"Invalid limits flag 0x{flags:02X}", offset=dec.pos - 1, code="bad_limits_flag")


def _decode_expression(dec: _Decoder, allow_locals: int = 0) -> Expression:
    """Decode a restricted expression (sequence of instructions ending with 'end')."""
    instructions = []
    while True:
        opcode = dec.read_byte()

        if opcode == 0x0B:  # end
            return Expression(instructions=instructions)
        elif opcode == 0x41:  # i32.const
            imm = dec.read_s32_leb128()
            instructions.append(Instruction(opcode=opcode, immediate=imm))
        elif opcode == 0x20:  # local.get
            localidx = dec.read_u32_leb128()
            instructions.append(Instruction(opcode=opcode, immediate=localidx))
        elif opcode == 0x21:  # local.set
            localidx = dec.read_u32_leb128()
            instructions.append(Instruction(opcode=opcode, immediate=localidx))
        elif opcode == 0x6A:  # i32.add
            instructions.append(Instruction(opcode=opcode, immediate=None))
        elif opcode == 0x10:  # call
            funcidx = dec.read_u32_leb128()
            instructions.append(Instruction(opcode=opcode, immediate=funcidx))
        else:
            raise DecodeError(f"Unsupported opcode 0x{opcode:02X}", offset=dec.pos - 1, code="unsupported_opcode")


def _decode_import(dec: _Decoder) -> Import:
    """Decode an import entry."""
    module = dec.read_name()
    name = dec.read_name()
    kind = dec.read_byte()

    if kind == 0:  # func
        typeidx = dec.read_u32_leb128()
        desc = ImportDesc(kind=0, typeidx=typeidx)
    elif kind == 1:  # table
        elemtype = dec.read_byte()
        if elemtype != 0x70:
            raise DecodeError(f"Unsupported table elemtype 0x{elemtype:02X}", offset=dec.pos - 1, code="unsupported_table_elemtype")
        min_val, max_val = _decode_limits(dec)
        desc = ImportDesc(kind=1, elemtype=elemtype, table_limits=TableLimits(min=min_val, max=max_val))
    elif kind == 2:  # memory
        min_val, max_val = _decode_limits(dec)
        desc = ImportDesc(kind=2, mem_limits=MemoryLimits(min=min_val, max=max_val))
    elif kind == 3:  # global
        valtype = _decode_valtype(dec)
        mut = dec.read_byte()
        if mut not in (0x00, 0x01):
            raise DecodeError(f"Invalid mutability 0x{mut:02X}", offset=dec.pos - 1, code="bad_mutability")
        desc = ImportDesc(kind=3, global_type=GlobalType(valtype=valtype, mutable=(mut == 0x01)))
    else:
        raise DecodeError(f"Unknown import kind {kind}", offset=dec.pos - 1, code="unknown_import_kind")

    return Import(module=module, name=name, desc=desc)


def _decode_table(dec: _Decoder) -> Table:
    """Decode a table entry."""
    elemtype = dec.read_byte()
    if elemtype != 0x70:
        raise DecodeError(f"Unsupported table elemtype 0x{elemtype:02X}", offset=dec.pos - 1, code="unsupported_table_elemtype")
    min_val, max_val = _decode_limits(dec)
    return Table(limits=TableLimits(min=min_val, max=max_val))


def _decode_memory(dec: _Decoder) -> Memory:
    """Decode a memory entry."""
    min_val, max_val = _decode_limits(dec)
    return Memory(limits=MemoryLimits(min=min_val, max=max_val))


def _decode_global(dec: _Decoder) -> Global:
    """Decode a global entry."""
    valtype = _decode_valtype(dec)
    mut = dec.read_byte()
    if mut not in (0x00, 0x01):
        raise DecodeError(f"Invalid mutability 0x{mut:02X}", offset=dec.pos - 1, code="bad_mutability")
    global_type = GlobalType(valtype=valtype, mutable=(mut == 0x01))
    init_expr = _decode_expression(dec)
    return Global(type=global_type, init=init_expr)


def _decode_export(dec: _Decoder) -> Export:
    """Decode an export entry."""
    name = dec.read_name()
    kind = dec.read_byte()
    if kind not in (0, 1, 2, 3):
        raise DecodeError(f"Unknown export kind {kind}", offset=dec.pos - 1, code="unknown_export_kind")
    index = dec.read_u32_leb128()
    return Export(name=name, kind=kind, index=index)


def _decode_element(dec: _Decoder) -> Element:
    """Decode an element segment (restricted form only)."""
    tableidx = dec.read_u32_leb128()
    if tableidx != 0:
        raise DecodeError(f"Only table 0 supported in element, got {tableidx}", offset=dec.pos, code="unsupported_element_form")

    # Offset must be: i32.const <val> end
    offset_start = dec.pos
    offset_expr = _decode_expression(dec)
    if len(offset_expr.instructions) != 1 or offset_expr.instructions[0].opcode != 0x41:
        raise DecodeError("Element offset must be i32.const followed by end", offset=offset_start, code="unsupported_element_form")

    # Init vector
    init_count = dec.read_vec_length()
    init = [dec.read_u32_leb128() for _ in range(init_count)]

    return Element(tableidx=tableidx, offset=offset_expr, init=init)


def _decode_code(dec: _Decoder, limits: Limits) -> Code:
    """Decode a code entry (function body)."""
    body_size = dec.read_u32_leb128()
    if body_size > limits.max_function_body_bytes:
        raise DecodeError(f"Function body size {body_size} exceeds limit", offset=dec.pos, code="limit_exceeded")

    body_start = dec.pos
    body_end = body_start + body_size

    # Locals
    locals_count = dec.read_vec_length()
    locals = []
    total_locals = 0
    for _ in range(locals_count):
        count = dec.read_u32_leb128()
        valtype = _decode_valtype(dec)
        locals.append((count, valtype))
        total_locals += count
        if total_locals > limits.max_locals_per_function:
            raise DecodeError(f"Total locals {total_locals} exceeds limit", offset=dec.pos, code="limit_exceeded")

    # Expression
    expr = _decode_expression(dec)

    # Check exact size
    if dec.pos != body_end:
        raise DecodeError(f"Function body size mismatch: expected {body_size}, got {dec.pos - body_start}", offset=body_start, code="section_size_mismatch")

    return Code(locals=locals, body=expr)


def _decode_data(dec: _Decoder) -> Data:
    """Decode a data segment (restricted form only)."""
    memidx = dec.read_u32_leb128()
    if memidx != 0:
        raise DecodeError(f"Only memory 0 supported in data, got {memidx}", offset=dec.pos, code="unsupported_data_form")

    # Offset must be: i32.const <val> end
    offset_start = dec.pos
    offset_expr = _decode_expression(dec)
    if len(offset_expr.instructions) != 1 or offset_expr.instructions[0].opcode != 0x41:
        raise DecodeError("Data offset must be i32.const followed by end", offset=offset_start, code="unsupported_data_form")

    # Init bytes
    init_len = dec.read_u32_leb128()
    init_bytes = dec.read_bytes(init_len)

    return Data(memidx=memidx, offset=offset_expr, init=init_bytes)


def _decode_section(dec: _Decoder, section_id: int, payload_len: int, limits: Limits) -> tuple:
    """Decode a section payload based on section_id."""
    section_start = dec.pos
    section_end = section_start + payload_len

    if section_id == 0:  # Custom
        if payload_len > limits.max_custom_section_bytes:
            raise DecodeError(f"Custom section size {payload_len} exceeds limit", offset=section_start, code="limit_exceeded")
        name = dec.read_name()
        data = dec.read_bytes(section_end - dec.pos)
        result = CustomSection(name=name, data=data)
    elif section_id == 1:  # Type
        count = dec.read_vec_length()
        result = [_decode_functype(dec) for _ in range(count)]
    elif section_id == 2:  # Import
        count = dec.read_vec_length()
        result = [_decode_import(dec) for _ in range(count)]
    elif section_id == 3:  # Function
        count = dec.read_vec_length()
        result = [dec.read_u32_leb128() for _ in range(count)]
    elif section_id == 4:  # Table
        count = dec.read_vec_length()
        result = [_decode_table(dec) for _ in range(count)]
    elif section_id == 5:  # Memory
        count = dec.read_vec_length()
        result = [_decode_memory(dec) for _ in range(count)]
    elif section_id == 6:  # Global
        count = dec.read_vec_length()
        result = [_decode_global(dec) for _ in range(count)]
    elif section_id == 7:  # Export
        count = dec.read_vec_length()
        result = [_decode_export(dec) for _ in range(count)]
    elif section_id == 8:  # Start
        result = dec.read_u32_leb128()
    elif section_id == 9:  # Element
        count = dec.read_vec_length()
        result = [_decode_element(dec) for _ in range(count)]
    elif section_id == 10:  # Code
        count = dec.read_vec_length()
        result = [_decode_code(dec, limits) for _ in range(count)]
    elif section_id == 11:  # Data
        count = dec.read_vec_length()
        result = [_decode_data(dec) for _ in range(count)]
    elif section_id == 12:  # Data count
        result = dec.read_u32_leb128()
    else:
        raise DecodeError(f"Unknown section ID {section_id}", offset=section_start - 5, code="unknown_section_id")

    # Check exact payload consumption
    if dec.pos != section_end:
        raise DecodeError(f"Section {section_id} size mismatch", offset=section_start, code="section_size_mismatch")

    return (section_id, result)


# ----------------------------
# Public API functions
# ----------------------------

def decode_module(data: bytes, *, limits: Limits = Limits()) -> Module:
    """
    Decode a WASM binary module (subset) into a Module AST.

    Raises:
        DecodeError: on malformed input or unsupported forms.
    """
    # Check module size limit
    original_data_len = len(data)
    if original_data_len > limits.max_module_bytes:
        raise DecodeError(f"Module size {original_data_len} exceeds limit {limits.max_module_bytes}", code="limit_exceeded")

    dec = _Decoder(data, limits)

    # Check magic
    magic = dec.read_bytes(4)
    if magic != b"\x00asm":
        raise DecodeError(f"Invalid magic: {magic.hex()}", offset=0, code="bad_magic")

    # Check version
    version = dec.read_bytes(4)
    if version != b"\x01\x00\x00\x00":
        raise DecodeError(f"Invalid version: {version.hex()}", offset=4, code="bad_version")

    # Parse sections
    types: List[FuncType] = []
    imports: List[Import] = []
    function_types: List[int] = []
    tables: List[Table] = []
    memories: List[Memory] = []
    globals: List[Global] = []
    exports: List[Export] = []
    start: Optional[int] = None
    elements: List[Element] = []
    code: List[Code] = []
    data: List[Data] = []
    data_count: Optional[int] = None
    customs: List[CustomSection] = []

    while dec.remaining() > 0:
        section_id = dec.read_byte()
        payload_len = dec.read_u32_leb128()

        if payload_len > limits.max_section_bytes and section_id != 0:
            raise DecodeError(f"Section {section_id} size {payload_len} exceeds limit", offset=dec.pos, code="limit_exceeded")

        # Check section ordering (custom sections can appear anywhere)
        if section_id != 0:
            if section_id in dec.seen_sections:
                raise DecodeError(f"Duplicate section {section_id}", offset=dec.pos - 1, code="section_order")
            if section_id <= dec.last_section_id:
                raise DecodeError(f"Section {section_id} out of order", offset=dec.pos - 1, code="section_order")
            dec.seen_sections.add(section_id)
            dec.last_section_id = section_id

        sid, result = _decode_section(dec, section_id, payload_len, limits)

        if sid == 0:
            customs.append(result)
        elif sid == 1:
            types = result
        elif sid == 2:
            imports = result
        elif sid == 3:
            function_types = result
        elif sid == 4:
            tables = result
        elif sid == 5:
            memories = result
        elif sid == 6:
            globals = result
        elif sid == 7:
            exports = result
        elif sid == 8:
            start = result
        elif sid == 9:
            elements = result
        elif sid == 10:
            code = result
        elif sid == 11:
            data = result
        elif sid == 12:
            data_count = result

    return Module(
        raw_size=original_data_len,
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
        data=data,
        data_count=data_count,
        customs=customs,
    )


def validate_module(module: Module) -> List[ValidationError]:
    """
    Perform structural validation on a decoded module.

    Returns:
        List[ValidationError]: empty if valid.
    """
    errors: List[ValidationError] = []

    # Compute index spaces
    func_imports = sum(1 for imp in module.imports if imp.desc.kind == 0)
    table_imports = sum(1 for imp in module.imports if imp.desc.kind == 1)
    mem_imports = sum(1 for imp in module.imports if imp.desc.kind == 2)
    global_imports = sum(1 for imp in module.imports if imp.desc.kind == 3)

    funcs_total = func_imports + len(module.function_types)
    tables_total = table_imports + len(module.tables)
    mems_total = mem_imports + len(module.memories)
    globals_total = global_imports + len(module.globals)

    # Validate limits
    for table in module.tables:
        if table.limits.max is not None and table.limits.min > table.limits.max:
            errors.append(ValidationError(code="limits_min_gt_max", message=f"Table limits min {table.limits.min} > max {table.limits.max}"))

    for memory in module.memories:
        if memory.limits.max is not None and memory.limits.min > memory.limits.max:
            errors.append(ValidationError(code="limits_min_gt_max", message=f"Memory limits min {memory.limits.min} > max {memory.limits.max}"))

    for imp in module.imports:
        if imp.desc.kind == 1 and imp.desc.table_limits:
            if imp.desc.table_limits.max is not None and imp.desc.table_limits.min > imp.desc.table_limits.max:
                errors.append(ValidationError(code="limits_min_gt_max", message=f"Imported table limits min > max"))
        elif imp.desc.kind == 2 and imp.desc.mem_limits:
            if imp.desc.mem_limits.max is not None and imp.desc.mem_limits.min > imp.desc.mem_limits.max:
                errors.append(ValidationError(code="limits_min_gt_max", message=f"Imported memory limits min > max"))

    # Validate import typeidx
    for imp in module.imports:
        if imp.desc.kind == 0 and imp.desc.typeidx is not None:
            if imp.desc.typeidx >= len(module.types):
                errors.append(ValidationError(code="type_index_out_of_range", message=f"Import func typeidx {imp.desc.typeidx} >= {len(module.types)}"))

    # Validate function typeidx
    for i, typeidx in enumerate(module.function_types):
        if typeidx >= len(module.types):
            errors.append(ValidationError(code="type_index_out_of_range", message=f"Function {i} typeidx {typeidx} >= {len(module.types)}", context=f"func {i}"))

    # Validate exports
    export_names = set()
    for exp in module.exports:
        if exp.name in export_names:
            errors.append(ValidationError(code="duplicate_export_name", message=f"Duplicate export name: {exp.name}"))
        export_names.add(exp.name)

        if exp.kind == 0:  # func
            if exp.index >= funcs_total:
                errors.append(ValidationError(code="index_out_of_range", message=f"Export func index {exp.index} >= {funcs_total}"))
        elif exp.kind == 1:  # table
            if exp.index >= tables_total:
                errors.append(ValidationError(code="index_out_of_range", message=f"Export table index {exp.index} >= {tables_total}"))
        elif exp.kind == 2:  # memory
            if exp.index >= mems_total:
                errors.append(ValidationError(code="index_out_of_range", message=f"Export memory index {exp.index} >= {mems_total}"))
        elif exp.kind == 3:  # global
            if exp.index >= globals_total:
                errors.append(ValidationError(code="index_out_of_range", message=f"Export global index {exp.index} >= {globals_total}"))

    # Validate start function
    if module.start is not None:
        if module.start >= funcs_total:
            errors.append(ValidationError(code="index_out_of_range", message=f"Start func index {module.start} >= {funcs_total}"))
        else:
            # Check signature
            if module.start < func_imports:
                # Imported function
                func_imp = [imp for imp in module.imports if imp.desc.kind == 0][module.start]
                typeidx = func_imp.desc.typeidx
            else:
                # Defined function
                typeidx = module.function_types[module.start - func_imports]

            if typeidx is not None and typeidx < len(module.types):
                func_type = module.types[typeidx]
                if len(func_type.params) != 0 or len(func_type.results) != 0:
                    errors.append(ValidationError(code="bad_start_signature", message=f"Start function must have signature [] -> [], got {func_type.params} -> {func_type.results}"))

    # Validate code section count
    if len(module.code) != len(module.function_types):
        errors.append(ValidationError(code="func_code_count_mismatch", message=f"Code count {len(module.code)} != function count {len(module.function_types)}"))

    # Validate code bodies
    for i, code_entry in enumerate(module.code):
        func_idx = func_imports + i
        if i < len(module.function_types):
            typeidx = module.function_types[i]
            if typeidx < len(module.types):
                func_type = module.types[typeidx]
                num_params = len(func_type.params)
                num_locals = sum(count for count, _ in code_entry.locals)
                total_locals = num_params + num_locals

                # Validate local indices
                for instr in code_entry.body.instructions:
                    if instr.opcode in (0x20, 0x21):  # local.get, local.set
                        if instr.immediate is not None and instr.immediate >= total_locals:
                            errors.append(ValidationError(code="local_index_out_of_range", message=f"Local index {instr.immediate} >= {total_locals}", context=f"func {func_idx}"))
                    elif instr.opcode == 0x10:  # call
                        if instr.immediate is not None and instr.immediate >= funcs_total:
                            errors.append(ValidationError(code="index_out_of_range", message=f"Call funcidx {instr.immediate} >= {funcs_total}", context=f"func {func_idx}"))

    # Validate element segments
    for elem in module.elements:
        for funcidx in elem.init:
            if funcidx >= funcs_total:
                errors.append(ValidationError(code="index_out_of_range", message=f"Element funcidx {funcidx} >= {funcs_total}"))

    # Validate data count
    if module.data_count is not None:
        if module.data_count != len(module.data):
            errors.append(ValidationError(code="data_count_mismatch", message=f"Data count {module.data_count} != actual data segments {len(module.data)}"))

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

