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
# AST dataclasses
# ----------------------------

class ValType(IntEnum):
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


@dataclass(frozen=True)
class TableType:
    elemtype: int  # 0x70 for funcref
    limits: TableLimits


# Instructions
@dataclass(frozen=True)
class I32Const:
    value: int


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
    instrs: List[Instruction]


# Import descriptors
@dataclass(frozen=True)
class ImportFunc:
    module: bytes
    name: bytes
    typeidx: int


@dataclass(frozen=True)
class ImportTable:
    module: bytes
    name: bytes
    tabletype: TableType


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


@dataclass(frozen=True)
class Export:
    name: bytes
    kind: int  # 0=func, 1=table, 2=mem, 3=global
    index: int


@dataclass(frozen=True)
class Global:
    globaltype: GlobalType
    init: Expression


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
    offset: Expression
    init: List[int]


@dataclass(frozen=True)
class DataSegment:
    memidx: int
    offset: Expression
    data: bytes


@dataclass(frozen=True)
class CustomSection:
    name: bytes
    data: bytes


@dataclass
class Module:
    """Decoded AST for a WASM module."""
    raw_size: int
    types: List[FuncType] = field(default_factory=list)
    imports: List[Import] = field(default_factory=list)
    function_typeidxs: List[int] = field(default_factory=list)
    tables: List[TableType] = field(default_factory=list)
    mems: List[MemLimits] = field(default_factory=list)
    globals: List[Global] = field(default_factory=list)
    exports: List[Export] = field(default_factory=list)
    start: Optional[int] = None
    elems: List[ElemSegment] = field(default_factory=list)
    code: List[FuncBody] = field(default_factory=list)
    datas: List[DataSegment] = field(default_factory=list)
    data_count: Optional[int] = None
    customs: List[CustomSection] = field(default_factory=list)


# ----------------------------
# LEB128 decoding
# ----------------------------

class Reader:
    def __init__(self, data: bytes, limits: Limits):
        self.data = data
        self.pos = 0
        self.limits = limits

    def eof(self) -> bool:
        return self.pos >= len(self.data)

    def read_byte(self) -> int:
        if self.pos >= len(self.data):
            raise DecodeError("Unexpected EOF", offset=self.pos)
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_bytes(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise DecodeError("Unexpected EOF", offset=self.pos)
        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result

    def read_u32(self) -> int:
        """Read unsigned LEB128 as u32."""
        result = 0
        shift = 0
        for i in range(5):  # max 5 bytes for u32
            if self.pos >= len(self.data):
                raise DecodeError("Truncated LEB128", offset=self.pos)
            b = self.data[self.pos]
            self.pos += 1
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                # Check for overlong encoding
                if i == 4 and (b & 0xF0) != 0:
                    raise DecodeError("LEB128 overflow for u32", offset=self.pos - 1)
                # Check if result fits in u32
                if result > 0xFFFFFFFF:
                    raise DecodeError("LEB128 overflow for u32", offset=self.pos - 1)
                return result
            shift += 7
        raise DecodeError("LEB128 overflow for u32", offset=self.pos)

    def read_s32(self) -> int:
        """Read signed LEB128 as s32."""
        result = 0
        shift = 0
        for i in range(5):  # max 5 bytes for s32
            if self.pos >= len(self.data):
                raise DecodeError("Truncated LEB128", offset=self.pos)
            b = self.data[self.pos]
            self.pos += 1
            result |= (b & 0x7F) << shift
            shift += 7
            if (b & 0x80) == 0:
                # Sign extend
                if shift < 32 and (b & 0x40):
                    result |= -(1 << shift)
                # Check if result fits in s32
                if result < -(2**31) or result > (2**31 - 1):
                    raise DecodeError("LEB128 overflow for s32", offset=self.pos - 1)
                return result
        raise DecodeError("LEB128 overflow for s32", offset=self.pos)

    def read_name(self) -> bytes:
        """Read a name (length-prefixed bytes)."""
        length = self.read_u32()
        return self.read_bytes(length)

    def peek_byte(self) -> int:
        if self.pos >= len(self.data):
            raise DecodeError("Unexpected EOF", offset=self.pos)
        return self.data[self.pos]


# ----------------------------
# Decoder
# ----------------------------

def decode_valtype(r: Reader) -> ValType:
    b = r.read_byte()
    if b == 0x7F:
        return ValType.I32
    elif b == 0x7E:
        return ValType.I64
    else:
        raise DecodeError(f"Unsupported valtype: 0x{b:02X}", offset=r.pos - 1, code="unsupported_valtype")


def decode_functype(r: Reader) -> FuncType:
    tag = r.read_byte()
    if tag != 0x60:
        raise DecodeError(f"Expected functype tag 0x60, got 0x{tag:02X}", offset=r.pos - 1)

    # Read params
    param_count = r.read_u32()
    if param_count > r.limits.max_vector_length:
        raise DecodeError(f"Vector length {param_count} exceeds limit", offset=r.pos)
    params = [decode_valtype(r) for _ in range(param_count)]

    # Read results
    result_count = r.read_u32()
    if result_count > r.limits.max_vector_length:
        raise DecodeError(f"Vector length {result_count} exceeds limit", offset=r.pos)
    results = [decode_valtype(r) for _ in range(result_count)]

    return FuncType(params, results)


def decode_limits(r: Reader) -> Union[TableLimits, MemLimits]:
    flags = r.read_byte()
    if flags == 0x00:
        min_val = r.read_u32()
        return TableLimits(min_val, None)
    elif flags == 0x01:
        min_val = r.read_u32()
        max_val = r.read_u32()
        return TableLimits(min_val, max_val)
    else:
        raise DecodeError(f"Bad limits flag: 0x{flags:02X}", offset=r.pos - 1, code="bad_limits_flag")


def decode_tabletype(r: Reader) -> TableType:
    elemtype = r.read_byte()
    if elemtype != 0x70:
        raise DecodeError(f"Unsupported table elemtype: 0x{elemtype:02X}", offset=r.pos - 1,
                         code="unsupported_table_elemtype")
    limits = decode_limits(r)
    return TableType(elemtype, limits)


def decode_globaltype(r: Reader) -> GlobalType:
    valtype = decode_valtype(r)
    mut = r.read_byte()
    if mut == 0x00:
        mutable = False
    elif mut == 0x01:
        mutable = True
    else:
        raise DecodeError(f"Bad mutability: 0x{mut:02X}", offset=r.pos - 1, code="bad_mutability")
    return GlobalType(valtype, mutable)


def decode_expression(r: Reader, max_bytes: Optional[int] = None) -> Expression:
    """Decode a restricted expression."""
    start_pos = r.pos
    instrs: List[Instruction] = []

    while True:
        if max_bytes and (r.pos - start_pos) > max_bytes:
            raise DecodeError("Expression exceeds max bytes", offset=r.pos)

        opcode = r.read_byte()

        if opcode == 0x41:  # i32.const
            value = r.read_s32()
            instrs.append(I32Const(value))
        elif opcode == 0x20:  # local.get
            localidx = r.read_u32()
            instrs.append(LocalGet(localidx))
        elif opcode == 0x21:  # local.set
            localidx = r.read_u32()
            instrs.append(LocalSet(localidx))
        elif opcode == 0x6A:  # i32.add
            instrs.append(I32Add())
        elif opcode == 0x10:  # call
            funcidx = r.read_u32()
            instrs.append(Call(funcidx))
        elif opcode == 0x0B:  # end
            instrs.append(End())
            return Expression(instrs)
        else:
            raise DecodeError(f"Unsupported opcode: 0x{opcode:02X}", offset=r.pos - 1,
                            code="unsupported_opcode")


def decode_import(r: Reader) -> Import:
    module = r.read_name()
    name = r.read_name()
    kind = r.read_byte()

    if kind == 0:  # func
        typeidx = r.read_u32()
        return ImportFunc(module, name, typeidx)
    elif kind == 1:  # table
        tabletype = decode_tabletype(r)
        return ImportTable(module, name, tabletype)
    elif kind == 2:  # mem
        limits = decode_limits(r)
        return ImportMem(module, name, limits)
    elif kind == 3:  # global
        globaltype = decode_globaltype(r)
        return ImportGlobal(module, name, globaltype)
    else:
        raise DecodeError(f"Unknown import kind: {kind}", offset=r.pos - 1)


def decode_export(r: Reader) -> Export:
    name = r.read_name()
    kind = r.read_byte()
    index = r.read_u32()
    return Export(name, kind, index)


def decode_global(r: Reader) -> Global:
    globaltype = decode_globaltype(r)
    init = decode_expression(r)
    return Global(globaltype, init)


def decode_elem_segment(r: Reader) -> ElemSegment:
    """Decode element segment (restricted form only)."""
    tableidx = r.read_u32()
    if tableidx != 0:
        raise DecodeError(f"Unsupported element form: tableidx={tableidx}",
                         offset=r.pos - 1, code="unsupported_element_form")

    # Decode offset expression - must be i32.const ; end
    offset = decode_expression(r)
    if len(offset.instrs) != 2:
        raise DecodeError("Element offset must be i32.const ; end",
                         offset=r.pos, code="unsupported_element_form")
    if not isinstance(offset.instrs[0], I32Const) or not isinstance(offset.instrs[1], End):
        raise DecodeError("Element offset must be i32.const ; end",
                         offset=r.pos, code="unsupported_element_form")

    # Read init vector
    count = r.read_u32()
    if count > r.limits.max_vector_length:
        raise DecodeError(f"Vector length {count} exceeds limit", offset=r.pos)
    init = [r.read_u32() for _ in range(count)]

    return ElemSegment(tableidx, offset, init)


def decode_data_segment(r: Reader) -> DataSegment:
    """Decode data segment (restricted form only)."""
    memidx = r.read_u32()
    if memidx != 0:
        raise DecodeError(f"Unsupported data form: memidx={memidx}",
                         offset=r.pos - 1, code="unsupported_data_form")

    # Decode offset expression - must be i32.const ; end
    offset = decode_expression(r)
    if len(offset.instrs) != 2:
        raise DecodeError("Data offset must be i32.const ; end",
                         offset=r.pos, code="unsupported_data_form")
    if not isinstance(offset.instrs[0], I32Const) or not isinstance(offset.instrs[1], End):
        raise DecodeError("Data offset must be i32.const ; end",
                         offset=r.pos, code="unsupported_data_form")

    # Read data bytes
    length = r.read_u32()
    data = r.read_bytes(length)

    return DataSegment(memidx, offset, data)


def decode_func_body(r: Reader, limits: Limits) -> FuncBody:
    """Decode a function body."""
    body_size = r.read_u32()
    if body_size > limits.max_function_body_bytes:
        raise DecodeError(f"Function body size {body_size} exceeds limit", offset=r.pos)

    body_start = r.pos
    body_end = body_start + body_size

    # Read locals
    locals_count = r.read_u32()
    if locals_count > limits.max_vector_length:
        raise DecodeError(f"Vector length {locals_count} exceeds limit", offset=r.pos)

    locals: List[LocalDecl] = []
    total_locals = 0
    for _ in range(locals_count):
        count = r.read_u32()
        valtype = decode_valtype(r)
        locals.append(LocalDecl(count, valtype))
        total_locals += count
        if total_locals > limits.max_locals_per_function:
            raise DecodeError(f"Total locals {total_locals} exceeds limit", offset=r.pos)

    # Read expression
    expr = decode_expression(r)

    # Check exact size
    if r.pos != body_end:
        raise DecodeError("Function body size mismatch", offset=r.pos, code="section_size_mismatch")

    return FuncBody(locals, expr)


def decode_section(r: Reader, limits: Limits, module: Module, section_id: int,
                   payload_len: int, seen_sections: set) -> None:
    """Decode a section and update the module."""
    section_start = r.pos
    section_end = section_start + payload_len

    # Check payload size
    if section_id == 0:  # custom section
        if payload_len > limits.max_custom_section_bytes:
            raise DecodeError(f"Custom section size {payload_len} exceeds limit", offset=r.pos)
    else:
        if payload_len > limits.max_section_bytes:
            raise DecodeError(f"Section size {payload_len} exceeds limit", offset=r.pos)

    if section_id == 0:  # custom
        name = r.read_name()
        data = r.read_bytes(section_end - r.pos)
        module.customs.append(CustomSection(name, data))

    elif section_id == 1:  # type
        count = r.read_u32()
        if count > limits.max_vector_length:
            raise DecodeError(f"Vector length {count} exceeds limit", offset=r.pos)
        module.types.extend([decode_functype(r) for _ in range(count)])

    elif section_id == 2:  # import
        count = r.read_u32()
        if count > limits.max_vector_length:
            raise DecodeError(f"Vector length {count} exceeds limit", offset=r.pos)
        module.imports.extend([decode_import(r) for _ in range(count)])

    elif section_id == 3:  # function
        count = r.read_u32()
        if count > limits.max_vector_length:
            raise DecodeError(f"Vector length {count} exceeds limit", offset=r.pos)
        module.function_typeidxs.extend([r.read_u32() for _ in range(count)])

    elif section_id == 4:  # table
        count = r.read_u32()
        if count > limits.max_vector_length:
            raise DecodeError(f"Vector length {count} exceeds limit", offset=r.pos)
        module.tables.extend([decode_tabletype(r) for _ in range(count)])

    elif section_id == 5:  # memory
        count = r.read_u32()
        if count > limits.max_vector_length:
            raise DecodeError(f"Vector length {count} exceeds limit", offset=r.pos)
        module.mems.extend([decode_limits(r) for _ in range(count)])

    elif section_id == 6:  # global
        count = r.read_u32()
        if count > limits.max_vector_length:
            raise DecodeError(f"Vector length {count} exceeds limit", offset=r.pos)
        module.globals.extend([decode_global(r) for _ in range(count)])

    elif section_id == 7:  # export
        count = r.read_u32()
        if count > limits.max_vector_length:
            raise DecodeError(f"Vector length {count} exceeds limit", offset=r.pos)
        module.exports.extend([decode_export(r) for _ in range(count)])

    elif section_id == 8:  # start
        module.start = r.read_u32()

    elif section_id == 9:  # element
        count = r.read_u32()
        if count > limits.max_vector_length:
            raise DecodeError(f"Vector length {count} exceeds limit", offset=r.pos)
        module.elems.extend([decode_elem_segment(r) for _ in range(count)])

    elif section_id == 10:  # code
        count = r.read_u32()
        if count > limits.max_vector_length:
            raise DecodeError(f"Vector length {count} exceeds limit", offset=r.pos)
        module.code.extend([decode_func_body(r, limits) for _ in range(count)])

    elif section_id == 11:  # data
        count = r.read_u32()
        if count > limits.max_vector_length:
            raise DecodeError(f"Vector length {count} exceeds limit", offset=r.pos)
        module.datas.extend([decode_data_segment(r) for _ in range(count)])

    elif section_id == 12:  # data count
        module.data_count = r.read_u32()

    else:
        raise DecodeError(f"Unknown section id: {section_id}", offset=section_start,
                         code="unknown_section_id")

    # Check exact payload consumption
    if r.pos != section_end:
        raise DecodeError("Section payload size mismatch", offset=r.pos,
                         code="section_size_mismatch")


def decode_module(data: bytes, *, limits: Limits = Limits()) -> Module:
    """
    Decode a WASM binary module (subset) into a Module AST.

    Raises:
        DecodeError: on malformed input or unsupported forms.
    """
    if len(data) > limits.max_module_bytes:
        raise DecodeError(f"Module size {len(data)} exceeds limit {limits.max_module_bytes}")

    r = Reader(data, limits)

    # Check magic
    magic = r.read_bytes(4)
    if magic != b'\x00asm':
        raise DecodeError(f"Invalid magic: {magic!r}", offset=0)

    # Check version
    version = r.read_bytes(4)
    if version != b'\x01\x00\x00\x00':
        raise DecodeError(f"Invalid version: {version!r}", offset=4)

    module = Module(raw_size=len(data))
    seen_sections = set()
    last_section_id = -1

    while not r.eof():
        section_id = r.read_byte()
        payload_len = r.read_u32()

        # Check section ordering
        if section_id != 0:  # non-custom section
            if section_id in seen_sections:
                raise DecodeError(f"Duplicate section {section_id}", offset=r.pos - 1,
                                 code="section_order")
            if section_id < last_section_id:
                raise DecodeError(f"Section {section_id} out of order", offset=r.pos - 1,
                                 code="section_order")
            seen_sections.add(section_id)
            last_section_id = section_id

        decode_section(r, limits, module, section_id, payload_len, seen_sections)

    return module


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
    imported_mems = sum(1 for imp in module.imports if isinstance(imp, ImportMem))
    imported_globals = sum(1 for imp in module.imports if isinstance(imp, ImportGlobal))

    funcs_total = imported_funcs + len(module.function_typeidxs)
    tables_total = imported_tables + len(module.tables)
    mems_total = imported_mems + len(module.mems)
    globals_total = imported_globals + len(module.globals)

    # Validate limits
    for table in module.tables:
        if table.limits.max is not None and table.limits.min > table.limits.max:
            errors.append(ValidationError("limits_min_gt_max",
                                         f"Table limits min {table.limits.min} > max {table.limits.max}"))

    for mem in module.mems:
        if mem.max is not None and mem.min > mem.max:
            errors.append(ValidationError("limits_min_gt_max",
                                         f"Memory limits min {mem.min} > max {mem.max}"))

    # Validate import typeidx
    for imp in module.imports:
        if isinstance(imp, ImportFunc):
            if imp.typeidx >= len(module.types):
                errors.append(ValidationError("type_index_out_of_range",
                                             f"Import func typeidx {imp.typeidx} >= {len(module.types)}"))

    # Validate function typeidx
    for idx, typeidx in enumerate(module.function_typeidxs):
        if typeidx >= len(module.types):
            errors.append(ValidationError("type_index_out_of_range",
                                         f"Function {idx} typeidx {typeidx} >= {len(module.types)}"))

    # Validate exports
    export_names = set()
    for exp in module.exports:
        # Check for duplicate names
        if exp.name in export_names:
            errors.append(ValidationError("duplicate_export_name",
                                         f"Duplicate export name: {exp.name!r}"))
        export_names.add(exp.name)

        # Check index range
        if exp.kind == 0:  # func
            if exp.index >= funcs_total:
                errors.append(ValidationError("index_out_of_range",
                                             f"Export func index {exp.index} >= {funcs_total}"))
        elif exp.kind == 1:  # table
            if exp.index >= tables_total:
                errors.append(ValidationError("index_out_of_range",
                                             f"Export table index {exp.index} >= {tables_total}"))
        elif exp.kind == 2:  # mem
            if exp.index >= mems_total:
                errors.append(ValidationError("index_out_of_range",
                                             f"Export mem index {exp.index} >= {mems_total}"))
        elif exp.kind == 3:  # global
            if exp.index >= globals_total:
                errors.append(ValidationError("index_out_of_range",
                                             f"Export global index {exp.index} >= {globals_total}"))

    # Validate start function
    if module.start is not None:
        if module.start >= funcs_total:
            errors.append(ValidationError("index_out_of_range",
                                         f"Start func index {module.start} >= {funcs_total}"))
        else:
            # Get the type of the start function
            if module.start < imported_funcs:
                # It's an imported function
                func_imports = [imp for imp in module.imports if isinstance(imp, ImportFunc)]
                typeidx = func_imports[module.start].typeidx
            else:
                # It's a defined function
                typeidx = module.function_typeidxs[module.start - imported_funcs]

            if typeidx < len(module.types):
                functype = module.types[typeidx]
                if functype.params or functype.results:
                    errors.append(ValidationError("bad_start_signature",
                                                 f"Start function must have type [] -> [], got {functype.params} -> {functype.results}"))

    # Validate element segments
    for elem in module.elems:
        for funcidx in elem.init:
            if funcidx >= funcs_total:
                errors.append(ValidationError("index_out_of_range",
                                             f"Element func index {funcidx} >= {funcs_total}"))

    # Validate code section count
    if len(module.code) != len(module.function_typeidxs):
        errors.append(ValidationError("func_code_count_mismatch",
                                     f"Code count {len(module.code)} != function count {len(module.function_typeidxs)}"))

    # Validate code bodies
    for func_idx, body in enumerate(module.code):
        if func_idx >= len(module.function_typeidxs):
            continue

        typeidx = module.function_typeidxs[func_idx]
        if typeidx >= len(module.types):
            continue

        functype = module.types[typeidx]
        num_params = len(functype.params)
        num_locals = sum(decl.count for decl in body.locals)
        total_locals = num_params + num_locals

        # Validate local indices in expressions
        for instr in body.expr.instrs:
            if isinstance(instr, (LocalGet, LocalSet)):
                if instr.localidx >= total_locals:
                    errors.append(ValidationError("local_index_out_of_range",
                                                 f"Function {func_idx}: local index {instr.localidx} >= {total_locals}"))
            elif isinstance(instr, Call):
                if instr.funcidx >= funcs_total:
                    errors.append(ValidationError("index_out_of_range",
                                                 f"Function {func_idx}: call funcidx {instr.funcidx} >= {funcs_total}"))

    # Validate data count
    if module.data_count is not None:
        if module.data_count != len(module.datas):
            errors.append(ValidationError("data_count_mismatch",
                                         f"Data count {module.data_count} != data segments {len(module.datas)}"))

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
