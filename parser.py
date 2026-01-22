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
class MemoryLimits:
    min: int
    max: Optional[int] = None


@dataclass(frozen=True)
class TableType:
    elemtype: int  # 0x70 for funcref
    limits: TableLimits


@dataclass(frozen=True)
class GlobalType:
    valtype: ValType
    mutable: bool


@dataclass(frozen=True)
class ImportDesc:
    pass


@dataclass(frozen=True)
class ImportFunc(ImportDesc):
    typeidx: int


@dataclass(frozen=True)
class ImportTable(ImportDesc):
    tabletype: TableType


@dataclass(frozen=True)
class ImportMemory(ImportDesc):
    memtype: MemoryLimits


@dataclass(frozen=True)
class ImportGlobal(ImportDesc):
    globaltype: GlobalType


@dataclass(frozen=True)
class Import:
    module: bytes
    name: bytes
    desc: ImportDesc


class Opcode(IntEnum):
    END = 0x0B
    CALL = 0x10
    LOCAL_GET = 0x20
    LOCAL_SET = 0x21
    I32_CONST = 0x41
    I32_ADD = 0x6A


@dataclass(frozen=True)
class Instr:
    pass


@dataclass(frozen=True)
class End(Instr):
    pass


@dataclass(frozen=True)
class Call(Instr):
    funcidx: int


@dataclass(frozen=True)
class LocalGet(Instr):
    localidx: int


@dataclass(frozen=True)
class LocalSet(Instr):
    localidx: int


@dataclass(frozen=True)
class I32Const(Instr):
    value: int


@dataclass(frozen=True)
class I32Add(Instr):
    pass


@dataclass(frozen=True)
class Expr:
    instrs: List[Instr]


@dataclass(frozen=True)
class Global:
    type: GlobalType
    init: Expr


@dataclass(frozen=True)
class Export:
    name: bytes
    kind: int  # 0=func, 1=table, 2=mem, 3=global
    index: int


@dataclass(frozen=True)
class LocalDecl:
    count: int
    valtype: ValType


@dataclass(frozen=True)
class FuncBody:
    locals: List[LocalDecl]
    expr: Expr


@dataclass(frozen=True)
class ElemSegment:
    tableidx: int
    offset: Expr
    init: List[int]  # funcidx list


@dataclass(frozen=True)
class DataSegment:
    memidx: int
    offset: Expr
    data: bytes


@dataclass
class Module:
    """Decoded WASM module AST."""
    raw_size: int
    types: List[FuncType] = field(default_factory=list)
    imports: List[Import] = field(default_factory=list)
    funcs: List[int] = field(default_factory=list)  # type indices for defined funcs
    tables: List[TableType] = field(default_factory=list)
    memories: List[MemoryLimits] = field(default_factory=list)
    globals: List[Global] = field(default_factory=list)
    exports: List[Export] = field(default_factory=list)
    start: Optional[int] = None
    elems: List[ElemSegment] = field(default_factory=list)
    code: List[FuncBody] = field(default_factory=list)
    datas: List[DataSegment] = field(default_factory=list)
    datacount: Optional[int] = None
    customs: List[bytes] = field(default_factory=list)


# ----------------------------
# Binary decoder
# ----------------------------

class Decoder:
    """Binary decoder with offset tracking and limit enforcement."""

    def __init__(self, data: bytes, limits: Limits):
        self.data = data
        self.limits = limits
        self.offset = 0

        if len(data) > limits.max_module_bytes:
            raise DecodeError(f"Module size {len(data)} exceeds limit {limits.max_module_bytes}", code="module_size_limit")

    def eof(self) -> bool:
        return self.offset >= len(self.data)

    def remaining(self) -> int:
        return len(self.data) - self.offset

    def read_byte(self) -> int:
        if self.eof():
            raise DecodeError("Unexpected end of input", offset=self.offset, code="truncated")
        b = self.data[self.offset]
        self.offset += 1
        return b

    def read_bytes(self, n: int) -> bytes:
        if self.remaining() < n:
            raise DecodeError(f"Need {n} bytes but only {self.remaining()} available", offset=self.offset, code="truncated")
        result = self.data[self.offset:self.offset + n]
        self.offset += n
        return result

    def read_u32(self) -> int:
        """Read unsigned LEB128 u32."""
        result = 0
        shift = 0
        for i in range(5):  # u32 needs at most 5 bytes
            if self.eof():
                raise DecodeError("Truncated LEB128", offset=self.offset, code="truncated_leb128")

            byte = self.read_byte()
            result |= (byte & 0x7F) << shift

            if (byte & 0x80) == 0:
                # Check for overflow
                if shift >= 32:
                    raise DecodeError("LEB128 overflow for u32", offset=self.offset - i - 1, code="leb128_overflow")
                # Check for overlong encoding
                if shift > 0 and byte == 0:
                    raise DecodeError("Overlong LEB128 encoding", offset=self.offset - i - 1, code="overlong_leb128")
                if result > 0xFFFFFFFF:
                    raise DecodeError("LEB128 value exceeds u32 range", offset=self.offset - i - 1, code="leb128_overflow")
                return result

            shift += 7

        raise DecodeError("LEB128 too long for u32", offset=self.offset - 5, code="leb128_too_long")

    def read_s32(self) -> int:
        """Read signed LEB128 s32."""
        result = 0
        shift = 0
        for i in range(5):  # s32 needs at most 5 bytes
            if self.eof():
                raise DecodeError("Truncated LEB128", offset=self.offset, code="truncated_leb128")

            byte = self.read_byte()
            result |= (byte & 0x7F) << shift
            shift += 7

            if (byte & 0x80) == 0:
                # Sign extend
                if shift < 32 and (byte & 0x40):
                    result |= -(1 << shift)

                # Check range for s32
                if result < -(1 << 31) or result >= (1 << 31):
                    raise DecodeError("LEB128 value exceeds s32 range", offset=self.offset - i - 1, code="leb128_overflow")

                return result

        raise DecodeError("LEB128 too long for s32", offset=self.offset - 5, code="leb128_too_long")

    def read_name(self) -> bytes:
        """Read name (length-prefixed byte string)."""
        length = self.read_u32()
        return self.read_bytes(length)

    def read_vec(self, read_elem, context: str = "vector") -> list:
        """Read vector of elements."""
        count = self.read_u32()
        if count > self.limits.max_vector_length:
            raise DecodeError(f"Vector length {count} exceeds limit {self.limits.max_vector_length}", offset=self.offset, code="vector_length_limit")

        result = []
        for _ in range(count):
            result.append(read_elem())
        return result


# ----------------------------
# Section decoders
# ----------------------------

def decode_valtype(decoder: Decoder) -> ValType:
    """Decode a value type."""
    b = decoder.read_byte()
    if b == 0x7F:
        return ValType.I32
    elif b == 0x7E:
        return ValType.I64
    else:
        raise DecodeError(f"Unsupported valtype 0x{b:02X}", offset=decoder.offset - 1, code="unsupported_valtype")


def decode_functype(decoder: Decoder) -> FuncType:
    """Decode a function type."""
    tag = decoder.read_byte()
    if tag != 0x60:
        raise DecodeError(f"Expected functype tag 0x60, got 0x{tag:02X}", offset=decoder.offset - 1, code="bad_functype_tag")

    params = decoder.read_vec(lambda: decode_valtype(decoder), "functype params")
    results = decoder.read_vec(lambda: decode_valtype(decoder), "functype results")

    return FuncType(params=params, results=results)


def decode_limits(decoder: Decoder) -> Union[TableLimits, MemoryLimits]:
    """Decode limits."""
    flags = decoder.read_byte()

    if flags == 0x00:
        min_val = decoder.read_u32()
        return TableLimits(min=min_val, max=None)
    elif flags == 0x01:
        min_val = decoder.read_u32()
        max_val = decoder.read_u32()
        return TableLimits(min=min_val, max=max_val)
    else:
        raise DecodeError(f"Invalid limits flag 0x{flags:02X}", offset=decoder.offset - 1, code="bad_limits_flag")


def decode_tabletype(decoder: Decoder) -> TableType:
    """Decode a table type."""
    elemtype = decoder.read_byte()
    if elemtype != 0x70:
        raise DecodeError(f"Unsupported table elemtype 0x{elemtype:02X}", offset=decoder.offset - 1, code="unsupported_table_elemtype")

    limits = decode_limits(decoder)
    return TableType(elemtype=elemtype, limits=limits)


def decode_globaltype(decoder: Decoder) -> GlobalType:
    """Decode a global type."""
    valtype = decode_valtype(decoder)
    mut = decoder.read_byte()

    if mut == 0x00:
        mutable = False
    elif mut == 0x01:
        mutable = True
    else:
        raise DecodeError(f"Invalid mutability 0x{mut:02X}", offset=decoder.offset - 1, code="bad_mutability")

    return GlobalType(valtype=valtype, mutable=mutable)


def decode_expr(decoder: Decoder, end_offset: Optional[int] = None) -> Expr:
    """Decode an expression (sequence of instructions ending with 0x0B)."""
    instrs = []

    while True:
        if end_offset is not None and decoder.offset >= end_offset:
            raise DecodeError("Expression missing end opcode", offset=decoder.offset, code="missing_end")

        opcode = decoder.read_byte()

        if opcode == Opcode.END:
            instrs.append(End())
            break
        elif opcode == Opcode.I32_CONST:
            value = decoder.read_s32()
            instrs.append(I32Const(value=value))
        elif opcode == Opcode.LOCAL_GET:
            localidx = decoder.read_u32()
            instrs.append(LocalGet(localidx=localidx))
        elif opcode == Opcode.LOCAL_SET:
            localidx = decoder.read_u32()
            instrs.append(LocalSet(localidx=localidx))
        elif opcode == Opcode.I32_ADD:
            instrs.append(I32Add())
        elif opcode == Opcode.CALL:
            funcidx = decoder.read_u32()
            instrs.append(Call(funcidx=funcidx))
        else:
            raise DecodeError(f"Unsupported opcode 0x{opcode:02X}", offset=decoder.offset - 1, code="unsupported_opcode")

    return Expr(instrs=instrs)


def decode_import(decoder: Decoder) -> Import:
    """Decode an import."""
    module = decoder.read_name()
    name = decoder.read_name()
    kind = decoder.read_byte()

    if kind == 0:  # func
        typeidx = decoder.read_u32()
        desc = ImportFunc(typeidx=typeidx)
    elif kind == 1:  # table
        tabletype = decode_tabletype(decoder)
        desc = ImportTable(tabletype=tabletype)
    elif kind == 2:  # memory
        memtype = decode_limits(decoder)
        desc = ImportMemory(memtype=memtype)
    elif kind == 3:  # global
        globaltype = decode_globaltype(decoder)
        desc = ImportGlobal(globaltype=globaltype)
    else:
        raise DecodeError(f"Unknown import kind {kind}", offset=decoder.offset - 1, code="unknown_import_kind")

    return Import(module=module, name=name, desc=desc)


def decode_global(decoder: Decoder) -> Global:
    """Decode a global."""
    globaltype = decode_globaltype(decoder)
    init = decode_expr(decoder)
    return Global(type=globaltype, init=init)


def decode_export(decoder: Decoder) -> Export:
    """Decode an export."""
    name = decoder.read_name()
    kind = decoder.read_byte()
    index = decoder.read_u32()
    return Export(name=name, kind=kind, index=index)


def decode_elem(decoder: Decoder) -> ElemSegment:
    """Decode an element segment (restricted form only)."""
    tableidx = decoder.read_u32()
    if tableidx != 0:
        raise DecodeError(f"Unsupported element segment tableidx {tableidx}", offset=decoder.offset - 1, code="unsupported_element_form")

    # Decode offset expression - must be i32.const + end
    offset_start = decoder.offset
    offset_expr = decode_expr(decoder)

    # Validate it's i32.const + end
    if len(offset_expr.instrs) != 2:
        raise DecodeError("Element offset must be i32.const + end", offset=offset_start, code="unsupported_element_form")

    if not isinstance(offset_expr.instrs[0], I32Const) or not isinstance(offset_expr.instrs[1], End):
        raise DecodeError("Element offset must be i32.const + end", offset=offset_start, code="unsupported_element_form")

    # Decode init funcidx vector
    init = decoder.read_vec(lambda: decoder.read_u32(), "elem init")

    return ElemSegment(tableidx=tableidx, offset=offset_expr, init=init)


def decode_code(decoder: Decoder) -> FuncBody:
    """Decode a function body."""
    body_size = decoder.read_u32()

    if body_size > decoder.limits.max_function_body_bytes:
        raise DecodeError(f"Function body size {body_size} exceeds limit", offset=decoder.offset, code="function_body_size_limit")

    body_start = decoder.offset
    body_end = body_start + body_size

    if body_end > len(decoder.data):
        raise DecodeError("Function body extends beyond module", offset=decoder.offset, code="truncated")

    # Decode locals
    locals_vec = decoder.read_vec(lambda: decode_local_decl(decoder), "locals")

    # Check total locals count
    total_locals = sum(ld.count for ld in locals_vec)
    if total_locals > decoder.limits.max_locals_per_function:
        raise DecodeError(f"Total locals {total_locals} exceeds limit", offset=body_start, code="locals_limit")

    # Decode expression
    expr = decode_expr(decoder, end_offset=body_end)

    # Check for exact consumption
    if decoder.offset != body_end:
        raise DecodeError("Function body size mismatch", offset=decoder.offset, code="section_size_mismatch")

    return FuncBody(locals=locals_vec, expr=expr)


def decode_local_decl(decoder: Decoder) -> LocalDecl:
    """Decode a local declaration."""
    count = decoder.read_u32()
    valtype = decode_valtype(decoder)
    return LocalDecl(count=count, valtype=valtype)


def decode_data(decoder: Decoder) -> DataSegment:
    """Decode a data segment (restricted form only)."""
    memidx = decoder.read_u32()
    if memidx != 0:
        raise DecodeError(f"Unsupported data segment memidx {memidx}", offset=decoder.offset - 1, code="unsupported_data_form")

    # Decode offset expression - must be i32.const + end
    offset_start = decoder.offset
    offset_expr = decode_expr(decoder)

    # Validate it's i32.const + end
    if len(offset_expr.instrs) != 2:
        raise DecodeError("Data offset must be i32.const + end", offset=offset_start, code="unsupported_data_form")

    if not isinstance(offset_expr.instrs[0], I32Const) or not isinstance(offset_expr.instrs[1], End):
        raise DecodeError("Data offset must be i32.const + end", offset=offset_start, code="unsupported_data_form")

    # Decode data bytes
    data_len = decoder.read_u32()
    data = decoder.read_bytes(data_len)

    return DataSegment(memidx=memidx, offset=offset_expr, data=data)


# ----------------------------
# Main decoder
# ----------------------------

def decode_module(data: bytes, *, limits: Limits = Limits()) -> Module:
    """
    Decode a WASM binary module (subset) into a Module AST.

    Raises:
        DecodeError: on malformed input or unsupported forms.
    """
    decoder = Decoder(data, limits)

    # Check magic
    magic = decoder.read_bytes(4)
    if magic != b'\x00asm':
        raise DecodeError(f"Invalid magic: {magic!r}", offset=0, code="bad_magic")

    # Check version
    version = decoder.read_bytes(4)
    if version != b'\x01\x00\x00\x00':
        raise DecodeError(f"Invalid version: {version!r}", offset=4, code="bad_version")

    module = Module(raw_size=len(data))

    # Track section order
    last_section_id = -1
    seen_sections = set()

    # Decode sections
    while not decoder.eof():
        section_id = decoder.read_byte()
        payload_len = decoder.read_u32()

        if payload_len > limits.max_section_bytes:
            if section_id == 0 and payload_len <= limits.max_custom_section_bytes:
                # Custom section has higher limit
                pass
            else:
                raise DecodeError(f"Section {section_id} payload {payload_len} exceeds limit", offset=decoder.offset, code="section_size_limit")

        section_start = decoder.offset
        section_end = section_start + payload_len

        if section_end > len(data):
            raise DecodeError(f"Section {section_id} extends beyond module", offset=section_start, code="truncated")

        # Check section ordering (custom sections can appear anywhere)
        if section_id != 0:
            if section_id in seen_sections:
                raise DecodeError(f"Duplicate section {section_id}", offset=section_start - 1, code="section_order")

            if section_id < last_section_id:
                raise DecodeError(f"Section {section_id} out of order", offset=section_start - 1, code="section_order")

            last_section_id = section_id
            seen_sections.add(section_id)

        # Create section decoder
        section_decoder = Decoder(data[section_start:section_end], limits)

        # Decode section payload
        if section_id == 0:  # Custom
            custom_data = section_decoder.read_bytes(payload_len)
            module.customs.append(custom_data)
        elif section_id == 1:  # Type
            module.types = section_decoder.read_vec(lambda: decode_functype(section_decoder), "types")
        elif section_id == 2:  # Import
            module.imports = section_decoder.read_vec(lambda: decode_import(section_decoder), "imports")
        elif section_id == 3:  # Function
            module.funcs = section_decoder.read_vec(lambda: section_decoder.read_u32(), "function type indices")
        elif section_id == 4:  # Table
            module.tables = section_decoder.read_vec(lambda: decode_tabletype(section_decoder), "tables")
        elif section_id == 5:  # Memory
            module.memories = section_decoder.read_vec(lambda: decode_limits(section_decoder), "memories")
        elif section_id == 6:  # Global
            module.globals = section_decoder.read_vec(lambda: decode_global(section_decoder), "globals")
        elif section_id == 7:  # Export
            module.exports = section_decoder.read_vec(lambda: decode_export(section_decoder), "exports")
        elif section_id == 8:  # Start
            module.start = section_decoder.read_u32()
        elif section_id == 9:  # Element
            module.elems = section_decoder.read_vec(lambda: decode_elem(section_decoder), "elements")
        elif section_id == 10:  # Code
            module.code = section_decoder.read_vec(lambda: decode_code(section_decoder), "code")
        elif section_id == 11:  # Data
            module.datas = section_decoder.read_vec(lambda: decode_data(section_decoder), "data")
        elif section_id == 12:  # Data count
            module.datacount = section_decoder.read_u32()
        else:
            raise DecodeError(f"Unknown section id {section_id}", offset=section_start - 1, code="unknown_section_id")

        # Check section was fully consumed
        if not section_decoder.eof():
            raise DecodeError(f"Section {section_id} has {section_decoder.remaining()} leftover bytes", offset=section_start, code="section_size_mismatch")

        decoder.offset = section_end

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
    errors = []

    # Compute index spaces
    imported_funcs = sum(1 for imp in module.imports if isinstance(imp.desc, ImportFunc))
    imported_tables = sum(1 for imp in module.imports if isinstance(imp.desc, ImportTable))
    imported_mems = sum(1 for imp in module.imports if isinstance(imp.desc, ImportMemory))
    imported_globals = sum(1 for imp in module.imports if isinstance(imp.desc, ImportGlobal))

    defined_funcs = len(module.funcs)
    defined_tables = len(module.tables)
    defined_mems = len(module.memories)
    defined_globals = len(module.globals)

    funcs_total = imported_funcs + defined_funcs
    tables_total = imported_tables + defined_tables
    mems_total = imported_mems + defined_mems
    globals_total = imported_globals + defined_globals

    # Validate type indices in imports
    for imp in module.imports:
        if isinstance(imp.desc, ImportFunc):
            if imp.desc.typeidx >= len(module.types):
                errors.append(ValidationError(
                    code="type_index_out_of_range",
                    message=f"Import function type index {imp.desc.typeidx} out of range (have {len(module.types)} types)",
                    context=f"import {imp.module!r}.{imp.name!r}"
                ))

    # Validate type indices in function section
    for i, typeidx in enumerate(module.funcs):
        if typeidx >= len(module.types):
            errors.append(ValidationError(
                code="type_index_out_of_range",
                message=f"Function {i} type index {typeidx} out of range (have {len(module.types)} types)",
                context=f"function {i}"
            ))

    # Validate limits (min <= max)
    for i, table in enumerate(module.tables):
        if table.limits.max is not None and table.limits.min > table.limits.max:
            errors.append(ValidationError(
                code="limits_min_gt_max",
                message=f"Table {i} min {table.limits.min} > max {table.limits.max}",
                context=f"table {i}"
            ))

    for i, mem in enumerate(module.memories):
        if mem.max is not None and mem.min > mem.max:
            errors.append(ValidationError(
                code="limits_min_gt_max",
                message=f"Memory {i} min {mem.min} > max {mem.max}",
                context=f"memory {i}"
            ))

    for imp in module.imports:
        if isinstance(imp.desc, ImportTable):
            limits = imp.desc.tabletype.limits
            if limits.max is not None and limits.min > limits.max:
                errors.append(ValidationError(
                    code="limits_min_gt_max",
                    message=f"Import table min {limits.min} > max {limits.max}",
                    context=f"import {imp.module!r}.{imp.name!r}"
                ))
        elif isinstance(imp.desc, ImportMemory):
            limits = imp.desc.memtype
            if limits.max is not None and limits.min > limits.max:
                errors.append(ValidationError(
                    code="limits_min_gt_max",
                    message=f"Import memory min {limits.min} > max {limits.max}",
                    context=f"import {imp.module!r}.{imp.name!r}"
                ))

    # Validate exports
    export_names = set()
    for exp in module.exports:
        # Check for duplicate names
        if exp.name in export_names:
            errors.append(ValidationError(
                code="duplicate_export_name",
                message=f"Duplicate export name {exp.name!r}",
                context=f"export {exp.name!r}"
            ))
        export_names.add(exp.name)

        # Check index ranges
        if exp.kind == 0:  # func
            if exp.index >= funcs_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export function index {exp.index} out of range (have {funcs_total} functions)",
                    context=f"export {exp.name!r}"
                ))
        elif exp.kind == 1:  # table
            if exp.index >= tables_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export table index {exp.index} out of range (have {tables_total} tables)",
                    context=f"export {exp.name!r}"
                ))
        elif exp.kind == 2:  # mem
            if exp.index >= mems_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export memory index {exp.index} out of range (have {mems_total} memories)",
                    context=f"export {exp.name!r}"
                ))
        elif exp.kind == 3:  # global
            if exp.index >= globals_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export global index {exp.index} out of range (have {globals_total} globals)",
                    context=f"export {exp.name!r}"
                ))

    # Validate start function
    if module.start is not None:
        if module.start >= funcs_total:
            errors.append(ValidationError(
                code="index_out_of_range",
                message=f"Start function index {module.start} out of range (have {funcs_total} functions)",
                context="start"
            ))
        else:
            # Get the function's type
            if module.start < imported_funcs:
                # It's an import
                func_imp = [imp for imp in module.imports if isinstance(imp.desc, ImportFunc)][module.start]
                typeidx = func_imp.desc.typeidx
            else:
                # It's a defined function
                typeidx = module.funcs[module.start - imported_funcs]

            if typeidx < len(module.types):
                func_type = module.types[typeidx]
                if func_type.params or func_type.results:
                    errors.append(ValidationError(
                        code="bad_start_signature",
                        message=f"Start function must have type [] -> [], got {func_type.params} -> {func_type.results}",
                        context="start"
                    ))

    # Validate code section matches function section
    if len(module.code) != len(module.funcs):
        errors.append(ValidationError(
            code="func_code_count_mismatch",
            message=f"Code section has {len(module.code)} entries but function section has {len(module.funcs)} entries"
        ))

    # Validate function bodies
    for i, (typeidx, body) in enumerate(zip(module.funcs, module.code)):
        if typeidx >= len(module.types):
            continue  # Already reported above

        func_type = module.types[typeidx]

        # Calculate total locals
        num_params = len(func_type.params)
        num_locals = sum(ld.count for ld in body.locals)
        total_locals = num_params + num_locals

        # Validate local indices in instructions
        for instr in body.expr.instrs:
            if isinstance(instr, (LocalGet, LocalSet)):
                if instr.localidx >= total_locals:
                    errors.append(ValidationError(
                        code="local_index_out_of_range",
                        message=f"Local index {instr.localidx} out of range (have {total_locals} locals)",
                        context=f"function {imported_funcs + i}"
                    ))
            elif isinstance(instr, Call):
                if instr.funcidx >= funcs_total:
                    errors.append(ValidationError(
                        code="index_out_of_range",
                        message=f"Call function index {instr.funcidx} out of range (have {funcs_total} functions)",
                        context=f"function {imported_funcs + i}"
                    ))

    # Validate element segments
    for i, elem in enumerate(module.elems):
        for funcidx in elem.init:
            if funcidx >= funcs_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Element segment {i} funcidx {funcidx} out of range (have {funcs_total} functions)",
                    context=f"element {i}"
                ))

    # Validate data count
    if module.datacount is not None:
        if module.datacount != len(module.datas):
            errors.append(ValidationError(
                code="data_count_mismatch",
                message=f"Data count section says {module.datacount} but data section has {len(module.datas)} segments"
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
