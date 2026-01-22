"""
parser.py - Public API surface for WASM binary module parsing + structural validation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List, Union


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

@dataclass(frozen=True)
class TableType:
    elemtype: int  # 0x70 for funcref
    limits: TableLimits


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
    params: List[int]
    results: List[int]


# Instructions
@dataclass(frozen=True)
class Instr:
    """Base class for instructions"""
    pass


@dataclass(frozen=True)
class I32Const(Instr):
    value: int


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
class Expression:
    instructions: List[Instr]


@dataclass(frozen=True)
class Import:
    module: bytes
    name: bytes
    kind: int  # 0=func, 1=table, 2=mem, 3=global
    desc: Union[int, TableType, MemoryLimits, GlobalType]  # typeidx for func, else type


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
class LocalDecl:
    count: int
    valtype: int


@dataclass(frozen=True)
class FunctionBody:
    locals: List[LocalDecl]
    code: Expression


@dataclass(frozen=True)
class ElementSegment:
    tableidx: int
    offset: Expression
    init: List[int]  # funcidx list


@dataclass(frozen=True)
class DataSegment:
    memidx: int
    offset: Expression
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
    tables: List[TableType] = field(default_factory=list)
    memories: List[MemoryLimits] = field(default_factory=list)
    globals: List[Global] = field(default_factory=list)
    exports: List[Export] = field(default_factory=list)
    start: Optional[int] = None
    elements: List[ElementSegment] = field(default_factory=list)
    code: List[FunctionBody] = field(default_factory=list)
    data: List[DataSegment] = field(default_factory=list)
    data_count: Optional[int] = None
    customs: List[CustomSection] = field(default_factory=list)


# ----------------------------
# Decoder implementation
# ----------------------------

class Decoder:
    """Binary decoder with offset tracking and limit enforcement."""

    def __init__(self, data: bytes, limits: Limits):
        self.data = data
        self.limits = limits
        self.offset = 0

    def eof(self) -> bool:
        return self.offset >= len(self.data)

    def read_byte(self) -> int:
        if self.offset >= len(self.data):
            raise DecodeError("unexpected EOF", offset=self.offset)
        b = self.data[self.offset]
        self.offset += 1
        return b

    def read_bytes(self, n: int) -> bytes:
        if self.offset + n > len(self.data):
            raise DecodeError("unexpected EOF", offset=self.offset)
        result = self.data[self.offset:self.offset + n]
        self.offset += n
        return result

    def read_u32(self) -> int:
        """Decode unsigned LEB128 u32."""
        result = 0
        shift = 0
        while True:
            if shift > 28:  # Max 5 bytes for u32
                raise DecodeError("LEB128 too long for u32", offset=self.offset)
            b = self.read_byte()
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                if shift == 28 and (b & 0xF0) != 0:
                    raise DecodeError("LEB128 overflow for u32", offset=self.offset)
                return result
            shift += 7

    def read_s32(self) -> int:
        """Decode signed LEB128 s32."""
        result = 0
        shift = 0
        while True:
            if shift > 28:
                raise DecodeError("LEB128 too long for s32", offset=self.offset)
            b = self.read_byte()
            result |= (b & 0x7F) << shift
            shift += 7
            if (b & 0x80) == 0:
                # Sign extend
                if shift < 32 and (b & 0x40):
                    result |= -(1 << shift)
                # Check overflow
                if result < -(2**31) or result >= 2**31:
                    raise DecodeError("LEB128 overflow for s32", offset=self.offset)
                return result

    def read_name(self) -> bytes:
        """Read length-prefixed byte string."""
        length = self.read_u32()
        return self.read_bytes(length)

    def read_vec(self, read_elem, limit: Optional[int] = None):
        """Read vector with optional element limit."""
        n = self.read_u32()
        if limit is not None and n > limit:
            raise DecodeError(f"vector length {n} exceeds limit {limit}", offset=self.offset)
        return [read_elem() for _ in range(n)]


def decode_module(data: bytes, *, limits: Limits = Limits()) -> Module:
    """
    Decode a WASM binary module (subset) into a Module AST.

    Raises:
        DecodeError: on malformed input or unsupported forms.
    """
    if len(data) > limits.max_module_bytes:
        raise DecodeError(f"module size {len(data)} exceeds limit {limits.max_module_bytes}")

    module_bytes = data  # Save original bytes before using 'data' as variable name
    decoder = Decoder(module_bytes, limits)

    # Check magic and version
    magic = decoder.read_bytes(4)
    if magic != b'\x00asm':
        raise DecodeError(f"invalid magic: {magic.hex()}", code="bad_magic")

    version = decoder.read_bytes(4)
    if version != b'\x01\x00\x00\x00':
        raise DecodeError(f"invalid version: {version.hex()}", code="bad_version")

    # Parse sections
    types: List[FuncType] = []
    imports: List[Import] = []
    function_types: List[int] = []
    tables: List[TableType] = []
    memories: List[MemoryLimits] = []
    globals: List[Global] = []
    exports: List[Export] = []
    start: Optional[int] = None
    elements: List[ElementSegment] = []
    code: List[FunctionBody] = []
    data: List[DataSegment] = []
    data_count: Optional[int] = None
    customs: List[CustomSection] = []

    last_section_id = -1

    while not decoder.eof():
        section_id = decoder.read_byte()
        payload_len = decoder.read_u32()

        # Check section size limit
        if section_id == 0:
            if payload_len > limits.max_custom_section_bytes:
                raise DecodeError(f"custom section size {payload_len} exceeds limit", offset=decoder.offset)
        else:
            if payload_len > limits.max_section_bytes:
                raise DecodeError(f"section size {payload_len} exceeds limit", offset=decoder.offset)

        section_start = decoder.offset
        section_end = section_start + payload_len

        if section_end > len(module_bytes):
            raise DecodeError("section extends past module end", offset=decoder.offset)

        # Create sub-decoder for section payload
        section_data = module_bytes[section_start:section_end]
        sec_dec = Decoder(section_data, limits)

        # Section ordering check for non-custom sections
        if section_id != 0:
            if section_id <= last_section_id:
                raise DecodeError(f"section {section_id} out of order", code="section_order")
            last_section_id = section_id

        # Parse section
        if section_id == 0:  # Custom
            name = sec_dec.read_name()
            remaining = section_data[sec_dec.offset:]
            customs.append(CustomSection(name=name, data=remaining))
            # Custom sections don't need to be fully consumed - they have arbitrary data
            sec_dec.offset = len(section_data)  # Mark as consumed

        elif section_id == 1:  # Type
            types = sec_dec.read_vec(lambda: decode_functype(sec_dec), limits.max_vector_length)

        elif section_id == 2:  # Import
            imports = sec_dec.read_vec(lambda: decode_import(sec_dec), limits.max_vector_length)

        elif section_id == 3:  # Function
            function_types = sec_dec.read_vec(sec_dec.read_u32, limits.max_vector_length)

        elif section_id == 4:  # Table
            tables = sec_dec.read_vec(lambda: decode_tabletype(sec_dec), limits.max_vector_length)

        elif section_id == 5:  # Memory
            memories = sec_dec.read_vec(lambda: decode_limits(sec_dec), limits.max_vector_length)

        elif section_id == 6:  # Global
            globals = sec_dec.read_vec(lambda: decode_global(sec_dec), limits.max_vector_length)

        elif section_id == 7:  # Export
            exports = sec_dec.read_vec(lambda: decode_export(sec_dec), limits.max_vector_length)

        elif section_id == 8:  # Start
            start = sec_dec.read_u32()

        elif section_id == 9:  # Element
            elements = sec_dec.read_vec(lambda: decode_element(sec_dec), limits.max_vector_length)

        elif section_id == 10:  # Code
            code = sec_dec.read_vec(lambda: decode_code(sec_dec, limits), limits.max_vector_length)

        elif section_id == 11:  # Data
            data = sec_dec.read_vec(lambda: decode_data(sec_dec), limits.max_vector_length)

        elif section_id == 12:  # Data Count
            data_count = sec_dec.read_u32()

        else:
            raise DecodeError(f"unknown section id: {section_id}", code="unknown_section_id")

        # Check section payload was fully consumed
        if not sec_dec.eof():
            raise DecodeError(f"section {section_id} has trailing bytes", code="section_size_mismatch")

        decoder.offset = section_end

    return Module(
        raw_size=len(module_bytes),
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
        data=data,  # List of DataSegments
        data_count=data_count,
        customs=customs
    )


def decode_functype(dec: Decoder) -> FuncType:
    """Decode a function type."""
    tag = dec.read_byte()
    if tag != 0x60:
        raise DecodeError(f"invalid functype tag: {tag:02x}", offset=dec.offset)

    params = dec.read_vec(lambda: decode_valtype(dec), dec.limits.max_vector_length)
    results = dec.read_vec(lambda: decode_valtype(dec), dec.limits.max_vector_length)
    return FuncType(params=params, results=results)


def decode_valtype(dec: Decoder) -> int:
    """Decode a value type (restricted to i32/i64)."""
    vt = dec.read_byte()
    if vt not in (0x7F, 0x7E):  # i32, i64
        raise DecodeError(f"unsupported valtype: {vt:02x}", code="unsupported_valtype", offset=dec.offset)
    return vt


def decode_import(dec: Decoder) -> Import:
    """Decode an import."""
    module = dec.read_name()
    name = dec.read_name()
    kind = dec.read_byte()

    if kind == 0:  # func
        typeidx = dec.read_u32()
        desc = typeidx
    elif kind == 1:  # table
        desc = decode_tabletype(dec)
    elif kind == 2:  # mem
        desc = decode_limits(dec)
    elif kind == 3:  # global
        valtype = decode_valtype(dec)
        mut = dec.read_byte()
        if mut not in (0x00, 0x01):
            raise DecodeError(f"bad mutability: {mut:02x}", code="bad_mutability", offset=dec.offset)
        desc = GlobalType(valtype=valtype, mutable=(mut == 0x01))
    else:
        raise DecodeError(f"unknown import kind: {kind}", offset=dec.offset)

    return Import(module=module, name=name, kind=kind, desc=desc)


def decode_tabletype(dec: Decoder) -> TableType:
    """Decode a table type."""
    elemtype = dec.read_byte()
    if elemtype != 0x70:  # funcref
        raise DecodeError(f"unsupported table elemtype: {elemtype:02x}", code="unsupported_table_elemtype", offset=dec.offset)
    limits = decode_limits(dec)
    return TableType(elemtype=elemtype, limits=limits)


def decode_limits(dec: Decoder) -> Union[MemoryLimits, TableLimits]:
    """Decode limits (for memory or table)."""
    flags = dec.read_byte()
    if flags == 0x00:
        min_val = dec.read_u32()
        return MemoryLimits(min=min_val, max=None)
    elif flags == 0x01:
        min_val = dec.read_u32()
        max_val = dec.read_u32()
        return MemoryLimits(min=min_val, max=max_val)
    else:
        raise DecodeError(f"bad limits flag: {flags:02x}", code="bad_limits_flag", offset=dec.offset)


def decode_global(dec: Decoder) -> Global:
    """Decode a global."""
    valtype = decode_valtype(dec)
    mut = dec.read_byte()
    if mut not in (0x00, 0x01):
        raise DecodeError(f"bad mutability: {mut:02x}", code="bad_mutability", offset=dec.offset)
    gtype = GlobalType(valtype=valtype, mutable=(mut == 0x01))
    init = decode_expr(dec)
    return Global(type=gtype, init=init)


def decode_export(dec: Decoder) -> Export:
    """Decode an export."""
    name = dec.read_name()
    kind = dec.read_byte()
    index = dec.read_u32()
    return Export(name=name, kind=kind, index=index)


def decode_element(dec: Decoder) -> ElementSegment:
    """Decode an element segment (restricted form only)."""
    tableidx = dec.read_u32()
    if tableidx != 0:
        raise DecodeError(f"unsupported element form: tableidx={tableidx}", code="unsupported_element_form", offset=dec.offset)

    # Offset must be i32.const + end
    offset = decode_expr(dec)
    if len(offset.instructions) != 2:
        raise DecodeError("unsupported element form: offset must be i32.const + end", code="unsupported_element_form", offset=dec.offset)
    if not isinstance(offset.instructions[0], I32Const) or not isinstance(offset.instructions[1], End):
        raise DecodeError("unsupported element form: offset must be i32.const + end", code="unsupported_element_form", offset=dec.offset)

    init = dec.read_vec(dec.read_u32, dec.limits.max_vector_length)
    return ElementSegment(tableidx=tableidx, offset=offset, init=init)


def decode_data(dec: Decoder) -> DataSegment:
    """Decode a data segment (restricted form only)."""
    memidx = dec.read_u32()
    if memidx != 0:
        raise DecodeError(f"unsupported data form: memidx={memidx}", code="unsupported_data_form", offset=dec.offset)

    # Offset must be i32.const + end
    offset = decode_expr(dec)
    if len(offset.instructions) != 2:
        raise DecodeError("unsupported data form: offset must be i32.const + end", code="unsupported_data_form", offset=dec.offset)
    if not isinstance(offset.instructions[0], I32Const) or not isinstance(offset.instructions[1], End):
        raise DecodeError("unsupported data form: offset must be i32.const + end", code="unsupported_data_form", offset=dec.offset)

    data_bytes = dec.read_name()  # Uses same encoding as name
    return DataSegment(memidx=memidx, offset=offset, data=data_bytes)


def decode_code(dec: Decoder, limits: Limits) -> FunctionBody:
    """Decode a function body."""
    body_size = dec.read_u32()

    if body_size > limits.max_function_body_bytes:
        raise DecodeError(f"function body size {body_size} exceeds limit", offset=dec.offset)

    body_data = dec.read_bytes(body_size)
    body_dec = Decoder(body_data, limits)

    # Decode locals
    locals_vec = body_dec.read_vec(lambda: decode_local_decl(body_dec), limits.max_vector_length)

    # Check total locals count
    total_locals = sum(ld.count for ld in locals_vec)
    if total_locals > limits.max_locals_per_function:
        raise DecodeError(f"total locals {total_locals} exceeds limit", offset=body_dec.offset)

    # Decode expression
    expr = decode_expr(body_dec)

    if not body_dec.eof():
        raise DecodeError("trailing bytes in function body", offset=body_dec.offset)

    return FunctionBody(locals=locals_vec, code=expr)


def decode_local_decl(dec: Decoder) -> LocalDecl:
    """Decode a local declaration."""
    count = dec.read_u32()
    valtype = decode_valtype(dec)
    return LocalDecl(count=count, valtype=valtype)


def decode_expr(dec: Decoder) -> Expression:
    """Decode an expression (sequence of instructions ending with 'end')."""
    instructions: List[Instr] = []

    while True:
        opcode = dec.read_byte()

        if opcode == 0x0B:  # end
            instructions.append(End())
            break
        elif opcode == 0x41:  # i32.const
            value = dec.read_s32()
            instructions.append(I32Const(value=value))
        elif opcode == 0x20:  # local.get
            localidx = dec.read_u32()
            instructions.append(LocalGet(localidx=localidx))
        elif opcode == 0x21:  # local.set
            localidx = dec.read_u32()
            instructions.append(LocalSet(localidx=localidx))
        elif opcode == 0x6A:  # i32.add
            instructions.append(I32Add())
        elif opcode == 0x10:  # call
            funcidx = dec.read_u32()
            instructions.append(Call(funcidx=funcidx))
        else:
            raise DecodeError(f"unsupported opcode: {opcode:02x}", code="unsupported_opcode", offset=dec.offset)

    return Expression(instructions=instructions)


# ----------------------------
# Validator implementation
# ----------------------------

def validate_module(module: Module) -> List[ValidationError]:
    """
    Perform structural validation on a decoded module.

    Returns:
        List[ValidationError]: empty if valid.
    """
    errors: List[ValidationError] = []

    # Compute index spaces
    imported_funcs = sum(1 for imp in module.imports if imp.kind == 0)
    imported_tables = sum(1 for imp in module.imports if imp.kind == 1)
    imported_mems = sum(1 for imp in module.imports if imp.kind == 2)
    imported_globals = sum(1 for imp in module.imports if imp.kind == 3)

    defined_funcs = len(module.function_types)
    defined_tables = len(module.tables)
    defined_mems = len(module.memories)
    defined_globals = len(module.globals)

    funcs_total = imported_funcs + defined_funcs
    tables_total = imported_tables + defined_tables
    mems_total = imported_mems + defined_mems
    globals_total = imported_globals + defined_globals

    # Validate limits
    for table in module.tables:
        if table.limits.max is not None and table.limits.min > table.limits.max:
            errors.append(ValidationError(
                code="limits_min_gt_max",
                message=f"table limits min ({table.limits.min}) > max ({table.limits.max})"
            ))

    for mem in module.memories:
        if mem.max is not None and mem.min > mem.max:
            errors.append(ValidationError(
                code="limits_min_gt_max",
                message=f"memory limits min ({mem.min}) > max ({mem.max})"
            ))

    for imp in module.imports:
        if imp.kind == 1:  # table
            ttype = imp.desc
            if isinstance(ttype, TableType) and ttype.limits.max is not None and ttype.limits.min > ttype.limits.max:
                errors.append(ValidationError(
                    code="limits_min_gt_max",
                    message=f"imported table limits min ({ttype.limits.min}) > max ({ttype.limits.max})"
                ))
        elif imp.kind == 2:  # mem
            mlimits = imp.desc
            if isinstance(mlimits, MemoryLimits) and mlimits.max is not None and mlimits.min > mlimits.max:
                errors.append(ValidationError(
                    code="limits_min_gt_max",
                    message=f"imported memory limits min ({mlimits.min}) > max ({mlimits.max})"
                ))

    # Validate import type indices
    for imp in module.imports:
        if imp.kind == 0:  # func
            typeidx = imp.desc
            if isinstance(typeidx, int) and typeidx >= len(module.types):
                errors.append(ValidationError(
                    code="type_index_out_of_range",
                    message=f"import func typeidx {typeidx} >= {len(module.types)}"
                ))

    # Validate function type indices
    for i, typeidx in enumerate(module.function_types):
        if typeidx >= len(module.types):
            errors.append(ValidationError(
                code="type_index_out_of_range",
                message=f"function {i} typeidx {typeidx} >= {len(module.types)}"
            ))

    # Validate exports
    export_names = set()
    for exp in module.exports:
        if exp.name in export_names:
            errors.append(ValidationError(
                code="duplicate_export_name",
                message=f"duplicate export name: {exp.name}"
            ))
        export_names.add(exp.name)

        # Check index ranges
        if exp.kind == 0:  # func
            if exp.index >= funcs_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"export func index {exp.index} >= {funcs_total}"
                ))
        elif exp.kind == 1:  # table
            if exp.index >= tables_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"export table index {exp.index} >= {tables_total}"
                ))
        elif exp.kind == 2:  # mem
            if exp.index >= mems_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"export mem index {exp.index} >= {mems_total}"
                ))
        elif exp.kind == 3:  # global
            if exp.index >= globals_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"export global index {exp.index} >= {globals_total}"
                ))

    # Validate start function
    if module.start is not None:
        if module.start >= funcs_total:
            errors.append(ValidationError(
                code="index_out_of_range",
                message=f"start funcidx {module.start} >= {funcs_total}"
            ))
        else:
            # Check start function signature
            start_typeidx = get_func_typeidx(module, module.start)
            if start_typeidx is not None and start_typeidx < len(module.types):
                ftype = module.types[start_typeidx]
                if len(ftype.params) != 0 or len(ftype.results) != 0:
                    errors.append(ValidationError(
                        code="bad_start_signature",
                        message=f"start function must have type [] -> [], got {ftype.params} -> {ftype.results}"
                    ))

    # Validate element segments
    for elem in module.elements:
        for funcidx in elem.init:
            if funcidx >= funcs_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"element funcidx {funcidx} >= {funcs_total}"
                ))

    # Validate code section count matches function section
    if len(module.code) != len(module.function_types):
        errors.append(ValidationError(
            code="func_code_count_mismatch",
            message=f"code count {len(module.code)} != function count {len(module.function_types)}"
        ))

    # Validate function bodies
    for i, (typeidx, body) in enumerate(zip(module.function_types, module.code)):
        if typeidx < len(module.types):
            ftype = module.types[typeidx]
            num_params = len(ftype.params)
            num_locals = sum(ld.count for ld in body.locals)
            total_locals = num_params + num_locals

            # Validate local indices
            for instr in body.code.instructions:
                if isinstance(instr, (LocalGet, LocalSet)):
                    if instr.localidx >= total_locals:
                        errors.append(ValidationError(
                            code="local_index_out_of_range",
                            message=f"function {i} local index {instr.localidx} >= {total_locals}"
                        ))
                elif isinstance(instr, Call):
                    if instr.funcidx >= funcs_total:
                        errors.append(ValidationError(
                            code="index_out_of_range",
                            message=f"function {i} call funcidx {instr.funcidx} >= {funcs_total}"
                        ))

    # Validate data count
    if module.data_count is not None:
        if module.data_count != len(module.data):
            errors.append(ValidationError(
                code="data_count_mismatch",
                message=f"data_count {module.data_count} != actual data segments {len(module.data)}"
            ))

    return errors


def get_func_typeidx(module: Module, funcidx: int) -> Optional[int]:
    """Get the type index for a function (imported or defined)."""
    imported_funcs = [imp for imp in module.imports if imp.kind == 0]

    if funcidx < len(imported_funcs):
        desc = imported_funcs[funcidx].desc
        return desc if isinstance(desc, int) else None
    else:
        local_idx = funcidx - len(imported_funcs)
        if local_idx < len(module.function_types):
            return module.function_types[local_idx]
    return None


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
