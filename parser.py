"""
parser.py - Public API surface for WASM binary module parsing + structural validation.
"""

from __future__ import annotations

from dataclasses import dataclass
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
# AST Types
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
    """Table/memory limits."""
    min: int
    max: Optional[int] = None


@dataclass(frozen=True)
class TableType:
    """Table type (funcref only)."""
    limits: TableLimits


@dataclass(frozen=True)
class GlobalType:
    """Global type."""
    valtype: ValType
    mutable: bool


@dataclass(frozen=True)
class ImportFunc:
    """Import function descriptor."""
    module: bytes
    name: bytes
    typeidx: int


@dataclass(frozen=True)
class ImportTable:
    """Import table descriptor."""
    module: bytes
    name: bytes
    table_type: TableType


@dataclass(frozen=True)
class ImportMem:
    """Import memory descriptor."""
    module: bytes
    name: bytes
    limits: TableLimits


@dataclass(frozen=True)
class ImportGlobal:
    """Import global descriptor."""
    module: bytes
    name: bytes
    global_type: GlobalType


ImportDesc = Union[ImportFunc, ImportTable, ImportMem, ImportGlobal]


@dataclass(frozen=True)
class Instr:
    """Base instruction class."""
    pass


@dataclass(frozen=True)
class I32Const(Instr):
    """i32.const instruction."""
    value: int


@dataclass(frozen=True)
class LocalGet(Instr):
    """local.get instruction."""
    localidx: int


@dataclass(frozen=True)
class LocalSet(Instr):
    """local.set instruction."""
    localidx: int


@dataclass(frozen=True)
class I32Add(Instr):
    """i32.add instruction."""
    pass


@dataclass(frozen=True)
class Call(Instr):
    """call instruction."""
    funcidx: int


@dataclass(frozen=True)
class End(Instr):
    """end instruction."""
    pass


@dataclass(frozen=True)
class Expr:
    """Expression (sequence of instructions ending with end)."""
    instrs: List[Instr]


@dataclass(frozen=True)
class LocalDecl:
    """Local variable declaration."""
    count: int
    valtype: ValType


@dataclass(frozen=True)
class FuncBody:
    """Function body (locals + expression)."""
    locals: List[LocalDecl]
    expr: Expr


@dataclass(frozen=True)
class Global:
    """Global definition."""
    global_type: GlobalType
    init_expr: Expr


@dataclass(frozen=True)
class Export:
    """Export definition."""
    name: bytes
    kind: int  # 0=func, 1=table, 2=mem, 3=global
    index: int


@dataclass(frozen=True)
class ElemSegment:
    """Element segment (active mode for table 0)."""
    tableidx: int
    offset_expr: Expr
    funcindices: List[int]


@dataclass(frozen=True)
class DataSegment:
    """Data segment (active mode for memory 0)."""
    memidx: int
    offset_expr: Expr
    data: bytes


@dataclass(frozen=True)
class CustomSection:
    """Custom section."""
    name: bytes
    data: bytes


@dataclass(frozen=True)
class Module:
    """Decoded WASM module AST."""
    raw_size: int
    types: List[FuncType]
    imports: List[ImportDesc]
    function_typeidxs: List[int]
    tables: List[TableType]
    memories: List[TableLimits]
    globals: List[Global]
    exports: List[Export]
    start: Optional[int]
    elements: List[ElemSegment]
    code: List[FuncBody]
    data: List[DataSegment]
    data_count: Optional[int]
    customs: List[CustomSection]


# ----------------------------
# Decoder implementation
# ----------------------------

class Decoder:
    """Binary decoder with position tracking and LEB128 support."""

    def __init__(self, data: bytes, limits: Limits):
        assert len(data) <= limits.max_module_bytes
        self.data = data
        self.pos = 0
        self.limits = limits

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def read_byte(self) -> int:
        if self.pos >= len(self.data):
            raise DecodeError("unexpected end of data", offset=self.pos)
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_bytes(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise DecodeError("unexpected end of data", offset=self.pos)
        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result

    def read_u32(self) -> int:
        """Read unsigned LEB128 u32."""
        result = 0
        shift = 0
        for i in range(5):
            if self.pos >= len(self.data):
                raise DecodeError("truncated LEB128", offset=self.pos)
            b = self.read_byte()
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                if shift >= 32 and (b & 0x7F) != 0:
                    raise DecodeError("LEB128 overflow for u32", offset=self.pos)
                return result
            shift += 7
        raise DecodeError("LEB128 too long for u32", offset=self.pos)

    def read_s32(self) -> int:
        """Read signed LEB128 s32."""
        result = 0
        shift = 0
        for i in range(5):
            if self.pos >= len(self.data):
                raise DecodeError("truncated LEB128", offset=self.pos)
            b = self.read_byte()
            result |= (b & 0x7F) << shift
            shift += 7
            if (b & 0x80) == 0:
                if shift < 32 and (b & 0x40):
                    result |= -(1 << shift)
                # Convert to signed 32-bit
                if result >= 2**31:
                    result -= 2**32
                elif result < -(2**31):
                    result += 2**32
                return result
        raise DecodeError("LEB128 too long for s32", offset=self.pos)

    def read_name(self) -> bytes:
        """Read a name (length-prefixed bytes)."""
        length = self.read_u32()
        return self.read_bytes(length)

    def read_vec(self, read_item, limit: Optional[int] = None):
        """Read a vector of items."""
        count = self.read_u32()
        if limit is not None and count > limit:
            raise DecodeError(f"vector length {count} exceeds limit {limit}", offset=self.pos)
        items = []
        for _ in range(count):
            items.append(read_item())
        return items


def decode_module(data: bytes, *, limits: Limits = Limits()) -> Module:
    """
    Decode a WASM binary module (subset) into a Module AST.

    Raises:
        DecodeError: on malformed input or unsupported forms.
    """
    assert isinstance(data, bytes)
    assert isinstance(limits, Limits)
    assert limits.max_module_bytes > 0

    if len(data) > limits.max_module_bytes:
        raise DecodeError(f"module size {len(data)} exceeds limit {limits.max_module_bytes}")

    dec = Decoder(data, limits)

    # Check magic and version
    magic = dec.read_bytes(4)
    if magic != b"\x00asm":
        raise DecodeError("invalid magic bytes", offset=0)

    version = dec.read_bytes(4)
    if version != b"\x01\x00\x00\x00":
        raise DecodeError("invalid version", offset=4)

    # Initialize module fields
    types: List[FuncType] = []
    imports: List[ImportDesc] = []
    function_typeidxs: List[int] = []
    tables: List[TableType] = []
    memories: List[TableLimits] = []
    globals: List[Global] = []
    exports: List[Export] = []
    start: Optional[int] = None
    elements: List[ElemSegment] = []
    code: List[FuncBody] = []
    data_segments: List[DataSegment] = []
    data_count: Optional[int] = None
    customs: List[CustomSection] = []

    # Track last non-custom section ID for ordering
    last_section_id = -1

    # Read sections
    while dec.remaining() > 0:
        section_id = dec.read_byte()
        payload_len = dec.read_u32()

        if section_id != 0 and payload_len > limits.max_section_bytes:
            raise DecodeError(f"section {section_id} payload size {payload_len} exceeds limit", offset=dec.pos)

        if section_id == 0 and payload_len > limits.max_custom_section_bytes:
            raise DecodeError(f"custom section payload size {payload_len} exceeds limit", offset=dec.pos)

        section_start = dec.pos
        section_end = section_start + payload_len

        if section_end > len(data):
            raise DecodeError(f"section {section_id} payload extends beyond module", offset=dec.pos)

        # Check section ordering (custom sections can appear anywhere)
        if section_id != 0:
            if section_id <= last_section_id:
                raise DecodeError(f"section {section_id} out of order", offset=dec.pos, code="section_order")
            last_section_id = section_id

        # Parse section based on ID
        if section_id == 0:  # Custom
            name = dec.read_name()
            remaining_data = dec.read_bytes(section_end - dec.pos)
            customs.append(CustomSection(name=name, data=remaining_data))

        elif section_id == 1:  # Type
            types = dec.read_vec(lambda: _read_functype(dec), limits.max_vector_length)

        elif section_id == 2:  # Import
            imports = dec.read_vec(lambda: _read_import(dec), limits.max_vector_length)

        elif section_id == 3:  # Function
            function_typeidxs = dec.read_vec(lambda: dec.read_u32(), limits.max_vector_length)

        elif section_id == 4:  # Table
            tables = dec.read_vec(lambda: _read_tabletype(dec), limits.max_vector_length)

        elif section_id == 5:  # Memory
            memories = dec.read_vec(lambda: _read_limits(dec), limits.max_vector_length)

        elif section_id == 6:  # Global
            globals = dec.read_vec(lambda: _read_global(dec), limits.max_vector_length)

        elif section_id == 7:  # Export
            exports = dec.read_vec(lambda: _read_export(dec), limits.max_vector_length)

        elif section_id == 8:  # Start
            start = dec.read_u32()

        elif section_id == 9:  # Element
            elements = dec.read_vec(lambda: _read_elem_segment(dec), limits.max_vector_length)

        elif section_id == 10:  # Code
            code = dec.read_vec(lambda: _read_func_body(dec, limits), limits.max_vector_length)

        elif section_id == 11:  # Data
            data_segments = dec.read_vec(lambda: _read_data_segment(dec), limits.max_vector_length)

        elif section_id == 12:  # DataCount
            data_count = dec.read_u32()

        else:
            raise DecodeError(f"unknown section id {section_id}", offset=dec.pos, code="unknown_section_id")

        # Verify exact payload consumption
        if dec.pos != section_end:
            raise DecodeError(f"section {section_id} size mismatch", offset=dec.pos, code="section_size_mismatch")

    return Module(
        raw_size=len(data),
        types=types,
        imports=imports,
        function_typeidxs=function_typeidxs,
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


def _read_valtype(dec: Decoder) -> ValType:
    """Read a value type."""
    assert dec.pos < len(dec.data)
    b = dec.read_byte()
    if b == 0x7F:
        return ValType.I32
    elif b == 0x7E:
        return ValType.I64
    else:
        raise DecodeError(f"unsupported valtype 0x{b:02x}", offset=dec.pos, code="unsupported_valtype")


def _read_functype(dec: Decoder) -> FuncType:
    """Read a function type."""
    assert dec.pos < len(dec.data)
    tag = dec.read_byte()
    if tag != 0x60:
        raise DecodeError(f"expected functype tag 0x60, got 0x{tag:02x}", offset=dec.pos)
    params = dec.read_vec(lambda: _read_valtype(dec), dec.limits.max_vector_length)
    results = dec.read_vec(lambda: _read_valtype(dec), dec.limits.max_vector_length)
    return FuncType(params=params, results=results)


def _read_limits(dec: Decoder) -> TableLimits:
    """Read table/memory limits."""
    assert dec.pos < len(dec.data)
    flags = dec.read_byte()
    if flags == 0x00:
        min_val = dec.read_u32()
        return TableLimits(min=min_val, max=None)
    elif flags == 0x01:
        min_val = dec.read_u32()
        max_val = dec.read_u32()
        return TableLimits(min=min_val, max=max_val)
    else:
        raise DecodeError(f"bad limits flag 0x{flags:02x}", offset=dec.pos, code="bad_limits_flag")


def _read_tabletype(dec: Decoder) -> TableType:
    """Read a table type."""
    assert dec.pos < len(dec.data)
    elemtype = dec.read_byte()
    if elemtype != 0x70:
        raise DecodeError(f"unsupported table elemtype 0x{elemtype:02x}", offset=dec.pos, code="unsupported_table_elemtype")
    limits = _read_limits(dec)
    return TableType(limits=limits)


def _read_globaltype(dec: Decoder) -> GlobalType:
    """Read a global type."""
    assert dec.pos < len(dec.data)
    valtype = _read_valtype(dec)
    mut = dec.read_byte()
    if mut == 0x00:
        mutable = False
    elif mut == 0x01:
        mutable = True
    else:
        raise DecodeError(f"bad mutability byte 0x{mut:02x}", offset=dec.pos, code="bad_mutability")
    return GlobalType(valtype=valtype, mutable=mutable)


def _read_import(dec: Decoder) -> ImportDesc:
    """Read an import."""
    assert dec.pos < len(dec.data)
    module = dec.read_name()
    name = dec.read_name()
    kind = dec.read_byte()

    if kind == 0:  # func
        typeidx = dec.read_u32()
        return ImportFunc(module=module, name=name, typeidx=typeidx)
    elif kind == 1:  # table
        table_type = _read_tabletype(dec)
        return ImportTable(module=module, name=name, table_type=table_type)
    elif kind == 2:  # mem
        limits = _read_limits(dec)
        return ImportMem(module=module, name=name, limits=limits)
    elif kind == 3:  # global
        global_type = _read_globaltype(dec)
        return ImportGlobal(module=module, name=name, global_type=global_type)
    else:
        raise DecodeError(f"unknown import kind {kind}", offset=dec.pos)


def _read_expr(dec: Decoder) -> Expr:
    """Read an expression (sequence of instructions ending with end)."""
    assert dec.pos <= len(dec.data)
    instrs: List[Instr] = []

    while True:
        if dec.pos >= len(dec.data):
            raise DecodeError("missing end in expression", offset=dec.pos, code="missing_end")

        opcode = dec.read_byte()

        if opcode == 0x0B:  # end
            instrs.append(End())
            break
        elif opcode == 0x41:  # i32.const
            value = dec.read_s32()
            instrs.append(I32Const(value=value))
        elif opcode == 0x20:  # local.get
            localidx = dec.read_u32()
            instrs.append(LocalGet(localidx=localidx))
        elif opcode == 0x21:  # local.set
            localidx = dec.read_u32()
            instrs.append(LocalSet(localidx=localidx))
        elif opcode == 0x6A:  # i32.add
            instrs.append(I32Add())
        elif opcode == 0x10:  # call
            funcidx = dec.read_u32()
            instrs.append(Call(funcidx=funcidx))
        else:
            raise DecodeError(f"unsupported opcode 0x{opcode:02x}", offset=dec.pos, code="unsupported_opcode")

    return Expr(instrs=instrs)


def _read_global(dec: Decoder) -> Global:
    """Read a global definition."""
    assert dec.pos < len(dec.data)
    global_type = _read_globaltype(dec)
    init_expr = _read_expr(dec)
    return Global(global_type=global_type, init_expr=init_expr)


def _read_export(dec: Decoder) -> Export:
    """Read an export."""
    assert dec.pos < len(dec.data)
    name = dec.read_name()
    kind = dec.read_byte()
    index = dec.read_u32()
    return Export(name=name, kind=kind, index=index)


def _read_elem_segment(dec: Decoder) -> ElemSegment:
    """Read an element segment (active mode only)."""
    assert dec.pos < len(dec.data)
    tableidx = dec.read_u32()
    if tableidx != 0:
        raise DecodeError(f"unsupported element tableidx {tableidx}", offset=dec.pos, code="unsupported_element_form")

    # Read offset expression - must be i32.const + end
    expr_start = dec.pos
    offset_expr = _read_expr(dec)

    # Validate it's exactly i32.const + end
    if len(offset_expr.instrs) != 2:
        raise DecodeError("element offset must be i32.const+end", offset=expr_start, code="unsupported_element_form")
    if not isinstance(offset_expr.instrs[0], I32Const):
        raise DecodeError("element offset must be i32.const+end", offset=expr_start, code="unsupported_element_form")
    if not isinstance(offset_expr.instrs[1], End):
        raise DecodeError("element offset must be i32.const+end", offset=expr_start, code="unsupported_element_form")

    funcindices = dec.read_vec(lambda: dec.read_u32(), dec.limits.max_vector_length)
    return ElemSegment(tableidx=tableidx, offset_expr=offset_expr, funcindices=funcindices)


def _read_data_segment(dec: Decoder) -> DataSegment:
    """Read a data segment (active mode only)."""
    assert dec.pos < len(dec.data)
    memidx = dec.read_u32()
    if memidx != 0:
        raise DecodeError(f"unsupported data memidx {memidx}", offset=dec.pos, code="unsupported_data_form")

    # Read offset expression - must be i32.const + end
    expr_start = dec.pos
    offset_expr = _read_expr(dec)

    # Validate it's exactly i32.const + end
    if len(offset_expr.instrs) != 2:
        raise DecodeError("data offset must be i32.const+end", offset=expr_start, code="unsupported_data_form")
    if not isinstance(offset_expr.instrs[0], I32Const):
        raise DecodeError("data offset must be i32.const+end", offset=expr_start, code="unsupported_data_form")
    if not isinstance(offset_expr.instrs[1], End):
        raise DecodeError("data offset must be i32.const+end", offset=expr_start, code="unsupported_data_form")

    data_bytes = dec.read_name()  # Same encoding as name (length + bytes)
    return DataSegment(memidx=memidx, offset_expr=offset_expr, data=data_bytes)


def _read_func_body(dec: Decoder, limits: Limits) -> FuncBody:
    """Read a function body."""
    assert dec.pos < len(dec.data)
    body_size = dec.read_u32()

    if body_size > limits.max_function_body_bytes:
        raise DecodeError(f"function body size {body_size} exceeds limit", offset=dec.pos)

    body_start = dec.pos
    body_end = body_start + body_size

    if body_end > len(dec.data):
        raise DecodeError("function body extends beyond module", offset=dec.pos)

    # Read locals
    locals = dec.read_vec(lambda: _read_local_decl(dec), limits.max_vector_length)

    # Count total locals
    total_locals = sum(ld.count for ld in locals)
    if total_locals > limits.max_locals_per_function:
        raise DecodeError(f"total locals {total_locals} exceeds limit", offset=dec.pos)

    # Read expression
    expr = _read_expr(dec)

    # Verify exact body size consumption
    if dec.pos != body_end:
        raise DecodeError("function body size mismatch", offset=dec.pos, code="section_size_mismatch")

    return FuncBody(locals=locals, expr=expr)


def _read_local_decl(dec: Decoder) -> LocalDecl:
    """Read a local variable declaration."""
    assert dec.pos < len(dec.data)
    count = dec.read_u32()
    valtype = _read_valtype(dec)
    return LocalDecl(count=count, valtype=valtype)


# ----------------------------
# Validator implementation
# ----------------------------

def validate_module(module: Module) -> List[ValidationError]:
    """
    Perform structural validation on a decoded module.

    Returns:
        List[ValidationError]: empty if valid.
    """
    assert isinstance(module, Module)
    errors: List[ValidationError] = []

    # Compute index spaces
    imported_funcs = sum(1 for imp in module.imports if isinstance(imp, ImportFunc))
    imported_tables = sum(1 for imp in module.imports if isinstance(imp, ImportTable))
    imported_mems = sum(1 for imp in module.imports if isinstance(imp, ImportMem))
    imported_globals = sum(1 for imp in module.imports if isinstance(imp, ImportGlobal))

    funcs_total = imported_funcs + len(module.function_typeidxs)
    tables_total = imported_tables + len(module.tables)
    mems_total = imported_mems + len(module.memories)
    globals_total = imported_globals + len(module.globals)

    # Validate limits (min <= max)
    for i, mem in enumerate(module.memories):
        if mem.max is not None and mem.min > mem.max:
            errors.append(ValidationError(
                code="limits_min_gt_max",
                message=f"memory {i}: min {mem.min} > max {mem.max}"
            ))

    for i, table in enumerate(module.tables):
        if table.limits.max is not None and table.limits.min > table.limits.max:
            errors.append(ValidationError(
                code="limits_min_gt_max",
                message=f"table {i}: min {table.limits.min} > max {table.limits.max}"
            ))

    # Validate import type indices
    for i, imp in enumerate(module.imports):
        if isinstance(imp, ImportFunc):
            if imp.typeidx >= len(module.types):
                errors.append(ValidationError(
                    code="type_index_out_of_range",
                    message=f"import func {i}: typeidx {imp.typeidx} >= {len(module.types)}"
                ))

    # Validate function type indices
    for i, typeidx in enumerate(module.function_typeidxs):
        if typeidx >= len(module.types):
            errors.append(ValidationError(
                code="type_index_out_of_range",
                message=f"function {i}: typeidx {typeidx} >= {len(module.types)}"
            ))

    # Validate code section size matches function section
    if len(module.code) != len(module.function_typeidxs):
        errors.append(ValidationError(
            code="func_code_count_mismatch",
            message=f"code count {len(module.code)} != function count {len(module.function_typeidxs)}"
        ))

    # Validate exports
    export_names = set()
    for exp in module.exports:
        # Check for duplicate names
        if exp.name in export_names:
            errors.append(ValidationError(
                code="duplicate_export_name",
                message=f"duplicate export name: {exp.name!r}"
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
            # Get start function type
            if module.start < imported_funcs:
                # It's an imported function
                func_imports = [imp for imp in module.imports if isinstance(imp, ImportFunc)]
                typeidx = func_imports[module.start].typeidx
            else:
                # It's a defined function
                func_idx = module.start - imported_funcs
                if func_idx < len(module.function_typeidxs):
                    typeidx = module.function_typeidxs[func_idx]
                else:
                    typeidx = -1

            if 0 <= typeidx < len(module.types):
                func_type = module.types[typeidx]
                if len(func_type.params) != 0 or len(func_type.results) != 0:
                    errors.append(ValidationError(
                        code="bad_start_signature",
                        message=f"start function must have type []->[], got {len(func_type.params)}->{len(func_type.results)}"
                    ))

    # Validate element segments
    for i, elem in enumerate(module.elements):
        for j, funcidx in enumerate(elem.funcindices):
            if funcidx >= funcs_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"element {i} funcidx[{j}] = {funcidx} >= {funcs_total}"
                ))

    # Validate code bodies
    for i, body in enumerate(module.code):
        func_idx = imported_funcs + i
        if i < len(module.function_typeidxs):
            typeidx = module.function_typeidxs[i]
            if typeidx < len(module.types):
                func_type = module.types[typeidx]
                num_params = len(func_type.params)
                num_locals = sum(ld.count for ld in body.locals)
                total_locals = num_params + num_locals

                # Validate local indices in instructions
                for instr in body.expr.instrs:
                    if isinstance(instr, LocalGet) or isinstance(instr, LocalSet):
                        if instr.localidx >= total_locals:
                            errors.append(ValidationError(
                                code="local_index_out_of_range",
                                message=f"func {func_idx}: local index {instr.localidx} >= {total_locals}"
                            ))
                    elif isinstance(instr, Call):
                        if instr.funcidx >= funcs_total:
                            errors.append(ValidationError(
                                code="index_out_of_range",
                                message=f"func {func_idx}: call funcidx {instr.funcidx} >= {funcs_total}"
                            ))

    # Validate data count
    if module.data_count is not None:
        if module.data_count != len(module.data):
            errors.append(ValidationError(
                code="data_count_mismatch",
                message=f"data count {module.data_count} != actual data segments {len(module.data)}"
            ))

    return errors


# ----------------------------
# Public API functions
# ----------------------------

def decode_and_validate(data: bytes, *, limits: Limits = Limits()) -> Module:
    """
    Convenience API: decode, then validate; raise on any validation errors.
    """
    assert isinstance(data, bytes)
    assert isinstance(limits, Limits)
    module = decode_module(data, limits=limits)
    errors = validate_module(module)
    if errors:
        # Raise a single exception with a readable summary
        msg = "Validation failed:\n" + "\n".join(f"- {e.code}: {e.message}" for e in errors[:20])
        raise ValueError(msg)
    return module

