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
class FuncType:
    """Function type signature."""
    params: List[str]  # 'i32' or 'i64'
    results: List[str]  # 'i32' or 'i64'


@dataclass(frozen=True)
class TableType:
    """Table type with element type and limits."""
    elemtype: str  # 'funcref'
    min: int
    max: Optional[int]


@dataclass(frozen=True)
class MemoryType:
    """Memory type with limits."""
    min: int
    max: Optional[int]


@dataclass(frozen=True)
class GlobalType:
    """Global type with value type and mutability."""
    valtype: str  # 'i32' or 'i64'
    mutable: bool


@dataclass(frozen=True)
class Import:
    """Import declaration."""
    module: bytes
    name: bytes
    kind: str  # 'func', 'table', 'mem', 'global'
    desc: object  # typeidx (int) for func, TableType/MemoryType/GlobalType for others


@dataclass(frozen=True)
class Export:
    """Export declaration."""
    name: bytes
    kind: str  # 'func', 'table', 'mem', 'global'
    index: int


@dataclass(frozen=True)
class Instr:
    """Single instruction."""
    opcode: int
    immediate: Optional[int] = None


@dataclass(frozen=True)
class Expr:
    """Expression (sequence of instructions ending with 'end')."""
    instrs: List[Instr]


@dataclass(frozen=True)
class Global:
    """Global definition."""
    type: GlobalType
    init: Expr


@dataclass(frozen=True)
class LocalDecl:
    """Local variable declaration."""
    count: int
    valtype: str


@dataclass(frozen=True)
class FuncBody:
    """Function body with locals and expression."""
    locals: List[LocalDecl]
    expr: Expr


@dataclass(frozen=True)
class ElemSegment:
    """Element segment (restricted form: active mode for table 0)."""
    tableidx: int
    offset: Expr
    init: List[int]  # funcidx list


@dataclass(frozen=True)
class DataSegment:
    """Data segment (restricted form: active mode for memory 0)."""
    memidx: int
    offset: Expr
    data: bytes


@dataclass(frozen=True)
class CustomSection:
    """Custom section."""
    name: bytes
    data: bytes


@dataclass(frozen=True)
class Module:
    """Complete decoded WASM module AST."""
    raw_size: int
    types: List[FuncType]
    imports: List[Import]
    funcs: List[int]  # typeidx for each defined function
    tables: List[TableType]
    mems: List[MemoryType]
    globals: List[Global]
    exports: List[Export]
    start: Optional[int]  # funcidx or None
    elems: List[ElemSegment]
    code: List[FuncBody]
    datas: List[DataSegment]
    data_count: Optional[int]
    customs: List[CustomSection]


# ----------------------------
# Public API functions
# ----------------------------

class _Decoder:
    """Internal decoder state."""
    def __init__(self, data: bytes, limits: Limits):
        self.data = data
        self.pos = 0
        self.limits = limits

        if len(data) > limits.max_module_bytes:
            raise DecodeError("Module exceeds max_module_bytes", code="size_limit")

    def read_byte(self) -> int:
        if self.pos >= len(self.data):
            raise DecodeError("Unexpected end of data", offset=self.pos, code="truncated")
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_bytes(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise DecodeError("Unexpected end of data", offset=self.pos, code="truncated")
        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result

    def read_u32(self) -> int:
        """Read unsigned LEB128 u32."""
        result = 0
        shift = 0
        for _ in range(5):  # u32 max 5 bytes
            if self.pos >= len(self.data):
                raise DecodeError("Truncated LEB128", offset=self.pos, code="truncated")
            b = self.read_byte()
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                if shift >= 32 and (b >> (32 - shift)) != 0:
                    raise DecodeError("LEB128 overflows u32", code="leb128_overflow")
                if result > 0xFFFFFFFF:
                    raise DecodeError("LEB128 overflows u32", code="leb128_overflow")
                return result
            shift += 7
        raise DecodeError("LEB128 too long for u32", code="leb128_overflow")

    def read_s32(self) -> int:
        """Read signed LEB128 s32."""
        result = 0
        shift = 0
        for _ in range(5):
            if self.pos >= len(self.data):
                raise DecodeError("Truncated LEB128", offset=self.pos, code="truncated")
            b = self.read_byte()
            result |= (b & 0x7F) << shift
            shift += 7
            if (b & 0x80) == 0:
                # Sign extend
                if shift < 32 and (b & 0x40):
                    result |= -(1 << shift)
                # Check range
                if result < -(1 << 31) or result >= (1 << 31):
                    raise DecodeError("LEB128 overflows s32", code="leb128_overflow")
                return result
        raise DecodeError("LEB128 too long for s32", code="leb128_overflow")

    def read_name(self) -> bytes:
        """Read a name (length-prefixed bytes)."""
        length = self.read_u32()
        if length > self.limits.max_vector_length:
            raise DecodeError("Name length exceeds limit", code="size_limit")
        return self.read_bytes(length)

    def read_vec(self, reader_fn, limit_check=True):
        """Read a vector with length prefix."""
        n = self.read_u32()
        if limit_check and n > self.limits.max_vector_length:
            raise DecodeError("Vector length exceeds limit", code="size_limit")
        return [reader_fn() for _ in range(n)]


def decode_module(data: bytes, *, limits: Limits = Limits()) -> Module:
    """
    Decode a WASM binary module (subset) into a Module AST.

    Raises:
        DecodeError: on malformed input or unsupported forms.
    """
    dec = _Decoder(data, limits)

    # Check magic and version
    magic = dec.read_bytes(4)
    if magic != b'\x00asm':
        raise DecodeError("Invalid magic bytes", code="bad_magic")

    version = dec.read_bytes(4)
    if version != b'\x01\x00\x00\x00':
        raise DecodeError("Unsupported version", code="bad_version")

    # Track sections
    types: List[FuncType] = []
    imports: List[Import] = []
    funcs: List[int] = []
    tables: List[TableType] = []
    mems: List[MemoryType] = []
    globals: List[Global] = []
    exports: List[Export] = []
    start: Optional[int] = None
    elems: List[ElemSegment] = []
    code: List[FuncBody] = []
    datas: List[DataSegment] = []
    data_count: Optional[int] = None
    customs: List[CustomSection] = []

    last_section_id = -1

    while dec.pos < len(data):
        section_id = dec.read_byte()
        payload_len = dec.read_u32()

        if section_id != 0 and payload_len > limits.max_section_bytes:
            raise DecodeError("Section payload exceeds limit", code="size_limit")
        if section_id == 0 and payload_len > limits.max_custom_section_bytes:
            raise DecodeError("Custom section exceeds limit", code="size_limit")

        section_start = dec.pos
        section_end = section_start + payload_len

        if section_end > len(data):
            raise DecodeError("Section payload exceeds module size", code="truncated")

        # Check ordering
        if section_id != 0:
            if section_id <= last_section_id:
                raise DecodeError("Section out of order", code="section_order")
            last_section_id = section_id

        # Decode section
        if section_id == 0:  # Custom
            name = dec.read_name()
            custom_data = dec.read_bytes(section_end - dec.pos)
            customs.append(CustomSection(name=name, data=custom_data))
        elif section_id == 1:  # Type
            types = dec.read_vec(lambda: _decode_functype(dec))
        elif section_id == 2:  # Import
            imports = dec.read_vec(lambda: _decode_import(dec))
        elif section_id == 3:  # Function
            funcs = dec.read_vec(lambda: dec.read_u32())
        elif section_id == 4:  # Table
            tables = dec.read_vec(lambda: _decode_tabletype(dec))
        elif section_id == 5:  # Memory
            mems = dec.read_vec(lambda: _decode_memtype(dec))
        elif section_id == 6:  # Global
            globals = dec.read_vec(lambda: _decode_global(dec))
        elif section_id == 7:  # Export
            exports = dec.read_vec(lambda: _decode_export(dec))
        elif section_id == 8:  # Start
            start = dec.read_u32()
        elif section_id == 9:  # Element
            elems = dec.read_vec(lambda: _decode_elem(dec))
        elif section_id == 10:  # Code
            code = dec.read_vec(lambda: _decode_funcbody(dec, limits))
        elif section_id == 11:  # Data
            datas = dec.read_vec(lambda: _decode_data(dec))
        elif section_id == 12:  # Data count
            data_count = dec.read_u32()
        else:
            raise DecodeError(f"Unknown section id {section_id}", code="unknown_section_id")

        # Check section was fully consumed
        if dec.pos != section_end:
            raise DecodeError("Section size mismatch", code="section_size_mismatch")

    return Module(
        raw_size=len(data),
        types=types,
        imports=imports,
        funcs=funcs,
        tables=tables,
        mems=mems,
        globals=globals,
        exports=exports,
        start=start,
        elems=elems,
        code=code,
        datas=datas,
        data_count=data_count,
        customs=customs
    )


def _decode_valtype(dec: _Decoder) -> str:
    """Decode a value type."""
    b = dec.read_byte()
    if b == 0x7F:
        return 'i32'
    elif b == 0x7E:
        return 'i64'
    else:
        raise DecodeError(f"Unsupported valtype 0x{b:02x}", code="unsupported_valtype")


def _decode_functype(dec: _Decoder) -> FuncType:
    """Decode a function type."""
    b = dec.read_byte()
    if b != 0x60:
        raise DecodeError(f"Expected functype tag 0x60, got 0x{b:02x}", code="bad_functype")
    params = dec.read_vec(lambda: _decode_valtype(dec))
    results = dec.read_vec(lambda: _decode_valtype(dec))
    return FuncType(params=params, results=results)


def _decode_limits(dec: _Decoder) -> tuple:
    """Decode limits. Returns (min, max)."""
    flags = dec.read_byte()
    if flags == 0x00:
        min_val = dec.read_u32()
        return (min_val, None)
    elif flags == 0x01:
        min_val = dec.read_u32()
        max_val = dec.read_u32()
        return (min_val, max_val)
    else:
        raise DecodeError(f"Bad limits flag 0x{flags:02x}", code="bad_limits_flag")


def _decode_tabletype(dec: _Decoder) -> TableType:
    """Decode a table type."""
    elemtype = dec.read_byte()
    if elemtype != 0x70:
        raise DecodeError(f"Unsupported table elemtype 0x{elemtype:02x}", code="unsupported_table_elemtype")
    min_val, max_val = _decode_limits(dec)
    return TableType(elemtype='funcref', min=min_val, max=max_val)


def _decode_memtype(dec: _Decoder) -> MemoryType:
    """Decode a memory type."""
    min_val, max_val = _decode_limits(dec)
    return MemoryType(min=min_val, max=max_val)


def _decode_globaltype(dec: _Decoder) -> GlobalType:
    """Decode a global type."""
    valtype = _decode_valtype(dec)
    mut = dec.read_byte()
    if mut == 0x00:
        mutable = False
    elif mut == 0x01:
        mutable = True
    else:
        raise DecodeError(f"Bad mutability 0x{mut:02x}", code="bad_mutability")
    return GlobalType(valtype=valtype, mutable=mutable)


def _decode_import(dec: _Decoder) -> Import:
    """Decode an import."""
    module = dec.read_name()
    name = dec.read_name()
    kind_byte = dec.read_byte()

    if kind_byte == 0x00:  # func
        typeidx = dec.read_u32()
        return Import(module=module, name=name, kind='func', desc=typeidx)
    elif kind_byte == 0x01:  # table
        tabletype = _decode_tabletype(dec)
        return Import(module=module, name=name, kind='table', desc=tabletype)
    elif kind_byte == 0x02:  # mem
        memtype = _decode_memtype(dec)
        return Import(module=module, name=name, kind='mem', desc=memtype)
    elif kind_byte == 0x03:  # global
        globaltype = _decode_globaltype(dec)
        return Import(module=module, name=name, kind='global', desc=globaltype)
    else:
        raise DecodeError(f"Unknown import kind 0x{kind_byte:02x}", code="bad_import_kind")


def _decode_export(dec: _Decoder) -> Export:
    """Decode an export."""
    name = dec.read_name()
    kind_byte = dec.read_byte()
    index = dec.read_u32()

    kind_map = {0x00: 'func', 0x01: 'table', 0x02: 'mem', 0x03: 'global'}
    if kind_byte not in kind_map:
        raise DecodeError(f"Unknown export kind 0x{kind_byte:02x}", code="bad_export_kind")

    return Export(name=name, kind=kind_map[kind_byte], index=index)


def _decode_expr(dec: _Decoder) -> Expr:
    """Decode an expression (sequence of instructions ending with 'end')."""
    instrs = []
    while True:
        opcode = dec.read_byte()

        if opcode == 0x0B:  # end
            instrs.append(Instr(opcode=opcode))
            break
        elif opcode == 0x41:  # i32.const
            immediate = dec.read_s32()
            instrs.append(Instr(opcode=opcode, immediate=immediate))
        elif opcode == 0x20:  # local.get
            immediate = dec.read_u32()
            instrs.append(Instr(opcode=opcode, immediate=immediate))
        elif opcode == 0x21:  # local.set
            immediate = dec.read_u32()
            instrs.append(Instr(opcode=opcode, immediate=immediate))
        elif opcode == 0x6A:  # i32.add
            instrs.append(Instr(opcode=opcode))
        elif opcode == 0x10:  # call
            immediate = dec.read_u32()
            instrs.append(Instr(opcode=opcode, immediate=immediate))
        else:
            raise DecodeError(f"Unsupported opcode 0x{opcode:02x}", code="unsupported_opcode")

    return Expr(instrs=instrs)


def _decode_global(dec: _Decoder) -> Global:
    """Decode a global."""
    globaltype = _decode_globaltype(dec)
    init = _decode_expr(dec)
    return Global(type=globaltype, init=init)


def _decode_elem(dec: _Decoder) -> ElemSegment:
    """Decode an element segment (restricted form)."""
    tableidx = dec.read_u32()
    if tableidx != 0:
        raise DecodeError("Element segment must reference table 0", code="unsupported_element_form")

    # Offset must be exactly i32.const + end
    offset_start = dec.pos
    offset = _decode_expr(dec)

    if len(offset.instrs) != 2:
        raise DecodeError("Element offset must be i32.const + end", code="unsupported_element_form")
    if offset.instrs[0].opcode != 0x41 or offset.instrs[1].opcode != 0x0B:
        raise DecodeError("Element offset must be i32.const + end", code="unsupported_element_form")

    init = dec.read_vec(lambda: dec.read_u32())
    return ElemSegment(tableidx=tableidx, offset=offset, init=init)


def _decode_data(dec: _Decoder) -> DataSegment:
    """Decode a data segment (restricted form)."""
    memidx = dec.read_u32()
    if memidx != 0:
        raise DecodeError("Data segment must reference memory 0", code="unsupported_data_form")

    # Offset must be exactly i32.const + end
    offset = _decode_expr(dec)

    if len(offset.instrs) != 2:
        raise DecodeError("Data offset must be i32.const + end", code="unsupported_data_form")
    if offset.instrs[0].opcode != 0x41 or offset.instrs[1].opcode != 0x0B:
        raise DecodeError("Data offset must be i32.const + end", code="unsupported_data_form")

    data = dec.read_name()  # bytes are encoded as name (length-prefixed)
    return DataSegment(memidx=memidx, offset=offset, data=data)


def _decode_funcbody(dec: _Decoder, limits: Limits) -> FuncBody:
    """Decode a function body."""
    body_size = dec.read_u32()
    if body_size > limits.max_function_body_bytes:
        raise DecodeError("Function body exceeds limit", code="size_limit")

    body_start = dec.pos
    body_end = body_start + body_size

    if body_end > len(dec.data):
        raise DecodeError("Function body exceeds module size", code="truncated")

    # Decode locals
    locals = dec.read_vec(lambda: _decode_local_decl(dec))

    # Check total locals count
    total_locals = sum(ld.count for ld in locals)
    if total_locals > limits.max_locals_per_function:
        raise DecodeError("Function locals exceed limit", code="size_limit")

    # Decode expression
    expr = _decode_expr(dec)

    # Check we consumed exactly body_size bytes
    if dec.pos != body_end:
        raise DecodeError("Function body size mismatch", code="section_size_mismatch")

    return FuncBody(locals=locals, expr=expr)


def _decode_local_decl(dec: _Decoder) -> LocalDecl:
    """Decode a local declaration."""
    count = dec.read_u32()
    valtype = _decode_valtype(dec)
    return LocalDecl(count=count, valtype=valtype)


def validate_module(module: Module) -> List[ValidationError]:
    """
    Perform structural validation on a decoded module.

    Returns:
        List[ValidationError]: empty if valid.
    """
    errors = []

    # Compute index spaces
    imported_funcs = sum(1 for imp in module.imports if imp.kind == 'func')
    imported_tables = sum(1 for imp in module.imports if imp.kind == 'table')
    imported_mems = sum(1 for imp in module.imports if imp.kind == 'mem')
    imported_globals = sum(1 for imp in module.imports if imp.kind == 'global')

    funcs_total = imported_funcs + len(module.funcs)
    tables_total = imported_tables + len(module.tables)
    mems_total = imported_mems + len(module.mems)
    globals_total = imported_globals + len(module.globals)

    # Validate type indices in imports
    for imp in module.imports:
        if imp.kind == 'func':
            typeidx = imp.desc
            if typeidx >= len(module.types):
                errors.append(ValidationError(
                    code='type_index_out_of_range',
                    message=f'Import func typeidx {typeidx} >= {len(module.types)}'
                ))

    # Validate type indices in function section
    for typeidx in module.funcs:
        if typeidx >= len(module.types):
            errors.append(ValidationError(
                code='type_index_out_of_range',
                message=f'Function typeidx {typeidx} >= {len(module.types)}'
            ))

    # Validate limits
    for table in module.tables:
        if table.max is not None and table.min > table.max:
            errors.append(ValidationError(
                code='limits_min_gt_max',
                message=f'Table min {table.min} > max {table.max}'
            ))

    for mem in module.mems:
        if mem.max is not None and mem.min > mem.max:
            errors.append(ValidationError(
                code='limits_min_gt_max',
                message=f'Memory min {mem.min} > max {mem.max}'
            ))

    for imp in module.imports:
        if imp.kind == 'table':
            table = imp.desc
            if table.max is not None and table.min > table.max:
                errors.append(ValidationError(
                    code='limits_min_gt_max',
                    message=f'Import table min {table.min} > max {table.max}'
                ))
        elif imp.kind == 'mem':
            mem = imp.desc
            if mem.max is not None and mem.min > mem.max:
                errors.append(ValidationError(
                    code='limits_min_gt_max',
                    message=f'Import memory min {mem.min} > max {mem.max}'
                ))

    # Validate exports
    export_names = {}
    for exp in module.exports:
        if exp.name in export_names:
            errors.append(ValidationError(
                code='duplicate_export_name',
                message=f'Duplicate export name: {exp.name!r}'
            ))
        export_names[exp.name] = True

        # Check index ranges
        if exp.kind == 'func' and exp.index >= funcs_total:
            errors.append(ValidationError(
                code='index_out_of_range',
                message=f'Export func index {exp.index} >= {funcs_total}'
            ))
        elif exp.kind == 'table' and exp.index >= tables_total:
            errors.append(ValidationError(
                code='index_out_of_range',
                message=f'Export table index {exp.index} >= {tables_total}'
            ))
        elif exp.kind == 'mem' and exp.index >= mems_total:
            errors.append(ValidationError(
                code='index_out_of_range',
                message=f'Export mem index {exp.index} >= {mems_total}'
            ))
        elif exp.kind == 'global' and exp.index >= globals_total:
            errors.append(ValidationError(
                code='index_out_of_range',
                message=f'Export global index {exp.index} >= {globals_total}'
            ))

    # Validate start function
    if module.start is not None:
        if module.start >= funcs_total:
            errors.append(ValidationError(
                code='index_out_of_range',
                message=f'Start funcidx {module.start} >= {funcs_total}'
            ))
        else:
            # Check signature
            if module.start < imported_funcs:
                # Imported function
                imp = [imp for imp in module.imports if imp.kind == 'func'][module.start]
                typeidx = imp.desc
            else:
                # Defined function
                typeidx = module.funcs[module.start - imported_funcs]

            if typeidx < len(module.types):
                functype = module.types[typeidx]
                if functype.params or functype.results:
                    errors.append(ValidationError(
                        code='bad_start_signature',
                        message=f'Start function must have type [] -> [], got {functype.params} -> {functype.results}'
                    ))

    # Validate element segments
    for elem in module.elems:
        for funcidx in elem.init:
            if funcidx >= funcs_total:
                errors.append(ValidationError(
                    code='index_out_of_range',
                    message=f'Element init funcidx {funcidx} >= {funcs_total}'
                ))

    # Validate code section count
    if len(module.code) != len(module.funcs):
        errors.append(ValidationError(
            code='func_code_count_mismatch',
            message=f'Code count {len(module.code)} != function count {len(module.funcs)}'
        ))

    # Validate data count
    if module.data_count is not None:
        if module.data_count != len(module.datas):
            errors.append(ValidationError(
                code='data_count_mismatch',
                message=f'Data count {module.data_count} != actual data segments {len(module.datas)}'
            ))

    # Validate function bodies
    for i, (typeidx, body) in enumerate(zip(module.funcs, module.code)):
        if typeidx < len(module.types):
            functype = module.types[typeidx]
            num_params = len(functype.params)
            num_locals = sum(ld.count for ld in body.locals)
            total_locals = num_params + num_locals

            # Validate local indices in instructions
            for instr in body.expr.instrs:
                if instr.opcode in (0x20, 0x21):  # local.get, local.set
                    localidx = instr.immediate
                    if localidx >= total_locals:
                        errors.append(ValidationError(
                            code='local_index_out_of_range',
                            message=f'Function {i} local index {localidx} >= {total_locals}',
                            context=f'func[{i}]'
                        ))
                elif instr.opcode == 0x10:  # call
                    funcidx = instr.immediate
                    if funcidx >= funcs_total:
                        errors.append(ValidationError(
                            code='index_out_of_range',
                            message=f'Function {i} call funcidx {funcidx} >= {funcs_total}',
                            context=f'func[{i}]'
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

