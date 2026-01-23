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
class ValueType:
    """Value type: i32 or i64"""
    code: int  # 0x7F for i32, 0x7E for i64

@dataclass(frozen=True)
class FuncType:
    """Function type with params and results"""
    params: List[ValueType]
    results: List[ValueType]

@dataclass(frozen=True)
class TableLimits:
    """Table or memory limits"""
    min: int
    max: Optional[int] = None

@dataclass(frozen=True)
class TableType:
    """Table type"""
    elemtype: int  # 0x70 for funcref
    limits: TableLimits

@dataclass(frozen=True)
class GlobalType:
    """Global type"""
    valtype: ValueType
    mutable: bool

@dataclass(frozen=True)
class ImportFunc:
    """Function import"""
    module: bytes
    name: bytes
    typeidx: int

@dataclass(frozen=True)
class ImportTable:
    """Table import"""
    module: bytes
    name: bytes
    table_type: TableType

@dataclass(frozen=True)
class ImportMem:
    """Memory import"""
    module: bytes
    name: bytes
    limits: TableLimits

@dataclass(frozen=True)
class ImportGlobal:
    """Global import"""
    module: bytes
    name: bytes
    global_type: GlobalType

@dataclass(frozen=True)
class Export:
    """Export"""
    name: bytes
    kind: int  # 0=func, 1=table, 2=mem, 3=global
    index: int

@dataclass(frozen=True)
class Instruction:
    """Single instruction"""
    opcode: int
    immediate: Optional[int] = None

@dataclass(frozen=True)
class Expression:
    """Expression (list of instructions ending with end)"""
    instructions: List[Instruction]

@dataclass(frozen=True)
class LocalDecl:
    """Local declaration in function body"""
    count: int
    valtype: ValueType

@dataclass(frozen=True)
class FuncBody:
    """Function body"""
    locals: List[LocalDecl]
    expr: Expression

@dataclass(frozen=True)
class Global:
    """Global definition"""
    global_type: GlobalType
    init_expr: Expression

@dataclass(frozen=True)
class ElementSegment:
    """Element segment (subset: tableidx=0, i32.const offset)"""
    tableidx: int
    offset: int
    init: List[int]

@dataclass(frozen=True)
class DataSegment:
    """Data segment (subset: memidx=0, i32.const offset)"""
    memidx: int
    offset: int
    data: bytes

@dataclass(frozen=True)
class CustomSection:
    """Custom section"""
    name: bytes
    data: bytes

@dataclass(frozen=True)
class Module:
    """
    Decoded WASM module AST.
    """
    raw_size: int
    types: List[FuncType]
    import_funcs: List[ImportFunc]
    import_tables: List[ImportTable]
    import_mems: List[ImportMem]
    import_globals: List[ImportGlobal]
    func_types: List[int]  # typeidx for each defined function
    tables: List[TableType]
    memories: List[TableLimits]
    globals: List[Global]
    exports: List[Export]
    start: Optional[int]
    elements: List[ElementSegment]
    func_bodies: List[FuncBody]
    data_segments: List[DataSegment]
    data_count: Optional[int]
    custom_sections: List[CustomSection]


# ----------------------------
# Public API functions
# ----------------------------

class _Decoder:
    """Internal decoder state"""
    def __init__(self, data: bytes, limits: Limits):
        self.data = data
        self.pos = 0
        self.limits = limits

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def read_byte(self) -> int:
        if self.pos >= len(self.data):
            raise DecodeError("unexpected end of input", offset=self.pos)
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_bytes(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise DecodeError("unexpected end of input", offset=self.pos)
        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result

    def read_u32(self) -> int:
        """Read unsigned LEB128 u32"""
        result = 0
        shift = 0
        for _ in range(5):  # max 5 bytes for u32
            if self.pos >= len(self.data):
                raise DecodeError("truncated LEB128", offset=self.pos)
            b = self.data[self.pos]
            self.pos += 1
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                if shift >= 32:
                    raise DecodeError("LEB128 too large for u32", offset=self.pos)
                if shift > 0 and (b == 0):
                    # Check for overlong encoding
                    pass  # We'll allow it for simplicity
                return result
            shift += 7
        raise DecodeError("LEB128 too large for u32", offset=self.pos)

    def read_s32(self) -> int:
        """Read signed LEB128 s32"""
        result = 0
        shift = 0
        for _ in range(5):
            if self.pos >= len(self.data):
                raise DecodeError("truncated LEB128", offset=self.pos)
            b = self.data[self.pos]
            self.pos += 1
            result |= (b & 0x7F) << shift
            shift += 7
            if (b & 0x80) == 0:
                if shift < 32 and (b & 0x40):
                    result |= -(1 << shift)
                # Convert to signed 32-bit
                result = (result & 0xFFFFFFFF)
                if result >= 0x80000000:
                    result -= 0x100000000
                return result
        raise DecodeError("LEB128 too large for s32", offset=self.pos)

    def read_name(self) -> bytes:
        length = self.read_u32()
        return self.read_bytes(length)

    def read_valtype(self) -> ValueType:
        code = self.read_byte()
        if code == 0x7F:  # i32
            return ValueType(code)
        elif code == 0x7E:  # i64
            return ValueType(code)
        else:
            raise DecodeError(f"unsupported valtype: 0x{code:02x}", offset=self.pos-1, code="unsupported_valtype")


def decode_module(data: bytes, *, limits: Limits = Limits()) -> Module:
    """
    Decode a WASM binary module (subset) into a Module AST.

    Raises:
        DecodeError: on malformed input or unsupported forms.
    """
    if len(data) > limits.max_module_bytes:
        raise DecodeError(f"module exceeds max_module_bytes ({len(data)} > {limits.max_module_bytes})")

    dec = _Decoder(data, limits)

    # Read magic and version
    if dec.remaining() < 8:
        raise DecodeError("module too short for preamble")
    magic = dec.read_bytes(4)
    if magic != b'\x00asm':
        raise DecodeError("invalid magic")
    version = dec.read_bytes(4)
    if version != b'\x01\x00\x00\x00':
        raise DecodeError("unsupported version")

    # Parse sections
    types: List[FuncType] = []
    import_funcs: List[ImportFunc] = []
    import_tables: List[ImportTable] = []
    import_mems: List[ImportMem] = []
    import_globals: List[ImportGlobal] = []
    func_types: List[int] = []
    tables: List[TableType] = []
    memories: List[TableLimits] = []
    globals: List[Global] = []
    exports: List[Export] = []
    start: Optional[int] = None
    elements: List[ElementSegment] = []
    func_bodies: List[FuncBody] = []
    data_segments: List[DataSegment] = []
    data_count: Optional[int] = None
    custom_sections: List[CustomSection] = []

    last_section_id = -1

    while dec.remaining() > 0:
        section_id = dec.read_byte()
        payload_len = dec.read_u32()

        if payload_len > limits.max_section_bytes:
            if section_id == 0 and payload_len > limits.max_custom_section_bytes:
                raise DecodeError(f"custom section exceeds max_custom_section_bytes", code="section_too_large")
            elif section_id != 0:
                raise DecodeError(f"section exceeds max_section_bytes", code="section_too_large")

        if dec.remaining() < payload_len:
            raise DecodeError("section payload exceeds module size")

        section_start = dec.pos
        section_end = section_start + payload_len

        # Check section ordering (custom sections can appear anywhere)
        if section_id != 0:
            if section_id <= last_section_id:
                raise DecodeError(f"section out of order: {section_id} after {last_section_id}", code="section_order")
            last_section_id = section_id

        # Parse section based on ID
        if section_id == 0:  # Custom
            name = dec.read_name()
            data_bytes = dec.read_bytes(section_end - dec.pos)
            custom_sections.append(CustomSection(name, data_bytes))
        elif section_id == 1:  # Type
            types = _decode_type_section(dec, limits)
        elif section_id == 2:  # Import
            import_funcs, import_tables, import_mems, import_globals = _decode_import_section(dec, limits)
        elif section_id == 3:  # Function
            func_types = _decode_function_section(dec, limits)
        elif section_id == 4:  # Table
            tables = _decode_table_section(dec, limits)
        elif section_id == 5:  # Memory
            memories = _decode_memory_section(dec, limits)
        elif section_id == 6:  # Global
            globals = _decode_global_section(dec, limits)
        elif section_id == 7:  # Export
            exports = _decode_export_section(dec, limits)
        elif section_id == 8:  # Start
            start = dec.read_u32()
        elif section_id == 9:  # Element
            elements = _decode_element_section(dec, limits)
        elif section_id == 10:  # Code
            func_bodies = _decode_code_section(dec, limits)
        elif section_id == 11:  # Data
            data_segments = _decode_data_section(dec, limits)
        elif section_id == 12:  # DataCount
            data_count = dec.read_u32()
        else:
            raise DecodeError(f"unknown section id: {section_id}", code="unknown_section_id")

        # Check that we consumed exactly the section payload
        if dec.pos != section_end:
            if dec.pos < section_end:
                raise DecodeError(f"section {section_id} has trailing bytes", code="section_size_mismatch")
            else:
                raise DecodeError(f"section {section_id} read past end", code="section_size_mismatch")

    return Module(
        raw_size=len(data),
        types=types,
        import_funcs=import_funcs,
        import_tables=import_tables,
        import_mems=import_mems,
        import_globals=import_globals,
        func_types=func_types,
        tables=tables,
        memories=memories,
        globals=globals,
        exports=exports,
        start=start,
        elements=elements,
        func_bodies=func_bodies,
        data_segments=data_segments,
        data_count=data_count,
        custom_sections=custom_sections
    )


def _decode_type_section(dec: _Decoder, limits: Limits) -> List[FuncType]:
    """Decode type section"""
    count = dec.read_u32()
    if count > limits.max_vector_length:
        raise DecodeError(f"type vector too long: {count}")
    types = []
    for _ in range(count):
        tag = dec.read_byte()
        if tag != 0x60:
            raise DecodeError(f"invalid functype tag: 0x{tag:02x}")
        param_count = dec.read_u32()
        if param_count > limits.max_vector_length:
            raise DecodeError(f"param vector too long: {param_count}")
        params = [dec.read_valtype() for _ in range(param_count)]
        result_count = dec.read_u32()
        if result_count > limits.max_vector_length:
            raise DecodeError(f"result vector too long: {result_count}")
        results = [dec.read_valtype() for _ in range(result_count)]
        types.append(FuncType(params, results))
    return types


def _decode_import_section(dec: _Decoder, limits: Limits):
    """Decode import section"""
    count = dec.read_u32()
    if count > limits.max_vector_length:
        raise DecodeError(f"import vector too long: {count}")

    import_funcs = []
    import_tables = []
    import_mems = []
    import_globals = []

    for _ in range(count):
        module = dec.read_name()
        name = dec.read_name()
        kind = dec.read_byte()

        if kind == 0:  # func
            typeidx = dec.read_u32()
            import_funcs.append(ImportFunc(module, name, typeidx))
        elif kind == 1:  # table
            elemtype = dec.read_byte()
            if elemtype != 0x70:
                raise DecodeError(f"unsupported table elemtype: 0x{elemtype:02x}", code="unsupported_table_elemtype")
            limits_val = _decode_limits(dec)
            import_tables.append(ImportTable(module, name, TableType(elemtype, limits_val)))
        elif kind == 2:  # mem
            limits_val = _decode_limits(dec)
            import_mems.append(ImportMem(module, name, limits_val))
        elif kind == 3:  # global
            valtype = dec.read_valtype()
            mut = dec.read_byte()
            if mut not in (0x00, 0x01):
                raise DecodeError(f"invalid mutability: 0x{mut:02x}", code="bad_mutability")
            import_globals.append(ImportGlobal(module, name, GlobalType(valtype, mut == 0x01)))
        else:
            raise DecodeError(f"unknown import kind: {kind}")

    return import_funcs, import_tables, import_mems, import_globals


def _decode_limits(dec: _Decoder) -> TableLimits:
    """Decode limits"""
    flags = dec.read_byte()
    if flags == 0x00:
        min_val = dec.read_u32()
        return TableLimits(min_val, None)
    elif flags == 0x01:
        min_val = dec.read_u32()
        max_val = dec.read_u32()
        return TableLimits(min_val, max_val)
    else:
        raise DecodeError(f"invalid limits flags: 0x{flags:02x}", code="bad_limits_flag")


def _decode_function_section(dec: _Decoder, limits: Limits) -> List[int]:
    """Decode function section"""
    count = dec.read_u32()
    if count > limits.max_vector_length:
        raise DecodeError(f"function vector too long: {count}")
    return [dec.read_u32() for _ in range(count)]


def _decode_table_section(dec: _Decoder, limits: Limits) -> List[TableType]:
    """Decode table section"""
    count = dec.read_u32()
    if count > limits.max_vector_length:
        raise DecodeError(f"table vector too long: {count}")
    tables = []
    for _ in range(count):
        elemtype = dec.read_byte()
        if elemtype != 0x70:
            raise DecodeError(f"unsupported table elemtype: 0x{elemtype:02x}", code="unsupported_table_elemtype")
        limits_val = _decode_limits(dec)
        tables.append(TableType(elemtype, limits_val))
    return tables


def _decode_memory_section(dec: _Decoder, limits: Limits) -> List[TableLimits]:
    """Decode memory section"""
    count = dec.read_u32()
    if count > limits.max_vector_length:
        raise DecodeError(f"memory vector too long: {count}")
    return [_decode_limits(dec) for _ in range(count)]


def _decode_global_section(dec: _Decoder, limits: Limits) -> List[Global]:
    """Decode global section"""
    count = dec.read_u32()
    if count > limits.max_vector_length:
        raise DecodeError(f"global vector too long: {count}")
    globals = []
    for _ in range(count):
        valtype = dec.read_valtype()
        mut = dec.read_byte()
        if mut not in (0x00, 0x01):
            raise DecodeError(f"invalid mutability: 0x{mut:02x}", code="bad_mutability")
        init_expr = _decode_expression(dec)
        globals.append(Global(GlobalType(valtype, mut == 0x01), init_expr))
    return globals


def _decode_export_section(dec: _Decoder, limits: Limits) -> List[Export]:
    """Decode export section"""
    count = dec.read_u32()
    if count > limits.max_vector_length:
        raise DecodeError(f"export vector too long: {count}")
    exports = []
    for _ in range(count):
        name = dec.read_name()
        kind = dec.read_byte()
        index = dec.read_u32()
        exports.append(Export(name, kind, index))
    return exports


def _decode_element_section(dec: _Decoder, limits: Limits) -> List[ElementSegment]:
    """Decode element section (subset only)"""
    count = dec.read_u32()
    if count > limits.max_vector_length:
        raise DecodeError(f"element vector too long: {count}")
    elements = []
    for _ in range(count):
        tableidx = dec.read_u32()
        if tableidx != 0:
            raise DecodeError(f"unsupported element form: tableidx={tableidx}", code="unsupported_element_form")

        # offset_expr must be exactly: i32.const <val> ; end
        offset_expr = _decode_expression(dec)
        if len(offset_expr.instructions) != 2:
            raise DecodeError("element offset must be i32.const;end", code="unsupported_element_form")
        if offset_expr.instructions[0].opcode != 0x41:
            raise DecodeError("element offset must be i32.const;end", code="unsupported_element_form")
        if offset_expr.instructions[1].opcode != 0x0B:
            raise DecodeError("element offset must end with end", code="unsupported_element_form")

        offset = offset_expr.instructions[0].immediate

        # init vector
        init_count = dec.read_u32()
        if init_count > limits.max_vector_length:
            raise DecodeError(f"element init vector too long: {init_count}")
        init = [dec.read_u32() for _ in range(init_count)]

        elements.append(ElementSegment(tableidx, offset, init))
    return elements


def _decode_code_section(dec: _Decoder, limits: Limits) -> List[FuncBody]:
    """Decode code section"""
    count = dec.read_u32()
    if count > limits.max_vector_length:
        raise DecodeError(f"code vector too long: {count}")
    bodies = []
    for _ in range(count):
        body_size = dec.read_u32()
        if body_size > limits.max_function_body_bytes:
            raise DecodeError(f"function body too large: {body_size}")

        body_start = dec.pos
        body_end = body_start + body_size

        # Decode locals
        local_decl_count = dec.read_u32()
        if local_decl_count > limits.max_vector_length:
            raise DecodeError(f"local decl vector too long: {local_decl_count}")

        locals = []
        total_locals = 0
        for _ in range(local_decl_count):
            count_val = dec.read_u32()
            total_locals += count_val
            if total_locals > limits.max_locals_per_function:
                raise DecodeError(f"too many locals: {total_locals}")
            valtype = dec.read_valtype()
            locals.append(LocalDecl(count_val, valtype))

        # Decode expression
        expr_bytes_remaining = body_end - dec.pos
        expr = _decode_expression(dec)

        if dec.pos != body_end:
            raise DecodeError("function body size mismatch", code="section_size_mismatch")

        bodies.append(FuncBody(locals, expr))
    return bodies


def _decode_data_section(dec: _Decoder, limits: Limits) -> List[DataSegment]:
    """Decode data section (subset only)"""
    count = dec.read_u32()
    if count > limits.max_vector_length:
        raise DecodeError(f"data vector too long: {count}")
    segments = []
    for _ in range(count):
        memidx = dec.read_u32()
        if memidx != 0:
            raise DecodeError(f"unsupported data form: memidx={memidx}", code="unsupported_data_form")

        # offset_expr must be exactly: i32.const <val> ; end
        offset_expr = _decode_expression(dec)
        if len(offset_expr.instructions) != 2:
            raise DecodeError("data offset must be i32.const;end", code="unsupported_data_form")
        if offset_expr.instructions[0].opcode != 0x41:
            raise DecodeError("data offset must be i32.const;end", code="unsupported_data_form")
        if offset_expr.instructions[1].opcode != 0x0B:
            raise DecodeError("data offset must end with end", code="unsupported_data_form")

        offset = offset_expr.instructions[0].immediate

        # data bytes
        byte_len = dec.read_u32()
        data_bytes = dec.read_bytes(byte_len)

        segments.append(DataSegment(memidx, offset, data_bytes))
    return segments


def _decode_expression(dec: _Decoder) -> Expression:
    """Decode expression (sequence of instructions ending with end)"""
    instructions = []
    while True:
        opcode = dec.read_byte()

        if opcode == 0x0B:  # end
            instructions.append(Instruction(opcode, None))
            break
        elif opcode == 0x41:  # i32.const
            immediate = dec.read_s32()
            instructions.append(Instruction(opcode, immediate))
        elif opcode == 0x20:  # local.get
            immediate = dec.read_u32()
            instructions.append(Instruction(opcode, immediate))
        elif opcode == 0x21:  # local.set
            immediate = dec.read_u32()
            instructions.append(Instruction(opcode, immediate))
        elif opcode == 0x6A:  # i32.add
            instructions.append(Instruction(opcode, None))
        elif opcode == 0x10:  # call
            immediate = dec.read_u32()
            instructions.append(Instruction(opcode, immediate))
        else:
            raise DecodeError(f"unsupported opcode: 0x{opcode:02x}", code="unsupported_opcode")

    return Expression(instructions)


def validate_module(module: Module) -> List[ValidationError]:
    """
    Perform structural validation on a decoded module.

    Returns:
        List[ValidationError]: empty if valid.
    """
    errors: List[ValidationError] = []

    # Compute index spaces
    funcs_total = len(module.import_funcs) + len(module.func_types)
    tables_total = len(module.import_tables) + len(module.tables)
    mems_total = len(module.import_mems) + len(module.memories)
    globals_total = len(module.import_globals) + len(module.globals)

    # Validate limits
    for table in module.import_tables:
        if table.table_type.limits.max is not None:
            if table.table_type.limits.min > table.table_type.limits.max:
                errors.append(ValidationError(
                    code="limits_min_gt_max",
                    message=f"table import limits: min {table.table_type.limits.min} > max {table.table_type.limits.max}"
                ))

    for table in module.tables:
        if table.limits.max is not None:
            if table.limits.min > table.limits.max:
                errors.append(ValidationError(
                    code="limits_min_gt_max",
                    message=f"table limits: min {table.limits.min} > max {table.limits.max}"
                ))

    for mem in module.import_mems:
        if mem.limits.max is not None:
            if mem.limits.min > mem.limits.max:
                errors.append(ValidationError(
                    code="limits_min_gt_max",
                    message=f"memory import limits: min {mem.limits.min} > max {mem.limits.max}"
                ))

    for mem in module.memories:
        if mem.max is not None:
            if mem.min > mem.max:
                errors.append(ValidationError(
                    code="limits_min_gt_max",
                    message=f"memory limits: min {mem.min} > max {mem.max}"
                ))

    # Validate type indices in imports
    for imp in module.import_funcs:
        if imp.typeidx >= len(module.types):
            errors.append(ValidationError(
                code="type_index_out_of_range",
                message=f"import func typeidx {imp.typeidx} >= {len(module.types)}"
            ))

    # Validate type indices in function section
    for typeidx in module.func_types:
        if typeidx >= len(module.types):
            errors.append(ValidationError(
                code="type_index_out_of_range",
                message=f"function typeidx {typeidx} >= {len(module.types)}"
            ))

    # Validate exports
    seen_export_names = set()
    for exp in module.exports:
        if exp.name in seen_export_names:
            errors.append(ValidationError(
                code="duplicate_export_name",
                message=f"duplicate export name: {exp.name!r}"
            ))
        seen_export_names.add(exp.name)

        if exp.kind == 0:  # func
            if exp.index >= funcs_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"export func index {exp.index} >= {funcs_total}",
                    context="export"
                ))
        elif exp.kind == 1:  # table
            if exp.index >= tables_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"export table index {exp.index} >= {tables_total}",
                    context="export"
                ))
        elif exp.kind == 2:  # mem
            if exp.index >= mems_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"export mem index {exp.index} >= {mems_total}",
                    context="export"
                ))
        elif exp.kind == 3:  # global
            if exp.index >= globals_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"export global index {exp.index} >= {globals_total}",
                    context="export"
                ))

    # Validate start function
    if module.start is not None:
        if module.start >= funcs_total:
            errors.append(ValidationError(
                code="index_out_of_range",
                message=f"start funcidx {module.start} >= {funcs_total}",
                context="start"
            ))
        else:
            # Get the type of the start function
            if module.start < len(module.import_funcs):
                typeidx = module.import_funcs[module.start].typeidx
            else:
                local_idx = module.start - len(module.import_funcs)
                typeidx = module.func_types[local_idx]

            if typeidx < len(module.types):
                func_type = module.types[typeidx]
                if len(func_type.params) != 0 or len(func_type.results) != 0:
                    errors.append(ValidationError(
                        code="bad_start_signature",
                        message=f"start function must have [] -> [] signature, got {len(func_type.params)} params, {len(func_type.results)} results"
                    ))

    # Validate element segments
    for elem in module.elements:
        for funcidx in elem.init:
            if funcidx >= funcs_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"element init funcidx {funcidx} >= {funcs_total}",
                    context="element"
                ))

    # Validate function bodies count
    if len(module.func_bodies) != len(module.func_types):
        errors.append(ValidationError(
            code="func_code_count_mismatch",
            message=f"code count {len(module.func_bodies)} != function count {len(module.func_types)}"
        ))

    # Validate function bodies
    for i, body in enumerate(module.func_bodies):
        if i < len(module.func_types):
            typeidx = module.func_types[i]
            if typeidx < len(module.types):
                func_type = module.types[typeidx]
                num_params = len(func_type.params)
                num_locals = sum(decl.count for decl in body.locals)
                total_locals = num_params + num_locals

                # Validate local indices in expression
                for instr in body.expr.instructions:
                    if instr.opcode in (0x20, 0x21):  # local.get, local.set
                        if instr.immediate >= total_locals:
                            errors.append(ValidationError(
                                code="local_index_out_of_range",
                                message=f"function {i}: local index {instr.immediate} >= {total_locals}"
                            ))
                    elif instr.opcode == 0x10:  # call
                        if instr.immediate >= funcs_total:
                            errors.append(ValidationError(
                                code="index_out_of_range",
                                message=f"function {i}: call funcidx {instr.immediate} >= {funcs_total}",
                                context="call"
                            ))

    # Validate data count
    if module.data_count is not None:
        if module.data_count != len(module.data_segments):
            errors.append(ValidationError(
                code="data_count_mismatch",
                message=f"data count {module.data_count} != actual data segments {len(module.data_segments)}"
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

