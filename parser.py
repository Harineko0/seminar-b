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
    """Function signature: params -> results."""
    params: List[int]  # valtype bytes (0x7F=i32, 0x7E=i64)
    results: List[int]


@dataclass(frozen=True)
class TableLimits:
    """Table or memory limits."""
    min: int
    max: Optional[int] = None


@dataclass(frozen=True)
class TableType:
    """Table type: elemtype + limits."""
    elemtype: int  # 0x70 = funcref
    limits: TableLimits


@dataclass(frozen=True)
class MemoryType:
    """Memory type: just limits."""
    limits: TableLimits


@dataclass(frozen=True)
class GlobalType:
    """Global type: valtype + mutability."""
    valtype: int
    mutable: bool


@dataclass(frozen=True)
class Instruction:
    """Single instruction with opcode and optional immediate."""
    opcode: int
    immediate: Optional[int] = None  # For const/local/call


@dataclass(frozen=True)
class Expression:
    """Expression = sequence of instructions ending with 'end'."""
    instructions: List[Instruction]


@dataclass(frozen=True)
class Import:
    """Import entry."""
    module: bytes
    name: bytes
    kind: int  # 0=func, 1=table, 2=mem, 3=global
    desc: object  # typeidx for func, TableType/MemoryType/GlobalType for others


@dataclass(frozen=True)
class Export:
    """Export entry."""
    name: bytes
    kind: int  # 0=func, 1=table, 2=mem, 3=global
    index: int


@dataclass(frozen=True)
class Global:
    """Global definition."""
    type: GlobalType
    init: Expression


@dataclass(frozen=True)
class LocalDecl:
    """Local variable declaration in function body."""
    count: int
    valtype: int


@dataclass(frozen=True)
class FuncBody:
    """Function body with locals and code."""
    locals: List[LocalDecl]
    code: Expression


@dataclass(frozen=True)
class ElementSegment:
    """Element segment (only active mode for table 0)."""
    tableidx: int
    offset: Expression
    init: List[int]  # funcidx list


@dataclass(frozen=True)
class DataSegment:
    """Data segment (only active mode for memory 0)."""
    memidx: int
    offset: Expression
    data: bytes


@dataclass(frozen=True)
class CustomSection:
    """Custom section (id=0)."""
    name: bytes
    data: bytes


@dataclass(frozen=True)
class Module:
    """
    Complete decoded WASM module AST.
    """
    raw_size: int
    types: List[FuncType]
    imports: List[Import]
    function_types: List[int]  # typeidx for each defined function
    tables: List[TableType]
    memories: List[MemoryType]
    globals: List[Global]
    exports: List[Export]
    start: Optional[int]  # funcidx or None
    elements: List[ElementSegment]
    code: List[FuncBody]
    data: List[DataSegment]
    data_count: Optional[int]
    customs: List[CustomSection]


# ----------------------------
# Internal decoder helpers
# ----------------------------

class Decoder:
    """Binary stream decoder with LEB128 support."""

    def __init__(self, data: bytes, limits: Limits):
        self.data = data
        self.pos = 0
        self.limits = limits

    def eof(self) -> bool:
        return self.pos >= len(self.data)

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def read_byte(self) -> int:
        if self.eof():
            raise DecodeError("Unexpected end of input", offset=self.pos)
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_bytes(self, n: int) -> bytes:
        if self.remaining() < n:
            raise DecodeError(f"Need {n} bytes but only {self.remaining()} available", offset=self.pos)
        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result

    def read_u32(self) -> int:
        """Decode unsigned LEB128 as u32."""
        result = 0
        shift = 0
        for i in range(5):  # max 5 bytes for u32
            if self.eof():
                raise DecodeError("Truncated LEB128", offset=self.pos)
            b = self.read_byte()
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                # Check for overflow
                if shift >= 32 or (shift == 28 and (b & 0xF0) != 0):
                    raise DecodeError("LEB128 value exceeds u32", offset=self.pos)
                # Check for overlong encoding
                if i > 0 and b == 0:
                    raise DecodeError("Overlong LEB128 encoding", offset=self.pos)
                return result
            shift += 7
        raise DecodeError("LEB128 too long for u32", offset=self.pos)

    def read_s32(self) -> int:
        """Decode signed LEB128 as i32."""
        result = 0
        shift = 0
        for i in range(5):
            if self.eof():
                raise DecodeError("Truncated signed LEB128", offset=self.pos)
            b = self.read_byte()
            result |= (b & 0x7F) << shift
            shift += 7
            if (b & 0x80) == 0:
                # Sign extend if needed
                if shift < 32 and (b & 0x40):
                    result |= -(1 << shift)
                # Convert to signed 32-bit
                if result >= 2**31:
                    result -= 2**32
                elif result < -(2**31):
                    result += 2**32
                return result
        raise DecodeError("Signed LEB128 too long", offset=self.pos)

    def read_name(self) -> bytes:
        """Read length-prefixed name (opaque bytes)."""
        length = self.read_u32()
        if length > self.limits.max_section_bytes:
            raise DecodeError(f"Name too long: {length}", offset=self.pos)
        return self.read_bytes(length)

    def read_vec(self, reader_fn, limit: int = None):
        """Read a vector of elements."""
        count = self.read_u32()
        if limit is None:
            limit = self.limits.max_vector_length
        if count > limit:
            raise DecodeError(f"Vector length {count} exceeds limit {limit}", offset=self.pos)
        return [reader_fn() for _ in range(count)]


def decode_valtype(decoder: Decoder) -> int:
    """Decode a value type (only i32/i64 supported)."""
    vt = decoder.read_byte()
    if vt not in (0x7F, 0x7E):  # i32, i64
        raise DecodeError(f"Unsupported valtype: 0x{vt:02X}", offset=decoder.pos, code="unsupported_valtype")
    return vt


def decode_limits(decoder: Decoder) -> TableLimits:
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
        raise DecodeError(f"Bad limits flag: 0x{flags:02X}", offset=decoder.pos, code="bad_limits_flag")


def decode_expression(decoder: Decoder, limits: Limits) -> Expression:
    """Decode an expression (sequence of instructions ending with 'end')."""
    instructions = []
    start_pos = decoder.pos

    while True:
        if decoder.pos - start_pos > limits.max_function_body_bytes:
            raise DecodeError("Expression too long", offset=decoder.pos)

        opcode = decoder.read_byte()

        if opcode == 0x0B:  # end
            break
        elif opcode == 0x41:  # i32.const
            imm = decoder.read_s32()
            instructions.append(Instruction(opcode=opcode, immediate=imm))
        elif opcode == 0x20:  # local.get
            imm = decoder.read_u32()
            instructions.append(Instruction(opcode=opcode, immediate=imm))
        elif opcode == 0x21:  # local.set
            imm = decoder.read_u32()
            instructions.append(Instruction(opcode=opcode, immediate=imm))
        elif opcode == 0x6A:  # i32.add
            instructions.append(Instruction(opcode=opcode))
        elif opcode == 0x10:  # call
            imm = decoder.read_u32()
            instructions.append(Instruction(opcode=opcode, immediate=imm))
        else:
            raise DecodeError(f"Unsupported opcode: 0x{opcode:02X}", offset=decoder.pos, code="unsupported_opcode")

    return Expression(instructions=instructions)


def decode_const_expression(decoder: Decoder) -> Expression:
    """Decode a restricted const expression (i32.const + end)."""
    start_pos = decoder.pos
    expr = decode_expression(decoder, Limits())

    # Must be exactly one i32.const instruction
    if len(expr.instructions) != 1:
        raise DecodeError("Expected single i32.const in offset expression", offset=start_pos, code="unsupported_element_form")
    if expr.instructions[0].opcode != 0x41:
        raise DecodeError("Expected i32.const in offset expression", offset=start_pos, code="unsupported_element_form")

    return expr


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

    module_size = len(data)  # Save before local variable 'data' shadows it
    decoder = Decoder(data, limits)

    # 1. Magic and version
    magic = decoder.read_bytes(4)
    if magic != b"\x00asm":
        raise DecodeError(f"Invalid magic: {magic!r}")
    version = decoder.read_bytes(4)
    if version != b"\x01\x00\x00\x00":
        raise DecodeError(f"Invalid version: {version!r}")

    # Track section order
    last_section_id = -1

    # Initialize all section data
    types: List[FuncType] = []
    imports: List[Import] = []
    function_types: List[int] = []
    tables: List[TableType] = []
    memories: List[MemoryType] = []
    globals: List[Global] = []
    exports: List[Export] = []
    start: Optional[int] = None
    elements: List[ElementSegment] = []
    code: List[FuncBody] = []
    data: List[DataSegment] = []
    data_count: Optional[int] = None
    customs: List[CustomSection] = []

    # 2. Parse sections
    while not decoder.eof():
        section_id = decoder.read_byte()
        section_size = decoder.read_u32()

        if section_size > limits.max_section_bytes and section_id != 0:
            raise DecodeError(f"Section {section_id} size {section_size} exceeds limit", offset=decoder.pos)

        if section_id == 0 and section_size > limits.max_custom_section_bytes:
            raise DecodeError(f"Custom section size {section_size} exceeds limit", offset=decoder.pos)

        section_start = decoder.pos
        section_end = section_start + section_size

        if section_end > module_size:
            raise DecodeError(f"Section extends beyond module end", offset=decoder.pos)

        # Check section ordering (custom sections can appear anywhere)
        if section_id != 0:
            if section_id <= last_section_id:
                raise DecodeError(f"Section {section_id} appears out of order", offset=decoder.pos, code="section_order")
            last_section_id = section_id

        # Parse section payload
        if section_id == 0:  # Custom
            name = decoder.read_name()
            remaining = section_end - decoder.pos
            data_bytes = decoder.read_bytes(remaining)
            customs.append(CustomSection(name=name, data=data_bytes))

        elif section_id == 1:  # Type
            types = decoder.read_vec(lambda: decode_functype(decoder))

        elif section_id == 2:  # Import
            imports = decoder.read_vec(lambda: decode_import(decoder))

        elif section_id == 3:  # Function
            function_types = decoder.read_vec(lambda: decoder.read_u32())

        elif section_id == 4:  # Table
            tables = decoder.read_vec(lambda: decode_tabletype(decoder))

        elif section_id == 5:  # Memory
            memories = decoder.read_vec(lambda: decode_memorytype(decoder))

        elif section_id == 6:  # Global
            globals = decoder.read_vec(lambda: decode_global(decoder, limits))

        elif section_id == 7:  # Export
            exports = decoder.read_vec(lambda: decode_export(decoder))

        elif section_id == 8:  # Start
            start = decoder.read_u32()

        elif section_id == 9:  # Element
            elements = decoder.read_vec(lambda: decode_element(decoder))

        elif section_id == 10:  # Code
            code = decoder.read_vec(lambda: decode_code(decoder, limits))

        elif section_id == 11:  # Data
            data = decoder.read_vec(lambda: decode_data(decoder))

        elif section_id == 12:  # Data count
            data_count = decoder.read_u32()

        else:
            raise DecodeError(f"Unknown section id: {section_id}", offset=decoder.pos, code="unknown_section_id")

        # Verify exact section consumption
        if decoder.pos != section_end:
            raise DecodeError(f"Section size mismatch: expected {section_size}, consumed {decoder.pos - section_start}",
                            offset=section_start, code="section_size_mismatch")

    return Module(
        raw_size=module_size,
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
        customs=customs
    )


def decode_functype(decoder: Decoder) -> FuncType:
    """Decode a function type."""
    tag = decoder.read_byte()
    if tag != 0x60:
        raise DecodeError(f"Expected functype tag 0x60, got 0x{tag:02X}", offset=decoder.pos)
    params = decoder.read_vec(lambda: decode_valtype(decoder))
    results = decoder.read_vec(lambda: decode_valtype(decoder))
    return FuncType(params=params, results=results)


def decode_import(decoder: Decoder) -> Import:
    """Decode an import entry."""
    module = decoder.read_name()
    name = decoder.read_name()
    kind = decoder.read_byte()

    if kind == 0:  # func
        typeidx = decoder.read_u32()
        desc = typeidx
    elif kind == 1:  # table
        desc = decode_tabletype(decoder)
    elif kind == 2:  # memory
        desc = decode_memorytype(decoder)
    elif kind == 3:  # global
        valtype = decode_valtype(decoder)
        mut = decoder.read_byte()
        if mut not in (0x00, 0x01):
            raise DecodeError(f"Invalid mutability: 0x{mut:02X}", offset=decoder.pos, code="bad_mutability")
        desc = GlobalType(valtype=valtype, mutable=(mut == 0x01))
    else:
        raise DecodeError(f"Invalid import kind: {kind}", offset=decoder.pos)

    return Import(module=module, name=name, kind=kind, desc=desc)


def decode_tabletype(decoder: Decoder) -> TableType:
    """Decode a table type."""
    elemtype = decoder.read_byte()
    if elemtype != 0x70:  # funcref
        raise DecodeError(f"Unsupported table elemtype: 0x{elemtype:02X}", offset=decoder.pos,
                        code="unsupported_table_elemtype")
    limits = decode_limits(decoder)
    return TableType(elemtype=elemtype, limits=limits)


def decode_memorytype(decoder: Decoder) -> MemoryType:
    """Decode a memory type."""
    limits = decode_limits(decoder)
    return MemoryType(limits=limits)


def decode_global(decoder: Decoder, limits: Limits) -> Global:
    """Decode a global definition."""
    valtype = decode_valtype(decoder)
    mut = decoder.read_byte()
    if mut not in (0x00, 0x01):
        raise DecodeError(f"Invalid mutability: 0x{mut:02X}", offset=decoder.pos, code="bad_mutability")
    gtype = GlobalType(valtype=valtype, mutable=(mut == 0x01))
    init_expr = decode_expression(decoder, limits)
    return Global(type=gtype, init=init_expr)


def decode_export(decoder: Decoder) -> Export:
    """Decode an export entry."""
    name = decoder.read_name()
    kind = decoder.read_byte()
    if kind not in (0, 1, 2, 3):
        raise DecodeError(f"Invalid export kind: {kind}", offset=decoder.pos)
    index = decoder.read_u32()
    return Export(name=name, kind=kind, index=index)


def decode_element(decoder: Decoder) -> ElementSegment:
    """Decode an element segment (restricted to active mode for table 0)."""
    tableidx = decoder.read_u32()
    if tableidx != 0:
        raise DecodeError(f"Element segment must target table 0, got {tableidx}",
                        offset=decoder.pos, code="unsupported_element_form")

    offset_expr = decode_const_expression(decoder)
    init = decoder.read_vec(lambda: decoder.read_u32())

    return ElementSegment(tableidx=tableidx, offset=offset_expr, init=init)


def decode_code(decoder: Decoder, limits: Limits) -> FuncBody:
    """Decode a function body."""
    body_size = decoder.read_u32()
    if body_size > limits.max_function_body_bytes:
        raise DecodeError(f"Function body size {body_size} exceeds limit", offset=decoder.pos)

    body_start = decoder.pos
    body_end = body_start + body_size

    # Decode locals
    local_decls = decoder.read_vec(lambda: decode_local_decl(decoder))

    # Check total locals count
    total_locals = sum(ld.count for ld in local_decls)
    if total_locals > limits.max_locals_per_function:
        raise DecodeError(f"Total locals {total_locals} exceeds limit", offset=decoder.pos)

    # Decode expression
    expr = decode_expression(decoder, limits)

    # Verify exact consumption
    if decoder.pos != body_end:
        if decoder.pos < body_end:
            raise DecodeError("Trailing bytes in function body", offset=decoder.pos, code="trailing_bytes_in_expr")
        else:
            raise DecodeError("Function body overrun", offset=decoder.pos)

    return FuncBody(locals=local_decls, code=expr)


def decode_local_decl(decoder: Decoder) -> LocalDecl:
    """Decode a local variable declaration."""
    count = decoder.read_u32()
    valtype = decode_valtype(decoder)
    return LocalDecl(count=count, valtype=valtype)


def decode_data(decoder: Decoder) -> DataSegment:
    """Decode a data segment (restricted to active mode for memory 0)."""
    memidx = decoder.read_u32()
    if memidx != 0:
        raise DecodeError(f"Data segment must target memory 0, got {memidx}",
                        offset=decoder.pos, code="unsupported_data_form")

    offset_expr = decode_const_expression(decoder)
    data_len = decoder.read_u32()
    data_bytes = decoder.read_bytes(data_len)

    return DataSegment(memidx=memidx, offset=offset_expr, data=data_bytes)


def validate_module(module: Module) -> List[ValidationError]:
    """
    Perform structural validation on a decoded module.

    Returns:
        List[ValidationError]: empty if valid.
    """
    errors: List[ValidationError] = []

    # Compute index spaces
    funcs_imported = sum(1 for imp in module.imports if imp.kind == 0)
    tables_imported = sum(1 for imp in module.imports if imp.kind == 1)
    mems_imported = sum(1 for imp in module.imports if imp.kind == 2)
    globals_imported = sum(1 for imp in module.imports if imp.kind == 3)

    funcs_total = funcs_imported + len(module.function_types)
    tables_total = tables_imported + len(module.tables)
    mems_total = mems_imported + len(module.memories)
    globals_total = globals_imported + len(module.globals)

    # 1. Validate limits (min <= max)
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

    for imp in module.imports:
        if imp.kind == 1:  # table
            ttype = imp.desc
            if ttype.limits.max is not None and ttype.limits.min > ttype.limits.max:
                errors.append(ValidationError(
                    code="limits_min_gt_max",
                    message=f"Imported table: min {ttype.limits.min} > max {ttype.limits.max}"
                ))
        elif imp.kind == 2:  # memory
            mtype = imp.desc
            if mtype.limits.max is not None and mtype.limits.min > mtype.limits.max:
                errors.append(ValidationError(
                    code="limits_min_gt_max",
                    message=f"Imported memory: min {mtype.limits.min} > max {mtype.limits.max}"
                ))

    # 2. Validate type indices in imports and function section
    for i, imp in enumerate(module.imports):
        if imp.kind == 0:  # func import
            typeidx = imp.desc
            if typeidx >= len(module.types):
                errors.append(ValidationError(
                    code="type_index_out_of_range",
                    message=f"Import {i}: typeidx {typeidx} >= {len(module.types)}"
                ))

    for i, typeidx in enumerate(module.function_types):
        if typeidx >= len(module.types):
            errors.append(ValidationError(
                code="type_index_out_of_range",
                message=f"Function {i}: typeidx {typeidx} >= {len(module.types)}"
            ))

    # 3. Validate exports
    export_names_seen = set()
    for exp in module.exports:
        # Check duplicate names
        if exp.name in export_names_seen:
            errors.append(ValidationError(
                code="duplicate_export_name",
                message=f"Duplicate export name: {exp.name!r}"
            ))
        export_names_seen.add(exp.name)

        # Check index ranges
        if exp.kind == 0:  # func
            if exp.index >= funcs_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export {exp.name!r}: funcidx {exp.index} >= {funcs_total}"
                ))
        elif exp.kind == 1:  # table
            if exp.index >= tables_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export {exp.name!r}: tableidx {exp.index} >= {tables_total}"
                ))
        elif exp.kind == 2:  # memory
            if exp.index >= mems_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export {exp.name!r}: memidx {exp.index} >= {mems_total}"
                ))
        elif exp.kind == 3:  # global
            if exp.index >= globals_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export {exp.name!r}: globalidx {exp.index} >= {globals_total}"
                ))

    # 4. Validate start function
    if module.start is not None:
        if module.start >= funcs_total:
            errors.append(ValidationError(
                code="index_out_of_range",
                message=f"Start function index {module.start} >= {funcs_total}"
            ))
        else:
            # Resolve type of start function
            if module.start < funcs_imported:
                # It's an import
                imp_idx = 0
                for imp in module.imports:
                    if imp.kind == 0:
                        if imp_idx == module.start:
                            typeidx = imp.desc
                            break
                        imp_idx += 1
            else:
                # It's a defined function
                func_idx = module.start - funcs_imported
                if func_idx < len(module.function_types):
                    typeidx = module.function_types[func_idx]

            if typeidx < len(module.types):
                ftype = module.types[typeidx]
                if ftype.params or ftype.results:
                    errors.append(ValidationError(
                        code="bad_start_signature",
                        message=f"Start function must have type [] -> [], got {ftype.params} -> {ftype.results}"
                    ))

    # 5. Validate code section matches function section
    if len(module.code) != len(module.function_types):
        errors.append(ValidationError(
            code="func_code_count_mismatch",
            message=f"Code section has {len(module.code)} entries but function section has {len(module.function_types)}"
        ))

    # 6. Validate function bodies (local and call indices)
    for func_idx, (typeidx, body) in enumerate(zip(module.function_types, module.code)):
        if typeidx >= len(module.types):
            continue  # Already reported

        ftype = module.types[typeidx]
        num_params = len(ftype.params)
        num_locals = sum(ld.count for ld in body.locals)
        total_locals = num_params + num_locals

        # Check local.get/set indices
        for instr in body.code.instructions:
            if instr.opcode in (0x20, 0x21):  # local.get, local.set
                if instr.immediate >= total_locals:
                    errors.append(ValidationError(
                        code="local_index_out_of_range",
                        message=f"Function {funcs_imported + func_idx}: local index {instr.immediate} >= {total_locals}",
                        context=f"func[{func_idx}]"
                    ))
            elif instr.opcode == 0x10:  # call
                if instr.immediate >= funcs_total:
                    errors.append(ValidationError(
                        code="index_out_of_range",
                        message=f"Function {funcs_imported + func_idx}: call target {instr.immediate} >= {funcs_total}",
                        context=f"func[{func_idx}]"
                    ))

    # 7. Validate element segments
    for i, elem in enumerate(module.elements):
        for funcidx in elem.init:
            if funcidx >= funcs_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Element segment {i}: funcidx {funcidx} >= {funcs_total}"
                ))

    # 8. Validate data count
    if module.data_count is not None:
        if module.data_count != len(module.data):
            errors.append(ValidationError(
                code="data_count_mismatch",
                message=f"Data count section says {module.data_count} but data section has {len(module.data)}"
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

