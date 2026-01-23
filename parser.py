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
    """WASM value types."""
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
    """Table type."""
    elemtype: int  # 0x70 for funcref
    limits: TableLimits


@dataclass(frozen=True)
class MemType:
    """Memory type."""
    limits: TableLimits


@dataclass(frozen=True)
class GlobalType:
    """Global type."""
    valtype: ValType
    mutable: bool


@dataclass(frozen=True)
class ImportFunc:
    """Function import."""
    module: bytes
    name: bytes
    typeidx: int


@dataclass(frozen=True)
class ImportTable:
    """Table import."""
    module: bytes
    name: bytes
    table_type: TableType


@dataclass(frozen=True)
class ImportMem:
    """Memory import."""
    module: bytes
    name: bytes
    mem_type: MemType


@dataclass(frozen=True)
class ImportGlobal:
    """Global import."""
    module: bytes
    name: bytes
    global_type: GlobalType


ImportDesc = Union[ImportFunc, ImportTable, ImportMem, ImportGlobal]


@dataclass(frozen=True)
class Export:
    """Export declaration."""
    name: bytes
    kind: int  # 0=func, 1=table, 2=mem, 3=global
    index: int


@dataclass(frozen=True)
class GlobalDef:
    """Global definition."""
    global_type: GlobalType
    init_expr: List['Instruction']


@dataclass(frozen=True)
class LocalDecl:
    """Local variable declaration."""
    count: int
    valtype: ValType


@dataclass(frozen=True)
class FuncBody:
    """Function body."""
    locals: List[LocalDecl]
    expr: List['Instruction']


@dataclass(frozen=True)
class ElementSegment:
    """Element segment (active mode only)."""
    tableidx: int
    offset_expr: List['Instruction']
    init: List[int]  # funcidx list


@dataclass(frozen=True)
class DataSegment:
    """Data segment (active mode only)."""
    memidx: int
    offset_expr: List['Instruction']
    data: bytes


@dataclass(frozen=True)
class Instruction:
    """WASM instruction."""
    opcode: int
    immediate: Optional[int] = None


@dataclass(frozen=True)
class CustomSection:
    """Custom section."""
    name: bytes
    data: bytes


@dataclass(frozen=True)
class Module:
    """Decoded WASM module AST."""
    raw_size: int
    types: List[FuncType] = field(default_factory=list)
    imports: List[ImportDesc] = field(default_factory=list)
    function_typeidxs: List[int] = field(default_factory=list)
    tables: List[TableType] = field(default_factory=list)
    memories: List[MemType] = field(default_factory=list)
    globals: List[GlobalDef] = field(default_factory=list)
    exports: List[Export] = field(default_factory=list)
    start: Optional[int] = None
    elements: List[ElementSegment] = field(default_factory=list)
    code: List[FuncBody] = field(default_factory=list)
    datas: List[DataSegment] = field(default_factory=list)
    data_count: Optional[int] = None
    customs: List[CustomSection] = field(default_factory=list)


# ----------------------------
# Binary decoder
# ----------------------------

class BinaryReader:
    """Binary reader with position tracking."""

    def __init__(self, data: bytes, limits: Limits):
        self.data = data
        self.pos = 0
        self.limits = limits

        if len(data) > limits.max_module_bytes:
            raise DecodeError(f"module exceeds max_module_bytes: {len(data)} > {limits.max_module_bytes}")

    def read_byte(self) -> int:
        """Read a single byte."""
        if self.pos >= len(self.data):
            raise DecodeError("unexpected end of data", offset=self.pos)
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_bytes(self, n: int) -> bytes:
        """Read n bytes."""
        if self.pos + n > len(self.data):
            raise DecodeError(f"unexpected end of data reading {n} bytes", offset=self.pos)
        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result

    def read_u32_leb128(self) -> int:
        """Read unsigned LEB128 u32."""
        result = 0
        shift = 0

        for _ in range(5):  # u32 needs at most 5 bytes
            if self.pos >= len(self.data):
                raise DecodeError("truncated LEB128", offset=self.pos)

            b = self.read_byte()
            result |= (b & 0x7F) << shift

            if (b & 0x80) == 0:
                # Check for overlong encoding
                if shift >= 32 and b != 0:
                    raise DecodeError("LEB128 overlong or overflow for u32", offset=self.pos - 1)
                if result > 0xFFFFFFFF:
                    raise DecodeError("LEB128 overflow for u32", offset=self.pos - 1)
                return result

            shift += 7

        raise DecodeError("LEB128 too long for u32", offset=self.pos)

    def read_s32_leb128(self) -> int:
        """Read signed LEB128 s32."""
        result = 0
        shift = 0

        for _ in range(5):
            if self.pos >= len(self.data):
                raise DecodeError("truncated LEB128", offset=self.pos)

            b = self.read_byte()
            result |= (b & 0x7F) << shift
            shift += 7

            if (b & 0x80) == 0:
                # Sign extend if needed
                if shift < 32 and (b & 0x40):
                    # Sign extend by filling upper bits with 1s
                    result |= (~0 << shift)

                # Convert to signed 32-bit range using two's complement
                # Mask to 32 bits first
                result &= 0xFFFFFFFF

                # Convert to signed
                if result >= 0x80000000:
                    result -= 0x100000000

                return result

        raise DecodeError("LEB128 too long for s32", offset=self.pos)

    def read_name(self) -> bytes:
        """Read a name (length-prefixed byte string)."""
        length = self.read_u32_leb128()
        return self.read_bytes(length)

    def read_vec(self, read_elem, max_length: Optional[int] = None):
        """Read a vector of elements."""
        count = self.read_u32_leb128()

        limit = max_length if max_length is not None else self.limits.max_vector_length
        if count > limit:
            raise DecodeError(f"vector length {count} exceeds limit {limit}", offset=self.pos)

        return [read_elem() for _ in range(count)]

    def at_end(self) -> bool:
        """Check if at end of data."""
        return self.pos >= len(self.data)

    def remaining(self) -> int:
        """Get remaining bytes."""
        return len(self.data) - self.pos


class SectionReader(BinaryReader):
    """Reader for a specific section with size enforcement."""

    def __init__(self, data: bytes, limits: Limits, section_size: int):
        super().__init__(data, limits)
        self.section_size = section_size
        self.section_start = 0

    def check_exact_end(self):
        """Verify we consumed exactly the section payload."""
        if self.pos != self.section_size:
            raise DecodeError(
                f"section size mismatch: expected {self.section_size}, consumed {self.pos}",
                offset=self.pos
            )


def decode_module(data: bytes, *, limits: Limits = Limits()) -> Module:
    """
    Decode a WASM binary module (subset) into a Module AST.

    Raises:
        DecodeError: on malformed input or unsupported forms.
    """
    reader = BinaryReader(data, limits)

    # Check magic and version
    magic = reader.read_bytes(4)
    if magic != b'\x00asm':
        raise DecodeError(f"invalid magic: {magic.hex()}", code="bad_magic")

    version = reader.read_bytes(4)
    if version != b'\x01\x00\x00\x00':
        raise DecodeError(f"invalid version: {version.hex()}", code="bad_version")

    module = Module(raw_size=len(data))

    # Track section order (non-custom sections)
    last_section_id = -1

    while not reader.at_end():
        section_id = reader.read_byte()
        payload_len = reader.read_u32_leb128()

        # Check section size limit
        if section_id == 0:
            if payload_len > limits.max_custom_section_bytes:
                raise DecodeError(f"custom section size {payload_len} exceeds limit")
        else:
            if payload_len > limits.max_section_bytes:
                raise DecodeError(f"section size {payload_len} exceeds limit")

        payload = reader.read_bytes(payload_len)
        sec_reader = SectionReader(payload, limits, payload_len)

        # Custom section can appear anywhere
        if section_id == 0:
            name = sec_reader.read_name()
            custom_data = sec_reader.read_bytes(sec_reader.remaining())
            module.customs.append(CustomSection(name=name, data=custom_data))
            continue

        # Non-custom sections must be in order
        if section_id <= last_section_id:
            raise DecodeError(f"section {section_id} out of order", code="section_order")

        if section_id > 12:
            raise DecodeError(f"unknown section id: {section_id}", code="unknown_section_id")

        last_section_id = section_id

        # Parse each section type
        if section_id == 1:  # Type section
            module.types.extend(parse_type_section(sec_reader))
        elif section_id == 2:  # Import section
            module.imports.extend(parse_import_section(sec_reader))
        elif section_id == 3:  # Function section
            module.function_typeidxs.extend(parse_function_section(sec_reader))
        elif section_id == 4:  # Table section
            module.tables.extend(parse_table_section(sec_reader))
        elif section_id == 5:  # Memory section
            module.memories.extend(parse_memory_section(sec_reader))
        elif section_id == 6:  # Global section
            module.globals.extend(parse_global_section(sec_reader))
        elif section_id == 7:  # Export section
            module.exports.extend(parse_export_section(sec_reader))
        elif section_id == 8:  # Start section
            module.start = parse_start_section(sec_reader)
        elif section_id == 9:  # Element section
            module.elements.extend(parse_element_section(sec_reader))
        elif section_id == 10:  # Code section
            module.code.extend(parse_code_section(sec_reader))
        elif section_id == 11:  # Data section
            module.datas.extend(parse_data_section(sec_reader))
        elif section_id == 12:  # Data count section
            module.data_count = parse_data_count_section(sec_reader)

        sec_reader.check_exact_end()

    return module


def parse_valtype(reader: SectionReader) -> ValType:
    """Parse a value type."""
    b = reader.read_byte()
    if b == 0x7F:
        return ValType.I32
    elif b == 0x7E:
        return ValType.I64
    else:
        raise DecodeError(f"unsupported valtype: 0x{b:02x}", code="unsupported_valtype")


def parse_limits(reader: SectionReader) -> TableLimits:
    """Parse limits."""
    flags = reader.read_byte()

    if flags == 0x00:
        min_val = reader.read_u32_leb128()
        return TableLimits(min=min_val, max=None)
    elif flags == 0x01:
        min_val = reader.read_u32_leb128()
        max_val = reader.read_u32_leb128()
        return TableLimits(min=min_val, max=max_val)
    else:
        raise DecodeError(f"bad limits flag: 0x{flags:02x}", code="bad_limits_flag")


def parse_type_section(reader: SectionReader) -> List[FuncType]:
    """Parse type section."""
    return reader.read_vec(lambda: parse_functype(reader))


def parse_functype(reader: SectionReader) -> FuncType:
    """Parse a function type."""
    marker = reader.read_byte()
    if marker != 0x60:
        raise DecodeError(f"expected functype marker 0x60, got 0x{marker:02x}")

    params = reader.read_vec(lambda: parse_valtype(reader))
    results = reader.read_vec(lambda: parse_valtype(reader))

    return FuncType(params=params, results=results)


def parse_import_section(reader: SectionReader) -> List[ImportDesc]:
    """Parse import section."""
    return reader.read_vec(lambda: parse_import(reader))


def parse_import(reader: SectionReader) -> ImportDesc:
    """Parse a single import."""
    module = reader.read_name()
    name = reader.read_name()
    kind = reader.read_byte()

    if kind == 0:  # Function
        typeidx = reader.read_u32_leb128()
        return ImportFunc(module=module, name=name, typeidx=typeidx)
    elif kind == 1:  # Table
        elemtype = reader.read_byte()
        if elemtype != 0x70:
            raise DecodeError(f"unsupported table elemtype: 0x{elemtype:02x}", code="unsupported_table_elemtype")
        limits = parse_limits(reader)
        return ImportTable(module=module, name=name, table_type=TableType(elemtype=elemtype, limits=limits))
    elif kind == 2:  # Memory
        limits = parse_limits(reader)
        return ImportMem(module=module, name=name, mem_type=MemType(limits=limits))
    elif kind == 3:  # Global
        valtype = parse_valtype(reader)
        mut = reader.read_byte()
        if mut not in (0x00, 0x01):
            raise DecodeError(f"bad mutability: 0x{mut:02x}", code="bad_mutability")
        return ImportGlobal(module=module, name=name, global_type=GlobalType(valtype=valtype, mutable=(mut == 0x01)))
    else:
        raise DecodeError(f"unknown import kind: {kind}")


def parse_function_section(reader: SectionReader) -> List[int]:
    """Parse function section."""
    return reader.read_vec(lambda: reader.read_u32_leb128())


def parse_table_section(reader: SectionReader) -> List[TableType]:
    """Parse table section."""
    return reader.read_vec(lambda: parse_table_type(reader))


def parse_table_type(reader: SectionReader) -> TableType:
    """Parse table type."""
    elemtype = reader.read_byte()
    if elemtype != 0x70:
        raise DecodeError(f"unsupported table elemtype: 0x{elemtype:02x}", code="unsupported_table_elemtype")
    limits = parse_limits(reader)
    return TableType(elemtype=elemtype, limits=limits)


def parse_memory_section(reader: SectionReader) -> List[MemType]:
    """Parse memory section."""
    return reader.read_vec(lambda: parse_memory_type(reader))


def parse_memory_type(reader: SectionReader) -> MemType:
    """Parse memory type."""
    limits = parse_limits(reader)
    return MemType(limits=limits)


def parse_global_section(reader: SectionReader) -> List[GlobalDef]:
    """Parse global section."""
    return reader.read_vec(lambda: parse_global(reader))


def parse_global(reader: SectionReader) -> GlobalDef:
    """Parse a global definition."""
    valtype = parse_valtype(reader)
    mut = reader.read_byte()
    if mut not in (0x00, 0x01):
        raise DecodeError(f"bad mutability: 0x{mut:02x}", code="bad_mutability")

    init_expr = parse_expr(reader)

    return GlobalDef(
        global_type=GlobalType(valtype=valtype, mutable=(mut == 0x01)),
        init_expr=init_expr
    )


def parse_export_section(reader: SectionReader) -> List[Export]:
    """Parse export section."""
    return reader.read_vec(lambda: parse_export(reader))


def parse_export(reader: SectionReader) -> Export:
    """Parse a single export."""
    name = reader.read_name()
    kind = reader.read_byte()
    index = reader.read_u32_leb128()
    return Export(name=name, kind=kind, index=index)


def parse_start_section(reader: SectionReader) -> int:
    """Parse start section."""
    return reader.read_u32_leb128()


def parse_element_section(reader: SectionReader) -> List[ElementSegment]:
    """Parse element section (active mode only)."""
    return reader.read_vec(lambda: parse_element_segment(reader))


def parse_element_segment(reader: SectionReader) -> ElementSegment:
    """Parse element segment."""
    tableidx = reader.read_u32_leb128()
    if tableidx != 0:
        raise DecodeError(f"unsupported element tableidx: {tableidx}", code="unsupported_element_form")

    offset_expr = parse_expr(reader)

    # Verify offset_expr is i32.const + end
    if len(offset_expr) != 2 or offset_expr[0].opcode != 0x41 or offset_expr[1].opcode != 0x0B:
        raise DecodeError("unsupported element offset expr", code="unsupported_element_form")

    init = reader.read_vec(lambda: reader.read_u32_leb128())

    return ElementSegment(tableidx=tableidx, offset_expr=offset_expr, init=init)


def parse_code_section(reader: SectionReader) -> List[FuncBody]:
    """Parse code section."""
    return reader.read_vec(lambda: parse_func_body(reader))


def parse_func_body(reader: SectionReader) -> FuncBody:
    """Parse a function body."""
    body_size = reader.read_u32_leb128()

    if body_size > reader.limits.max_function_body_bytes:
        raise DecodeError(f"function body size {body_size} exceeds limit")

    body_data = reader.read_bytes(body_size)
    body_reader = SectionReader(body_data, reader.limits, body_size)

    locals = body_reader.read_vec(lambda: parse_local_decl(body_reader))

    # Check total locals
    total_locals = sum(ld.count for ld in locals)
    if total_locals > reader.limits.max_locals_per_function:
        raise DecodeError(f"total locals {total_locals} exceeds limit")

    expr = parse_expr(body_reader)

    body_reader.check_exact_end()

    return FuncBody(locals=locals, expr=expr)


def parse_local_decl(reader: SectionReader) -> LocalDecl:
    """Parse local declaration."""
    count = reader.read_u32_leb128()
    valtype = parse_valtype(reader)
    return LocalDecl(count=count, valtype=valtype)


def parse_data_section(reader: SectionReader) -> List[DataSegment]:
    """Parse data section (active mode only)."""
    return reader.read_vec(lambda: parse_data_segment(reader))


def parse_data_segment(reader: SectionReader) -> DataSegment:
    """Parse data segment."""
    memidx = reader.read_u32_leb128()
    if memidx != 0:
        raise DecodeError(f"unsupported data memidx: {memidx}", code="unsupported_data_form")

    offset_expr = parse_expr(reader)

    # Verify offset_expr is i32.const + end
    if len(offset_expr) != 2 or offset_expr[0].opcode != 0x41 or offset_expr[1].opcode != 0x0B:
        raise DecodeError("unsupported data offset expr", code="unsupported_data_form")

    data = reader.read_name()  # Data is length-prefixed

    return DataSegment(memidx=memidx, offset_expr=offset_expr, data=data)


def parse_data_count_section(reader: SectionReader) -> int:
    """Parse data count section."""
    return reader.read_u32_leb128()


def parse_expr(reader: SectionReader) -> List[Instruction]:
    """Parse an expression (instruction sequence ending with 0x0B)."""
    instructions = []

    while True:
        opcode = reader.read_byte()

        if opcode == 0x0B:  # end
            instructions.append(Instruction(opcode=0x0B))
            break
        elif opcode == 0x41:  # i32.const
            immediate = reader.read_s32_leb128()
            instructions.append(Instruction(opcode=0x41, immediate=immediate))
        elif opcode == 0x20:  # local.get
            localidx = reader.read_u32_leb128()
            instructions.append(Instruction(opcode=0x20, immediate=localidx))
        elif opcode == 0x21:  # local.set
            localidx = reader.read_u32_leb128()
            instructions.append(Instruction(opcode=0x21, immediate=localidx))
        elif opcode == 0x6A:  # i32.add
            instructions.append(Instruction(opcode=0x6A))
        elif opcode == 0x10:  # call
            funcidx = reader.read_u32_leb128()
            instructions.append(Instruction(opcode=0x10, immediate=funcidx))
        else:
            raise DecodeError(f"unsupported opcode: 0x{opcode:02x}", code="unsupported_opcode")

    return instructions


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
    imported_funcs = sum(1 for imp in module.imports if isinstance(imp, ImportFunc))
    imported_tables = sum(1 for imp in module.imports if isinstance(imp, ImportTable))
    imported_mems = sum(1 for imp in module.imports if isinstance(imp, ImportMem))
    imported_globals = sum(1 for imp in module.imports if isinstance(imp, ImportGlobal))

    funcs_total = imported_funcs + len(module.function_typeidxs)
    tables_total = imported_tables + len(module.tables)
    mems_total = imported_mems + len(module.memories)
    globals_total = imported_globals + len(module.globals)

    # Validate limits
    for table in module.tables:
        errors.extend(validate_limits(table.limits))
    for mem in module.memories:
        errors.extend(validate_limits(mem.limits))
    for imp in module.imports:
        if isinstance(imp, ImportTable):
            errors.extend(validate_limits(imp.table_type.limits))
        elif isinstance(imp, ImportMem):
            errors.extend(validate_limits(imp.mem_type.limits))

    # Validate type indices in imports
    for imp in module.imports:
        if isinstance(imp, ImportFunc):
            if imp.typeidx >= len(module.types):
                errors.append(ValidationError(
                    code="type_index_out_of_range",
                    message=f"import func typeidx {imp.typeidx} >= {len(module.types)}"
                ))

    # Validate type indices in function section
    for idx, typeidx in enumerate(module.function_typeidxs):
        if typeidx >= len(module.types):
            errors.append(ValidationError(
                code="type_index_out_of_range",
                message=f"function {idx} typeidx {typeidx} >= {len(module.types)}"
            ))

    # Validate exports
    export_names = set()
    for exp in module.exports:
        if exp.name in export_names:
            errors.append(ValidationError(
                code="duplicate_export_name",
                message=f"duplicate export name: {exp.name!r}"
            ))
        export_names.add(exp.name)

        # Validate export indices
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
                func_type = module.types[start_typeidx]
                if func_type.params or func_type.results:
                    errors.append(ValidationError(
                        code="bad_start_signature",
                        message=f"start function must have type [] -> [], got {func_type.params} -> {func_type.results}"
                    ))

    # Validate code/function count match
    if len(module.code) != len(module.function_typeidxs):
        errors.append(ValidationError(
            code="func_code_count_mismatch",
            message=f"code count {len(module.code)} != function count {len(module.function_typeidxs)}"
        ))

    # Validate function bodies
    for func_idx, (body, typeidx) in enumerate(zip(module.code, module.function_typeidxs)):
        if typeidx < len(module.types):
            func_type = module.types[typeidx]
            num_params = len(func_type.params)
            num_locals = sum(ld.count for ld in body.locals)
            total_locals = num_params + num_locals

            # Validate local indices
            for instr in body.expr:
                if instr.opcode in (0x20, 0x21):  # local.get, local.set
                    if instr.immediate is not None and instr.immediate >= total_locals:
                        errors.append(ValidationError(
                            code="local_index_out_of_range",
                            message=f"function {imported_funcs + func_idx}: local index {instr.immediate} >= {total_locals}",
                            context=f"func_{imported_funcs + func_idx}"
                        ))

                # Validate call indices
                if instr.opcode == 0x10:  # call
                    if instr.immediate is not None and instr.immediate >= funcs_total:
                        errors.append(ValidationError(
                            code="index_out_of_range",
                            message=f"function {imported_funcs + func_idx}: call index {instr.immediate} >= {funcs_total}",
                            context=f"func_{imported_funcs + func_idx}"
                        ))

    # Validate element segments
    for elem in module.elements:
        for funcidx in elem.init:
            if funcidx >= funcs_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"element init funcidx {funcidx} >= {funcs_total}"
                ))

    # Validate data count
    if module.data_count is not None:
        if module.data_count != len(module.datas):
            errors.append(ValidationError(
                code="data_count_mismatch",
                message=f"data count {module.data_count} != actual data segments {len(module.datas)}"
            ))

    return errors


def validate_limits(limits: TableLimits) -> List[ValidationError]:
    """Validate table/memory limits."""
    errors = []
    if limits.max is not None and limits.min > limits.max:
        errors.append(ValidationError(
            code="limits_min_gt_max",
            message=f"limits min {limits.min} > max {limits.max}"
        ))
    return errors


def get_func_typeidx(module: Module, funcidx: int) -> Optional[int]:
    """Get the type index for a function (including imports)."""
    imported_funcs = [imp for imp in module.imports if isinstance(imp, ImportFunc)]

    if funcidx < len(imported_funcs):
        return imported_funcs[funcidx].typeidx

    defined_idx = funcidx - len(imported_funcs)
    if defined_idx < len(module.function_typeidxs):
        return module.function_typeidxs[defined_idx]

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
