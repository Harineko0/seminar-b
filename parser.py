"""
parser.py - Public API surface for WASM binary module parsing + structural validation.

Implementation is intentionally omitted in this template.
"""

from __future__ import annotations

from dataclasses import dataclass
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
# AST data structures
# ----------------------------

@dataclass(frozen=True)
class ValType:
    """Value type (i32 or i64)."""
    tag: int  # 0x7F for i32, 0x7E for i64

    def __str__(self) -> str:
        return "i32" if self.tag == 0x7F else "i64"


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
    module: str  # opaque bytes as string
    name: str    # opaque bytes as string
    kind: int    # 0=func, 1=table, 2=mem, 3=global
    desc: Union[int, TableType, MemoryType, GlobalType]  # depends on kind


@dataclass(frozen=True)
class Export:
    """Export entry."""
    name: str  # opaque bytes as string
    kind: int  # 0=func, 1=table, 2=mem, 3=global
    index: int


@dataclass(frozen=True)
class Instruction:
    """Single instruction."""
    opcode: int
    immediate: Optional[int] = None


@dataclass(frozen=True)
class Expression:
    """Expression (sequence of instructions)."""
    instructions: List[Instruction]


@dataclass(frozen=True)
class Global:
    """Global definition."""
    type: GlobalType
    init: Expression


@dataclass(frozen=True)
class LocalDecl:
    """Local variable declaration."""
    count: int
    valtype: ValType


@dataclass(frozen=True)
class FuncBody:
    """Function body."""
    locals: List[LocalDecl]
    expr: Expression


@dataclass(frozen=True)
class ElementSegment:
    """Element segment (subset: active mode only)."""
    tableidx: int
    offset: Expression
    init: List[int]  # funcidx list


@dataclass(frozen=True)
class DataSegment:
    """Data segment (subset: active mode only)."""
    memidx: int
    offset: Expression
    data: bytes


@dataclass(frozen=True)
class CustomSection:
    """Custom section."""
    name: str
    data: bytes


@dataclass(frozen=True)
class Module:
    """
    Placeholder for the decoded AST.
    In the full implementation, this becomes a rich dataclass tree.
    """
    raw_size: int
    types: List[FuncType]
    imports: List[Import]
    functions: List[int]  # type indices
    tables: List[TableType]
    memories: List[MemoryType]
    globals: List[Global]
    exports: List[Export]
    start: Optional[int]
    elements: List[ElementSegment]
    code: List[FuncBody]
    data: List[DataSegment]
    data_count: Optional[int]
    customs: List[CustomSection]


# ----------------------------
# Internal decoder utilities
# ----------------------------

class Decoder:
    """Binary decoder with position tracking."""

    def __init__(self, data: bytes, limits: Limits):
        self.data = data
        self.pos = 0
        self.limits = limits

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def read_byte(self) -> int:
        if self.pos >= len(self.data):
            raise DecodeError("Unexpected end of input (truncated)", offset=self.pos)
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_bytes(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise DecodeError("Unexpected end of input (truncated)", offset=self.pos)
        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result

    def read_u32(self) -> int:
        """Decode unsigned LEB128 as u32."""
        result = 0
        shift = 0
        while True:
            if shift > 28:
                raise DecodeError("LEB128 u32 overflow", offset=self.pos)
            byte = self.read_byte()
            result |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
        if result > 0xFFFFFFFF:
            raise DecodeError("LEB128 u32 overflow", offset=self.pos)
        return result

    def read_s32(self) -> int:
        """Decode signed LEB128 as s32."""
        result = 0
        shift = 0
        byte = 0
        while True:
            if shift > 28:
                raise DecodeError("LEB128 s32 overflow", offset=self.pos)
            byte = self.read_byte()
            result |= (byte & 0x7F) << shift
            shift += 7
            if (byte & 0x80) == 0:
                break
        # Sign extend
        if shift < 32 and (byte & 0x40):
            result |= -(1 << shift)
        # Ensure it fits in s32 range
        if result < -(2**31) or result > 2**31 - 1:
            raise DecodeError("LEB128 s32 overflow", offset=self.pos)
        return result

    def read_name(self) -> str:
        """Read a name (length-prefixed bytes, opaque)."""
        length = self.read_u32()
        if length > self.limits.max_section_bytes:
            raise DecodeError(f"Name too large: {length}", offset=self.pos)
        name_bytes = self.read_bytes(length)
        return name_bytes.decode('latin1')  # opaque bytes, use latin1 for 1:1 mapping

    def read_vector(self, item_reader) -> list:
        """Read a vector (count + items)."""
        count = self.read_u32()
        if count > self.limits.max_vector_length:
            raise DecodeError(f"Vector too large: {count}", offset=self.pos)
        return [item_reader() for _ in range(count)]


# ----------------------------
# Public API functions
# ----------------------------

def decode_module(data: bytes, *, limits: Limits = Limits()) -> Module:
    """
    Decode a WASM binary module (subset) into a Module AST.

    Raises:
        DecodeError: on malformed input or unsupported forms.
    """
    module_size = len(data)
    if module_size > limits.max_module_bytes:
        raise DecodeError(f"Module too large: {module_size} bytes exceeds limit {limits.max_module_bytes}")

    decoder = Decoder(data, limits)

    # Check magic and version
    if decoder.remaining() < 8:
        raise DecodeError("Module too short (truncated magic/version)", offset=decoder.pos)
    magic = decoder.read_bytes(4)
    if magic != b"\x00asm":
        raise DecodeError(f"Invalid magic number: {magic!r}", offset=0)
    version = decoder.read_bytes(4)
    if version != b"\x01\x00\x00\x00":
        raise DecodeError(f"Invalid version: {version!r}", offset=4)

    # Initialize section storage
    types: List[FuncType] = []
    imports: List[Import] = []
    functions: List[int] = []
    tables: List[TableType] = []
    memories: List[MemoryType] = []
    globals: List[Global] = []
    exports: List[Export] = []
    start: Optional[int] = None
    elements: List[ElementSegment] = []
    code: List[FuncBody] = []
    data_segments: List[DataSegment] = []
    data_count: Optional[int] = None
    customs: List[CustomSection] = []

    last_section_id = -1

    # Read sections
    while decoder.remaining() > 0:
        section_id = decoder.read_byte()
        section_size = decoder.read_u32()

        if section_size > limits.max_section_bytes and section_id != 0:
            raise DecodeError(f"Section {section_id} too large: {section_size}", offset=decoder.pos)
        if section_id == 0 and section_size > limits.max_custom_section_bytes:
            raise DecodeError(f"Custom section too large: {section_size}", offset=decoder.pos)

        section_start = decoder.pos
        section_end = section_start + section_size

        if section_end > len(decoder.data):
            raise DecodeError(f"Section {section_id} extends past module end", offset=decoder.pos)

        # Check section ordering (custom sections can appear anywhere)
        if section_id != 0:
            if section_id <= last_section_id:
                raise DecodeError(f"Section {section_id} out of order (previous: {last_section_id})", offset=decoder.pos)
            last_section_id = section_id

        # Decode section based on ID
        if section_id == 0:  # Custom
            name = decoder.read_name()
            custom_data = decoder.read_bytes(section_end - decoder.pos)
            customs.append(CustomSection(name=name, data=custom_data))
        elif section_id == 1:  # Type
            types = decode_type_section(decoder)
        elif section_id == 2:  # Import
            imports = decode_import_section(decoder, limits)
        elif section_id == 3:  # Function
            functions = decode_function_section(decoder)
        elif section_id == 4:  # Table
            tables = decode_table_section(decoder)
        elif section_id == 5:  # Memory
            memories = decode_memory_section(decoder)
        elif section_id == 6:  # Global
            globals = decode_global_section(decoder, limits)
        elif section_id == 7:  # Export
            exports = decode_export_section(decoder, limits)
        elif section_id == 8:  # Start
            start = decoder.read_u32()
        elif section_id == 9:  # Element
            elements = decode_element_section(decoder, limits)
        elif section_id == 10:  # Code
            code = decode_code_section(decoder, limits)
        elif section_id == 11:  # Data
            data_segments = decode_data_section(decoder, limits)
        elif section_id == 12:  # Data count
            data_count = decoder.read_u32()
        else:
            raise DecodeError(f"Unknown section ID: {section_id}", offset=section_start - 1)

        # Ensure section was fully consumed
        if decoder.pos != section_end:
            raise DecodeError(f"Section {section_id} size mismatch: expected {section_size}, consumed {decoder.pos - section_start}", offset=section_start)

    return Module(
        raw_size=module_size,
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
        data=data_segments,
        data_count=data_count,
        customs=customs
    )


def decode_type_section(decoder: Decoder) -> List[FuncType]:
    """Decode type section."""
    def read_valtype() -> ValType:
        tag = decoder.read_byte()
        if tag not in (0x7F, 0x7E):
            raise DecodeError(f"Unsupported valtype: 0x{tag:02x}", offset=decoder.pos - 1)
        return ValType(tag=tag)

    def read_functype() -> FuncType:
        tag = decoder.read_byte()
        if tag != 0x60:
            raise DecodeError(f"Invalid functype tag: 0x{tag:02x}", offset=decoder.pos - 1)
        params = decoder.read_vector(read_valtype)
        results = decoder.read_vector(read_valtype)
        return FuncType(params=params, results=results)

    return decoder.read_vector(read_functype)


def decode_import_section(decoder: Decoder, limits: Limits) -> List[Import]:
    """Decode import section."""
    def read_import() -> Import:
        module = decoder.read_name()
        name = decoder.read_name()
        kind = decoder.read_byte()

        if kind == 0:  # func
            typeidx = decoder.read_u32()
            return Import(module=module, name=name, kind=kind, desc=typeidx)
        elif kind == 1:  # table
            elemtype = decoder.read_byte()
            if elemtype != 0x70:
                raise DecodeError(f"Unsupported table elemtype: 0x{elemtype:02x}", offset=decoder.pos - 1)
            lim = read_limits()
            return Import(module=module, name=name, kind=kind, desc=TableType(elemtype=elemtype, limits=lim))
        elif kind == 2:  # mem
            lim = read_limits()
            return Import(module=module, name=name, kind=kind, desc=MemoryType(limits=lim))
        elif kind == 3:  # global
            tag = decoder.read_byte()
            if tag not in (0x7F, 0x7E):
                raise DecodeError(f"Unsupported valtype: 0x{tag:02x}", offset=decoder.pos - 1)
            mut = decoder.read_byte()
            if mut not in (0x00, 0x01):
                raise DecodeError(f"Bad mutability: 0x{mut:02x}", offset=decoder.pos - 1)
            return Import(module=module, name=name, kind=kind, desc=GlobalType(valtype=ValType(tag), mutable=(mut == 0x01)))
        else:
            raise DecodeError(f"Unknown import kind: {kind}", offset=decoder.pos - 1)

    def read_limits() -> TableLimits:
        flags = decoder.read_byte()
        if flags == 0x00:
            min_val = decoder.read_u32()
            return TableLimits(min=min_val, max=None)
        elif flags == 0x01:
            min_val = decoder.read_u32()
            max_val = decoder.read_u32()
            return TableLimits(min=min_val, max=max_val)
        else:
            raise DecodeError(f"Bad limits flag: 0x{flags:02x}", offset=decoder.pos - 1)

    return decoder.read_vector(read_import)


def decode_function_section(decoder: Decoder) -> List[int]:
    """Decode function section."""
    return decoder.read_vector(decoder.read_u32)


def decode_table_section(decoder: Decoder) -> List[TableType]:
    """Decode table section."""
    def read_table() -> TableType:
        elemtype = decoder.read_byte()
        if elemtype != 0x70:
            raise DecodeError(f"Unsupported table elemtype: 0x{elemtype:02x}", offset=decoder.pos - 1)
        lim = read_limits()
        return TableType(elemtype=elemtype, limits=lim)

    def read_limits() -> TableLimits:
        flags = decoder.read_byte()
        if flags == 0x00:
            min_val = decoder.read_u32()
            return TableLimits(min=min_val, max=None)
        elif flags == 0x01:
            min_val = decoder.read_u32()
            max_val = decoder.read_u32()
            return TableLimits(min=min_val, max=max_val)
        else:
            raise DecodeError(f"Bad limits flag: 0x{flags:02x}", offset=decoder.pos - 1)

    return decoder.read_vector(read_table)


def decode_memory_section(decoder: Decoder) -> List[MemoryType]:
    """Decode memory section."""
    def read_memory() -> MemoryType:
        lim = read_limits()
        return MemoryType(limits=lim)

    def read_limits() -> TableLimits:
        flags = decoder.read_byte()
        if flags == 0x00:
            min_val = decoder.read_u32()
            return TableLimits(min=min_val, max=None)
        elif flags == 0x01:
            min_val = decoder.read_u32()
            max_val = decoder.read_u32()
            return TableLimits(min=min_val, max=max_val)
        else:
            raise DecodeError(f"Bad limits flag: 0x{flags:02x}", offset=decoder.pos - 1)

    return decoder.read_vector(read_memory)


def decode_global_section(decoder: Decoder, limits: Limits) -> List[Global]:
    """Decode global section."""
    def read_global() -> Global:
        tag = decoder.read_byte()
        if tag not in (0x7F, 0x7E):
            raise DecodeError(f"Unsupported valtype: 0x{tag:02x}", offset=decoder.pos - 1)
        mut = decoder.read_byte()
        if mut not in (0x00, 0x01):
            raise DecodeError(f"Bad mutability: 0x{mut:02x}", offset=decoder.pos - 1)
        init_expr = read_expression()
        return Global(type=GlobalType(valtype=ValType(tag), mutable=(mut == 0x01)), init=init_expr)

    def read_expression() -> Expression:
        instructions = []
        while True:
            opcode = decoder.read_byte()
            if opcode == 0x0B:  # end
                instructions.append(Instruction(opcode=opcode))
                break
            elif opcode == 0x41:  # i32.const
                imm = decoder.read_s32()
                instructions.append(Instruction(opcode=opcode, immediate=imm))
            else:
                raise DecodeError(f"Unsupported opcode in init expression: 0x{opcode:02x}", offset=decoder.pos - 1)
        return Expression(instructions=instructions)

    return decoder.read_vector(read_global)


def decode_export_section(decoder: Decoder, limits: Limits) -> List[Export]:
    """Decode export section."""
    def read_export() -> Export:
        name = decoder.read_name()
        kind = decoder.read_byte()
        index = decoder.read_u32()
        return Export(name=name, kind=kind, index=index)

    return decoder.read_vector(read_export)


def decode_element_section(decoder: Decoder, limits: Limits) -> List[ElementSegment]:
    """Decode element section (subset: active mode only)."""
    def read_element() -> ElementSegment:
        tableidx = decoder.read_u32()
        if tableidx != 0:
            raise DecodeError(f"Unsupported element form: tableidx={tableidx}", offset=decoder.pos)

        # Read offset expression (must be i32.const + end)
        offset_start = decoder.pos
        opcode = decoder.read_byte()
        if opcode != 0x41:  # i32.const
            raise DecodeError(f"Unsupported element form: expected i32.const", offset=offset_start)
        offset_val = decoder.read_s32()
        end_opcode = decoder.read_byte()
        if end_opcode != 0x0B:
            raise DecodeError(f"Unsupported element form: expected end after i32.const", offset=decoder.pos - 1)
        offset = Expression(instructions=[Instruction(opcode=0x41, immediate=offset_val), Instruction(opcode=0x0B)])

        # Read init vector
        init = decoder.read_vector(decoder.read_u32)
        return ElementSegment(tableidx=tableidx, offset=offset, init=init)

    return decoder.read_vector(read_element)


def decode_code_section(decoder: Decoder, limits: Limits) -> List[FuncBody]:
    """Decode code section."""
    def read_func_body() -> FuncBody:
        body_size = decoder.read_u32()
        if body_size > limits.max_function_body_bytes:
            raise DecodeError(f"Function body too large: {body_size}", offset=decoder.pos)

        body_start = decoder.pos
        body_end = body_start + body_size

        # Read locals
        def read_local_decl() -> LocalDecl:
            count = decoder.read_u32()
            tag = decoder.read_byte()
            if tag not in (0x7F, 0x7E):
                raise DecodeError(f"Unsupported valtype: 0x{tag:02x}", offset=decoder.pos - 1)
            return LocalDecl(count=count, valtype=ValType(tag))

        locals = decoder.read_vector(read_local_decl)

        # Check total locals count
        total_locals = sum(ld.count for ld in locals)
        if total_locals > limits.max_locals_per_function:
            raise DecodeError(f"Too many locals: {total_locals}", offset=body_start)

        # Read expression
        expr = read_expression()

        # Ensure body was fully consumed
        if decoder.pos != body_end:
            raise DecodeError(f"Function body size mismatch", offset=body_start)

        return FuncBody(locals=locals, expr=expr)

    def read_expression() -> Expression:
        instructions = []
        while True:
            opcode = decoder.read_byte()
            if opcode == 0x0B:  # end
                instructions.append(Instruction(opcode=opcode))
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
                raise DecodeError(f"Unsupported opcode: 0x{opcode:02x}", offset=decoder.pos - 1)
        return Expression(instructions=instructions)

    return decoder.read_vector(read_func_body)


def decode_data_section(decoder: Decoder, limits: Limits) -> List[DataSegment]:
    """Decode data section (subset: active mode only)."""
    def read_data() -> DataSegment:
        memidx = decoder.read_u32()
        if memidx != 0:
            raise DecodeError(f"Unsupported data form: memidx={memidx}", offset=decoder.pos)

        # Read offset expression (must be i32.const + end)
        offset_start = decoder.pos
        opcode = decoder.read_byte()
        if opcode != 0x41:  # i32.const
            raise DecodeError(f"Unsupported data form: expected i32.const", offset=offset_start)
        offset_val = decoder.read_s32()
        end_opcode = decoder.read_byte()
        if end_opcode != 0x0B:
            raise DecodeError(f"Unsupported data form: expected end after i32.const", offset=decoder.pos - 1)
        offset = Expression(instructions=[Instruction(opcode=0x41, immediate=offset_val), Instruction(opcode=0x0B)])

        # Read data bytes
        data_len = decoder.read_u32()
        data_bytes = decoder.read_bytes(data_len)
        return DataSegment(memidx=memidx, offset=offset, data=data_bytes)

    return decoder.read_vector(read_data)


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

    funcs_total = imported_funcs + len(module.functions)
    tables_total = imported_tables + len(module.tables)
    mems_total = imported_mems + len(module.memories)
    globals_total = imported_globals + len(module.globals)

    # Validate limits (min <= max)
    for i, table in enumerate(module.tables):
        if table.limits.max is not None and table.limits.min > table.limits.max:
            errors.append(ValidationError(
                code="limits_min_gt_max",
                message=f"Table {i}: min ({table.limits.min}) > max ({table.limits.max})",
                context=f"table_{i}"
            ))

    for i, mem in enumerate(module.memories):
        if mem.limits.max is not None and mem.limits.min > mem.limits.max:
            errors.append(ValidationError(
                code="limits_min_gt_max",
                message=f"Memory {i}: min ({mem.limits.min}) > max ({mem.limits.max})",
                context=f"memory_{i}"
            ))

    # Check imported table limits
    for i, imp in enumerate(module.imports):
        if imp.kind == 1:
            desc = imp.desc
            if isinstance(desc, TableType):
                if desc.limits.max is not None and desc.limits.min > desc.limits.max:
                    errors.append(ValidationError(
                        code="limits_min_gt_max",
                        message=f"Imported table {i}: min ({desc.limits.min}) > max ({desc.limits.max})",
                        context=f"import_{i}"
                    ))
        elif imp.kind == 2:
            desc = imp.desc
            if isinstance(desc, MemoryType):
                if desc.limits.max is not None and desc.limits.min > desc.limits.max:
                    errors.append(ValidationError(
                        code="limits_min_gt_max",
                        message=f"Imported memory {i}: min ({desc.limits.min}) > max ({desc.limits.max})",
                        context=f"import_{i}"
                    ))

    # Validate type indices in imports
    for i, imp in enumerate(module.imports):
        if imp.kind == 0:  # func import
            typeidx = imp.desc
            if isinstance(typeidx, int) and typeidx >= len(module.types):
                errors.append(ValidationError(
                    code="type_index_out_of_range",
                    message=f"Import {i}: type index {typeidx} out of range (have {len(module.types)} types)",
                    context=f"import_{i}"
                ))

    # Validate type indices in functions
    for i, typeidx in enumerate(module.functions):
        if typeidx >= len(module.types):
            errors.append(ValidationError(
                code="type_index_out_of_range",
                message=f"Function {i}: type index {typeidx} out of range (have {len(module.types)} types)",
                context=f"function_{i}"
            ))

    # Validate function/code count match
    if len(module.functions) != len(module.code):
        errors.append(ValidationError(
            code="func_code_count_mismatch",
            message=f"Function count ({len(module.functions)}) != code count ({len(module.code)})",
            context="code_section"
        ))

    # Validate exports
    export_names = set()
    for i, exp in enumerate(module.exports):
        # Check duplicate names
        if exp.name in export_names:
            errors.append(ValidationError(
                code="duplicate_export_name",
                message=f"Duplicate export name: {exp.name!r}",
                context=f"export_{i}"
            ))
        export_names.add(exp.name)

        # Check index ranges
        if exp.kind == 0:  # func
            if exp.index >= funcs_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export {exp.name!r}: function index {exp.index} out of range (have {funcs_total} funcs)",
                    context=f"export_{i}"
                ))
        elif exp.kind == 1:  # table
            if exp.index >= tables_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export {exp.name!r}: table index {exp.index} out of range (have {tables_total} tables)",
                    context=f"export_{i}"
                ))
        elif exp.kind == 2:  # mem
            if exp.index >= mems_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export {exp.name!r}: memory index {exp.index} out of range (have {mems_total} memories)",
                    context=f"export_{i}"
                ))
        elif exp.kind == 3:  # global
            if exp.index >= globals_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export {exp.name!r}: global index {exp.index} out of range (have {globals_total} globals)",
                    context=f"export_{i}"
                ))

    # Validate start function
    if module.start is not None:
        if module.start >= funcs_total:
            errors.append(ValidationError(
                code="index_out_of_range",
                message=f"Start function index {module.start} out of range (have {funcs_total} funcs)",
                context="start_section"
            ))
        else:
            # Check start function signature (must be [] -> [])
            if module.start < imported_funcs:
                # It's an import
                imp_idx = 0
                for imp in module.imports:
                    if imp.kind == 0:
                        if imp_idx == module.start:
                            typeidx = imp.desc
                            if isinstance(typeidx, int) and typeidx < len(module.types):
                                func_type = module.types[typeidx]
                                if len(func_type.params) != 0 or len(func_type.results) != 0:
                                    errors.append(ValidationError(
                                        code="bad_start_signature",
                                        message=f"Start function has invalid signature: must have type [] -> [], got {len(func_type.params)} params, {len(func_type.results)} results",
                                        context="start_section"
                                    ))
                            break
                        imp_idx += 1
            else:
                # It's a defined function
                func_idx = module.start - imported_funcs
                if func_idx < len(module.functions):
                    typeidx = module.functions[func_idx]
                    if typeidx < len(module.types):
                        func_type = module.types[typeidx]
                        if len(func_type.params) != 0 or len(func_type.results) != 0:
                            errors.append(ValidationError(
                                code="bad_start_signature",
                                message=f"Start function has invalid signature: must have type [] -> [], got {len(func_type.params)} params, {len(func_type.results)} results",
                                context="start_section"
                            ))

    # Validate code section local indices and call indices
    for i, (func_body, typeidx) in enumerate(zip(module.code, module.functions)):
        # Get number of params
        if typeidx < len(module.types):
            num_params = len(module.types[typeidx].params)
        else:
            num_params = 0  # Already reported error above

        # Count locals
        num_locals = sum(ld.count for ld in func_body.locals)
        total_locals = num_params + num_locals

        # Check local indices
        for instr in func_body.expr.instructions:
            if instr.opcode in (0x20, 0x21):  # local.get, local.set
                if instr.immediate is not None and instr.immediate >= total_locals:
                    errors.append(ValidationError(
                        code="local_index_out_of_range",
                        message=f"Function {i}: local index {instr.immediate} out of range (have {total_locals} locals)",
                        context=f"function_{i}"
                    ))
            elif instr.opcode == 0x10:  # call
                if instr.immediate is not None and instr.immediate >= funcs_total:
                    errors.append(ValidationError(
                        code="index_out_of_range",
                        message=f"Function {i}: call index {instr.immediate} out of range (have {funcs_total} funcs)",
                        context=f"function_{i}"
                    ))

    # Validate element section
    for i, elem in enumerate(module.elements):
        for j, funcidx in enumerate(elem.init):
            if funcidx >= funcs_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Element {i}: funcidx {funcidx} out of range (have {funcs_total} funcs)",
                    context=f"element_{i}"
                ))

    # Validate data count
    if module.data_count is not None:
        if module.data_count != len(module.data):
            errors.append(ValidationError(
                code="data_count_mismatch",
                message=f"Data count ({module.data_count}) != actual data segments ({len(module.data)})",
                context="data_count_section"
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

