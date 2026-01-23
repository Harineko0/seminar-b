"""
parser.py - Public API surface for WASM binary module parsing + structural validation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List, Union
from enum import Enum


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
# AST Dataclasses
# ----------------------------

class ValType(Enum):
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
class GlobalType:
    valtype: ValType
    mutable: bool


@dataclass(frozen=True)
class Instruction:
    opcode: int
    immediate: Optional[int] = None


@dataclass(frozen=True)
class Expression:
    instructions: List[Instruction]


@dataclass(frozen=True)
class ImportFunc:
    module: bytes
    name: bytes
    typeidx: int


@dataclass(frozen=True)
class ImportTable:
    module: bytes
    name: bytes
    limits: TableLimits


@dataclass(frozen=True)
class ImportMemory:
    module: bytes
    name: bytes
    limits: MemoryLimits


@dataclass(frozen=True)
class ImportGlobal:
    module: bytes
    name: bytes
    globaltype: GlobalType


Import = Union[ImportFunc, ImportTable, ImportMemory, ImportGlobal]


@dataclass(frozen=True)
class Table:
    limits: TableLimits


@dataclass(frozen=True)
class Memory:
    limits: MemoryLimits


@dataclass(frozen=True)
class Global:
    globaltype: GlobalType
    init_expr: Expression


@dataclass(frozen=True)
class Export:
    name: bytes
    kind: int  # 0=func, 1=table, 2=mem, 3=global
    index: int


@dataclass(frozen=True)
class ElementSegment:
    tableidx: int
    offset_expr: Expression
    funcidxs: List[int]


@dataclass(frozen=True)
class LocalDecl:
    count: int
    valtype: ValType


@dataclass(frozen=True)
class FunctionBody:
    locals: List[LocalDecl]
    expr: Expression


@dataclass(frozen=True)
class DataSegment:
    memidx: int
    offset_expr: Expression
    data: bytes


@dataclass(frozen=True)
class CustomSection:
    name: bytes
    data: bytes


@dataclass(frozen=True)
class Module:
    """The decoded WASM module AST."""
    raw_size: int
    types: List[FuncType] = field(default_factory=list)
    imports: List[Import] = field(default_factory=list)
    function_typeidxs: List[int] = field(default_factory=list)
    tables: List[Table] = field(default_factory=list)
    memories: List[Memory] = field(default_factory=list)
    globals: List[Global] = field(default_factory=list)
    exports: List[Export] = field(default_factory=list)
    start: Optional[int] = None
    elements: List[ElementSegment] = field(default_factory=list)
    code: List[FunctionBody] = field(default_factory=list)
    data: List[DataSegment] = field(default_factory=list)
    data_count: Optional[int] = None
    customs: List[CustomSection] = field(default_factory=list)


# ----------------------------
# Binary Decoder
# ----------------------------

class BinaryReader:
    """Helper class for reading WASM binary format."""

    def __init__(self, data: bytes, limits: Limits):
        self.data = data
        self.pos = 0
        self.limits = limits

    def read_byte(self) -> int:
        """Read a single byte."""
        if self.pos >= len(self.data):
            raise DecodeError("Unexpected end of data", offset=self.pos)
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_bytes(self, n: int) -> bytes:
        """Read n bytes."""
        if self.pos + n > len(self.data):
            raise DecodeError("Unexpected end of data", offset=self.pos)
        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result

    def read_u32_leb128(self) -> int:
        """Read unsigned LEB128 u32."""
        result = 0
        shift = 0
        while True:
            if shift > 28:  # u32 is max 5 bytes (5*7=35 bits, but we check > 2^32)
                raise DecodeError("LEB128 u32 overlong or too large", offset=self.pos)
            if self.pos >= len(self.data):
                raise DecodeError("Truncated LEB128", offset=self.pos)

            byte = self.read_byte()
            result |= (byte & 0x7F) << shift

            if (byte & 0x80) == 0:
                if result > 0xFFFFFFFF:
                    raise DecodeError("LEB128 u32 value exceeds 2^32-1", offset=self.pos-1)
                return result

            shift += 7

    def read_s32_leb128(self) -> int:
        """Read signed LEB128 s32."""
        result = 0
        shift = 0
        while True:
            if shift > 28:
                raise DecodeError("LEB128 s32 overlong or too large", offset=self.pos)
            if self.pos >= len(self.data):
                raise DecodeError("Truncated LEB128", offset=self.pos)

            byte = self.read_byte()
            result |= (byte & 0x7F) << shift
            shift += 7

            if (byte & 0x80) == 0:
                # Sign extend
                if shift < 32 and (byte & 0x40):
                    result |= -(1 << shift)

                # Check range for s32
                if result < -(2**31) or result > (2**31 - 1):
                    raise DecodeError("LEB128 s32 value out of range", offset=self.pos-1)
                return result

    def read_name(self) -> bytes:
        """Read a name (length-prefixed byte string)."""
        length = self.read_u32_leb128()
        if length > self.limits.max_section_bytes:
            raise DecodeError(f"Name length {length} exceeds limit", offset=self.pos)
        return self.read_bytes(length)

    def read_valtype(self) -> ValType:
        """Read a value type."""
        b = self.read_byte()
        if b == 0x7F:
            return ValType.I32
        elif b == 0x7E:
            return ValType.I64
        else:
            raise DecodeError(f"Unsupported valtype: 0x{b:02x}", offset=self.pos-1, code="unsupported_valtype")

    def at_end(self) -> bool:
        """Check if at end of data."""
        return self.pos >= len(self.data)

    def remaining(self) -> int:
        """Get remaining bytes."""
        return len(self.data) - self.pos


def decode_module(data: bytes, *, limits: Limits = Limits()) -> Module:
    """
    Decode a WASM binary module (subset) into a Module AST.

    Raises:
        DecodeError: on malformed input or unsupported forms.
    """
    if len(data) > limits.max_module_bytes:
        raise DecodeError(f"Module size {len(data)} exceeds limit {limits.max_module_bytes}")

    reader = BinaryReader(data, limits)

    # Check magic and version
    magic = reader.read_bytes(4)
    if magic != b'\x00asm':
        raise DecodeError(f"Invalid magic number: {magic.hex()}")

    version = reader.read_bytes(4)
    if version != b'\x01\x00\x00\x00':
        raise DecodeError(f"Invalid version: {version.hex()}")

    # Parse sections
    types: List[FuncType] = []
    imports: List[Import] = []
    function_typeidxs: List[int] = []
    tables: List[Table] = []
    memories: List[Memory] = []
    globals: List[Global] = []
    exports: List[Export] = []
    start: Optional[int] = None
    elements: List[ElementSegment] = []
    code: List[FunctionBody] = []
    data_segs: List[DataSegment] = []
    data_count: Optional[int] = None
    customs: List[CustomSection] = []

    last_section_id = -1

    while not reader.at_end():
        section_id = reader.read_byte()
        section_size = reader.read_u32_leb128()

        if section_size > limits.max_section_bytes:
            if section_id == 0 and section_size > limits.max_custom_section_bytes:
                raise DecodeError(f"Custom section size {section_size} exceeds limit", offset=reader.pos)
            elif section_id != 0:
                raise DecodeError(f"Section size {section_size} exceeds limit", offset=reader.pos)

        section_start = reader.pos
        section_end = section_start + section_size

        if section_end > len(data):
            raise DecodeError("Section extends beyond module", offset=reader.pos)

        # Check section ordering (custom sections can appear anywhere)
        if section_id != 0:
            if section_id <= last_section_id:
                raise DecodeError(f"Section {section_id} appears out of order", offset=reader.pos, code="section_order")
            last_section_id = section_id

        # Create a reader for this section
        section_data = data[section_start:section_end]
        sec_reader = BinaryReader(section_data, limits)

        if section_id == 0:  # Custom section
            name = sec_reader.read_name()
            custom_data = sec_reader.read_bytes(sec_reader.remaining())
            customs.append(CustomSection(name=name, data=custom_data))

        elif section_id == 1:  # Type section
            count = sec_reader.read_u32_leb128()
            if count > limits.max_vector_length:
                raise DecodeError(f"Type count {count} exceeds limit", offset=sec_reader.pos)

            for _ in range(count):
                tag = sec_reader.read_byte()
                if tag != 0x60:
                    raise DecodeError(f"Invalid functype tag: 0x{tag:02x}", offset=sec_reader.pos)

                param_count = sec_reader.read_u32_leb128()
                if param_count > limits.max_vector_length:
                    raise DecodeError(f"Param count {param_count} exceeds limit", offset=sec_reader.pos)
                params = [sec_reader.read_valtype() for _ in range(param_count)]

                result_count = sec_reader.read_u32_leb128()
                if result_count > limits.max_vector_length:
                    raise DecodeError(f"Result count {result_count} exceeds limit", offset=sec_reader.pos)
                results = [sec_reader.read_valtype() for _ in range(result_count)]

                types.append(FuncType(params=params, results=results))

        elif section_id == 2:  # Import section
            count = sec_reader.read_u32_leb128()
            if count > limits.max_vector_length:
                raise DecodeError(f"Import count {count} exceeds limit", offset=sec_reader.pos)

            for _ in range(count):
                module_name = sec_reader.read_name()
                item_name = sec_reader.read_name()
                kind = sec_reader.read_byte()

                if kind == 0:  # func
                    typeidx = sec_reader.read_u32_leb128()
                    imports.append(ImportFunc(module=module_name, name=item_name, typeidx=typeidx))
                elif kind == 1:  # table
                    elemtype = sec_reader.read_byte()
                    if elemtype != 0x70:
                        raise DecodeError(f"Unsupported table elemtype: 0x{elemtype:02x}",
                                        offset=sec_reader.pos, code="unsupported_table_elemtype")
                    lim = read_limits(sec_reader)
                    imports.append(ImportTable(module=module_name, name=item_name, limits=lim))
                elif kind == 2:  # memory
                    lim = read_limits(sec_reader)
                    imports.append(ImportMemory(module=module_name, name=item_name, limits=lim))
                elif kind == 3:  # global
                    valtype = sec_reader.read_valtype()
                    mut_byte = sec_reader.read_byte()
                    if mut_byte not in (0x00, 0x01):
                        raise DecodeError(f"Invalid mutability: 0x{mut_byte:02x}",
                                        offset=sec_reader.pos, code="bad_mutability")
                    mutable = (mut_byte == 0x01)
                    globaltype = GlobalType(valtype=valtype, mutable=mutable)
                    imports.append(ImportGlobal(module=module_name, name=item_name, globaltype=globaltype))
                else:
                    raise DecodeError(f"Unknown import kind: {kind}", offset=sec_reader.pos)

        elif section_id == 3:  # Function section
            count = sec_reader.read_u32_leb128()
            if count > limits.max_vector_length:
                raise DecodeError(f"Function count {count} exceeds limit", offset=sec_reader.pos)
            function_typeidxs = [sec_reader.read_u32_leb128() for _ in range(count)]

        elif section_id == 4:  # Table section
            count = sec_reader.read_u32_leb128()
            if count > limits.max_vector_length:
                raise DecodeError(f"Table count {count} exceeds limit", offset=sec_reader.pos)

            for _ in range(count):
                elemtype = sec_reader.read_byte()
                if elemtype != 0x70:
                    raise DecodeError(f"Unsupported table elemtype: 0x{elemtype:02x}",
                                    offset=sec_reader.pos, code="unsupported_table_elemtype")
                lim = read_limits(sec_reader)
                tables.append(Table(limits=lim))

        elif section_id == 5:  # Memory section
            count = sec_reader.read_u32_leb128()
            if count > limits.max_vector_length:
                raise DecodeError(f"Memory count {count} exceeds limit", offset=sec_reader.pos)

            for _ in range(count):
                lim = read_limits(sec_reader)
                memories.append(Memory(limits=lim))

        elif section_id == 6:  # Global section
            count = sec_reader.read_u32_leb128()
            if count > limits.max_vector_length:
                raise DecodeError(f"Global count {count} exceeds limit", offset=sec_reader.pos)

            for _ in range(count):
                valtype = sec_reader.read_valtype()
                mut_byte = sec_reader.read_byte()
                if mut_byte not in (0x00, 0x01):
                    raise DecodeError(f"Invalid mutability: 0x{mut_byte:02x}",
                                    offset=sec_reader.pos, code="bad_mutability")
                mutable = (mut_byte == 0x01)
                globaltype = GlobalType(valtype=valtype, mutable=mutable)
                init_expr = read_expression(sec_reader)
                globals.append(Global(globaltype=globaltype, init_expr=init_expr))

        elif section_id == 7:  # Export section
            count = sec_reader.read_u32_leb128()
            if count > limits.max_vector_length:
                raise DecodeError(f"Export count {count} exceeds limit", offset=sec_reader.pos)

            for _ in range(count):
                name = sec_reader.read_name()
                kind = sec_reader.read_byte()
                index = sec_reader.read_u32_leb128()
                exports.append(Export(name=name, kind=kind, index=index))

        elif section_id == 8:  # Start section
            start = sec_reader.read_u32_leb128()

        elif section_id == 9:  # Element section
            count = sec_reader.read_u32_leb128()
            if count > limits.max_vector_length:
                raise DecodeError(f"Element count {count} exceeds limit", offset=sec_reader.pos)

            for _ in range(count):
                tableidx = sec_reader.read_u32_leb128()
                if tableidx != 0:
                    raise DecodeError(f"Unsupported element tableidx: {tableidx}",
                                    offset=sec_reader.pos, code="unsupported_element_form")

                offset_expr = read_expression(sec_reader)

                # Validate it's i32.const + end
                if len(offset_expr.instructions) != 2:
                    raise DecodeError("Element offset must be i32.const + end",
                                    offset=sec_reader.pos, code="unsupported_element_form")
                if offset_expr.instructions[0].opcode != 0x41:
                    raise DecodeError("Element offset must be i32.const + end",
                                    offset=sec_reader.pos, code="unsupported_element_form")
                if offset_expr.instructions[1].opcode != 0x0B:
                    raise DecodeError("Element offset must be i32.const + end",
                                    offset=sec_reader.pos, code="unsupported_element_form")

                init_count = sec_reader.read_u32_leb128()
                if init_count > limits.max_vector_length:
                    raise DecodeError(f"Element init count {init_count} exceeds limit", offset=sec_reader.pos)
                funcidxs = [sec_reader.read_u32_leb128() for _ in range(init_count)]

                elements.append(ElementSegment(tableidx=tableidx, offset_expr=offset_expr, funcidxs=funcidxs))

        elif section_id == 10:  # Code section
            count = sec_reader.read_u32_leb128()
            if count > limits.max_vector_length:
                raise DecodeError(f"Code count {count} exceeds limit", offset=sec_reader.pos)

            for _ in range(count):
                body_size = sec_reader.read_u32_leb128()
                if body_size > limits.max_function_body_bytes:
                    raise DecodeError(f"Function body size {body_size} exceeds limit", offset=sec_reader.pos)

                body_data = sec_reader.read_bytes(body_size)
                body_reader = BinaryReader(body_data, limits)

                # Read locals
                local_decl_count = body_reader.read_u32_leb128()
                if local_decl_count > limits.max_vector_length:
                    raise DecodeError(f"Local decl count {local_decl_count} exceeds limit", offset=body_reader.pos)

                local_decls: List[LocalDecl] = []
                total_locals = 0
                for _ in range(local_decl_count):
                    count_val = body_reader.read_u32_leb128()
                    valtype = body_reader.read_valtype()
                    local_decls.append(LocalDecl(count=count_val, valtype=valtype))
                    total_locals += count_val
                    if total_locals > limits.max_locals_per_function:
                        raise DecodeError(f"Total locals {total_locals} exceeds limit", offset=body_reader.pos)

                # Read expression
                expr = read_expression(body_reader)

                if not body_reader.at_end():
                    raise DecodeError("Trailing bytes in function body", offset=body_reader.pos,
                                    code="section_size_mismatch")

                code.append(FunctionBody(locals=local_decls, expr=expr))

        elif section_id == 11:  # Data section
            count = sec_reader.read_u32_leb128()
            if count > limits.max_vector_length:
                raise DecodeError(f"Data count {count} exceeds limit", offset=sec_reader.pos)

            for _ in range(count):
                memidx = sec_reader.read_u32_leb128()
                if memidx != 0:
                    raise DecodeError(f"Unsupported data memidx: {memidx}",
                                    offset=sec_reader.pos, code="unsupported_data_form")

                offset_expr = read_expression(sec_reader)

                # Validate it's i32.const + end
                if len(offset_expr.instructions) != 2:
                    raise DecodeError("Data offset must be i32.const + end",
                                    offset=sec_reader.pos, code="unsupported_data_form")
                if offset_expr.instructions[0].opcode != 0x41:
                    raise DecodeError("Data offset must be i32.const + end",
                                    offset=sec_reader.pos, code="unsupported_data_form")
                if offset_expr.instructions[1].opcode != 0x0B:
                    raise DecodeError("Data offset must be i32.const + end",
                                    offset=sec_reader.pos, code="unsupported_data_form")

                data_len = sec_reader.read_u32_leb128()
                data_bytes = sec_reader.read_bytes(data_len)

                data_segs.append(DataSegment(memidx=memidx, offset_expr=offset_expr, data=data_bytes))

        elif section_id == 12:  # Data count section
            data_count = sec_reader.read_u32_leb128()

        else:
            raise DecodeError(f"Unknown section id: {section_id}", offset=reader.pos)

        # Check that we consumed exactly the section
        if not sec_reader.at_end():
            raise DecodeError(f"Section {section_id} has leftover bytes", offset=sec_reader.pos,
                            code="section_size_mismatch")

        reader.pos = section_end

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
        data=data_segs,
        data_count=data_count,
        customs=customs
    )


def read_limits(reader: BinaryReader) -> Union[TableLimits, MemoryLimits]:
    """Read table or memory limits."""
    flags = reader.read_byte()

    if flags == 0x00:
        min_val = reader.read_u32_leb128()
        return TableLimits(min=min_val, max=None)
    elif flags == 0x01:
        min_val = reader.read_u32_leb128()
        max_val = reader.read_u32_leb128()
        return TableLimits(min=min_val, max=max_val)
    else:
        raise DecodeError(f"Invalid limits flag: 0x{flags:02x}", offset=reader.pos, code="bad_limits_flag")


def read_expression(reader: BinaryReader) -> Expression:
    """Read an expression (sequence of instructions ending with 0x0B)."""
    instructions: List[Instruction] = []

    while True:
        opcode = reader.read_byte()

        if opcode == 0x0B:  # end
            instructions.append(Instruction(opcode=0x0B))
            break
        elif opcode == 0x41:  # i32.const
            imm = reader.read_s32_leb128()
            instructions.append(Instruction(opcode=0x41, immediate=imm))
        elif opcode == 0x20:  # local.get
            imm = reader.read_u32_leb128()
            instructions.append(Instruction(opcode=0x20, immediate=imm))
        elif opcode == 0x21:  # local.set
            imm = reader.read_u32_leb128()
            instructions.append(Instruction(opcode=0x21, immediate=imm))
        elif opcode == 0x6A:  # i32.add
            instructions.append(Instruction(opcode=0x6A))
        elif opcode == 0x10:  # call
            imm = reader.read_u32_leb128()
            instructions.append(Instruction(opcode=0x10, immediate=imm))
        else:
            raise DecodeError(f"Unsupported opcode: 0x{opcode:02x}", offset=reader.pos,
                            code="unsupported_opcode")

    return Expression(instructions=instructions)


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
    imported_mems = sum(1 for imp in module.imports if isinstance(imp, ImportMemory))
    imported_globals = sum(1 for imp in module.imports if isinstance(imp, ImportGlobal))

    funcs_total = imported_funcs + len(module.function_typeidxs)
    tables_total = imported_tables + len(module.tables)
    mems_total = imported_mems + len(module.memories)
    globals_total = imported_globals + len(module.globals)

    # Validate limits
    for table in module.tables:
        if table.limits.max is not None and table.limits.min > table.limits.max:
            errors.append(ValidationError(code="limits_min_gt_max",
                                         message=f"Table limits min {table.limits.min} > max {table.limits.max}"))

    for imp in module.imports:
        if isinstance(imp, ImportTable):
            if imp.limits.max is not None and imp.limits.min > imp.limits.max:
                errors.append(ValidationError(code="limits_min_gt_max",
                                             message=f"Import table limits min {imp.limits.min} > max {imp.limits.max}"))
        elif isinstance(imp, ImportMemory):
            if imp.limits.max is not None and imp.limits.min > imp.limits.max:
                errors.append(ValidationError(code="limits_min_gt_max",
                                             message=f"Import memory limits min {imp.limits.min} > max {imp.limits.max}"))

    for mem in module.memories:
        if mem.limits.max is not None and mem.limits.min > mem.limits.max:
            errors.append(ValidationError(code="limits_min_gt_max",
                                         message=f"Memory limits min {mem.limits.min} > max {mem.limits.max}"))

    # Validate import function type indices
    for imp in module.imports:
        if isinstance(imp, ImportFunc):
            if imp.typeidx >= len(module.types):
                errors.append(ValidationError(code="type_index_out_of_range",
                                             message=f"Import func typeidx {imp.typeidx} >= {len(module.types)}"))

    # Validate function type indices
    for idx, typeidx in enumerate(module.function_typeidxs):
        if typeidx >= len(module.types):
            errors.append(ValidationError(code="type_index_out_of_range",
                                         message=f"Function {idx} typeidx {typeidx} >= {len(module.types)}"))

    # Validate export names are unique
    export_names = [exp.name for exp in module.exports]
    seen_names = set()
    for name in export_names:
        if name in seen_names:
            errors.append(ValidationError(code="duplicate_export_name",
                                         message=f"Duplicate export name: {name.hex()}"))
        seen_names.add(name)

    # Validate export indices
    for exp in module.exports:
        if exp.kind == 0:  # func
            if exp.index >= funcs_total:
                errors.append(ValidationError(code="index_out_of_range",
                                             message=f"Export func index {exp.index} >= {funcs_total}"))
        elif exp.kind == 1:  # table
            if exp.index >= tables_total:
                errors.append(ValidationError(code="index_out_of_range",
                                             message=f"Export table index {exp.index} >= {tables_total}"))
        elif exp.kind == 2:  # memory
            if exp.index >= mems_total:
                errors.append(ValidationError(code="index_out_of_range",
                                             message=f"Export memory index {exp.index} >= {mems_total}"))
        elif exp.kind == 3:  # global
            if exp.index >= globals_total:
                errors.append(ValidationError(code="index_out_of_range",
                                             message=f"Export global index {exp.index} >= {globals_total}"))

    # Validate start function
    if module.start is not None:
        if module.start >= funcs_total:
            errors.append(ValidationError(code="index_out_of_range",
                                         message=f"Start funcidx {module.start} >= {funcs_total}"))
        else:
            # Get the type of the start function
            if module.start < imported_funcs:
                # It's an imported function
                func_imp = [imp for imp in module.imports if isinstance(imp, ImportFunc)][module.start]
                if func_imp.typeidx < len(module.types):
                    func_type = module.types[func_imp.typeidx]
                    if func_type.params or func_type.results:
                        errors.append(ValidationError(code="bad_start_signature",
                                                     message=f"Start function must have type [] -> []"))
            else:
                # It's a defined function
                def_idx = module.start - imported_funcs
                if def_idx < len(module.function_typeidxs):
                    typeidx = module.function_typeidxs[def_idx]
                    if typeidx < len(module.types):
                        func_type = module.types[typeidx]
                        if func_type.params or func_type.results:
                            errors.append(ValidationError(code="bad_start_signature",
                                                         message=f"Start function must have type [] -> []"))

    # Validate code count matches function count
    if len(module.code) != len(module.function_typeidxs):
        errors.append(ValidationError(code="func_code_count_mismatch",
                                     message=f"Code count {len(module.code)} != function count {len(module.function_typeidxs)}"))

    # Validate element segments
    for elem in module.elements:
        for funcidx in elem.funcidxs:
            if funcidx >= funcs_total:
                errors.append(ValidationError(code="index_out_of_range",
                                             message=f"Element funcidx {funcidx} >= {funcs_total}"))

    # Validate data count
    if module.data_count is not None:
        if module.data_count != len(module.data):
            errors.append(ValidationError(code="data_count_mismatch",
                                         message=f"Data count {module.data_count} != actual data segments {len(module.data)}"))

    # Validate function bodies
    for func_idx, body in enumerate(module.code):
        # Get the function type
        if func_idx < len(module.function_typeidxs):
            typeidx = module.function_typeidxs[func_idx]
            if typeidx < len(module.types):
                func_type = module.types[typeidx]
                num_params = len(func_type.params)

                # Calculate total locals
                num_locals = sum(decl.count for decl in body.locals)
                total_locals = num_params + num_locals

                # Validate local indices in instructions
                for instr in body.expr.instructions:
                    if instr.opcode in (0x20, 0x21):  # local.get, local.set
                        if instr.immediate is not None and instr.immediate >= total_locals:
                            errors.append(ValidationError(code="local_index_out_of_range",
                                                         message=f"Function {func_idx} local index {instr.immediate} >= {total_locals}"))
                    elif instr.opcode == 0x10:  # call
                        if instr.immediate is not None and instr.immediate >= funcs_total:
                            errors.append(ValidationError(code="index_out_of_range",
                                                         message=f"Function {func_idx} call index {instr.immediate} >= {funcs_total}"))

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

