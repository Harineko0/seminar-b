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
class ValType:
    """Value type (i32 or i64)."""
    kind: str  # "i32" or "i64"


@dataclass(frozen=True)
class FuncType:
    """Function type: params -> results."""
    params: List[ValType]
    results: List[ValType]


@dataclass(frozen=True)
class TableLimits:
    """Table or memory limits."""
    min: int
    max: Optional[int] = None


@dataclass(frozen=True)
class TableType:
    """Table type (only funcref supported)."""
    elemtype: str  # "funcref"
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
class ImportDesc:
    """Import descriptor."""
    kind: str  # "func", "table", "mem", "global"
    typeidx: Optional[int] = None
    table_type: Optional[TableType] = None
    mem_type: Optional[MemoryType] = None
    global_type: Optional[GlobalType] = None


@dataclass(frozen=True)
class Import:
    """Import entry."""
    module: str
    name: str
    desc: ImportDesc


@dataclass(frozen=True)
class Instruction:
    """Single instruction."""
    opcode: int
    immediate: Optional[int] = None


@dataclass(frozen=True)
class Expression:
    """Expression (list of instructions)."""
    instructions: List[Instruction]


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
class Global:
    """Global entry."""
    type: GlobalType
    init: Expression


@dataclass(frozen=True)
class Export:
    """Export entry."""
    name: str
    kind: int  # 0=func, 1=table, 2=mem, 3=global
    index: int


@dataclass(frozen=True)
class ElementSegment:
    """Element segment (active only)."""
    tableidx: int
    offset: Expression
    init: List[int]  # funcidx list


@dataclass(frozen=True)
class DataSegment:
    """Data segment (active only)."""
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
    Decoded WASM module AST.
    """
    raw_size: int
    types: List[FuncType]
    imports: List[Import]
    functions: List[int]  # typeidx list
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
# Internal decoder implementation
# ----------------------------

class _Decoder:
    """Internal WASM binary decoder."""

    def __init__(self, data: bytes, limits: Limits):
        self.data = data
        self.limits = limits
        self.pos = 0

    def decode(self) -> Module:
        """Decode the entire module."""
        raw_size = len(self.data)

        # Check magic and version
        self._check_magic()
        self._check_version()

        # Initialize fields
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
        data: List[DataSegment] = []
        data_count: Optional[int] = None
        customs: List[CustomSection] = []

        # Track section order (non-custom sections)
        last_section_id = -1

        # Parse sections
        while self.pos < len(self.data):
            section_id = self._read_byte()
            payload_len = self._read_u32()

            # Check section size limit
            if section_id == 0:  # Custom section
                if payload_len > self.limits.max_custom_section_bytes:
                    raise DecodeError(f"Custom section too large: {payload_len}", offset=self.pos, code="section_too_large")
            else:
                if payload_len > self.limits.max_section_bytes:
                    raise DecodeError(f"Section too large: {payload_len}", offset=self.pos, code="section_too_large")

            # Check section ordering (non-custom only)
            if section_id != 0:
                if section_id <= last_section_id:
                    raise DecodeError(f"Section out of order: {section_id} after {last_section_id}", offset=self.pos, code="section_order")
                last_section_id = section_id

            payload_start = self.pos
            payload_end = self.pos + payload_len

            if payload_end > len(self.data):
                raise DecodeError("Section payload exceeds module bounds", offset=self.pos, code="truncated")

            # Parse section by ID
            if section_id == 0:  # Custom
                customs.append(self._decode_custom_section(payload_end))
            elif section_id == 1:  # Type
                types = self._decode_type_section(payload_end)
            elif section_id == 2:  # Import
                imports = self._decode_import_section(payload_end)
            elif section_id == 3:  # Function
                functions = self._decode_function_section(payload_end)
            elif section_id == 4:  # Table
                tables = self._decode_table_section(payload_end)
            elif section_id == 5:  # Memory
                memories = self._decode_memory_section(payload_end)
            elif section_id == 6:  # Global
                globals = self._decode_global_section(payload_end)
            elif section_id == 7:  # Export
                exports = self._decode_export_section(payload_end)
            elif section_id == 8:  # Start
                start = self._decode_start_section(payload_end)
            elif section_id == 9:  # Element
                elements = self._decode_element_section(payload_end)
            elif section_id == 10:  # Code
                code = self._decode_code_section(payload_end)
            elif section_id == 11:  # Data
                data = self._decode_data_section(payload_end)
            elif section_id == 12:  # Data count
                data_count = self._decode_data_count_section(payload_end)
            else:
                raise DecodeError(f"Unknown section ID: {section_id}", offset=self.pos, code="unknown_section")

            # Check exact payload consumption
            if self.pos != payload_end:
                raise DecodeError(f"Section payload size mismatch", offset=self.pos, code="section_size_mismatch")

        return Module(
            raw_size=raw_size,
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
            data=data,
            data_count=data_count,
            customs=customs
        )

    def _check_magic(self):
        """Check WASM magic number."""
        if len(self.data) < 4:
            raise DecodeError("Truncated magic number", offset=self.pos, code="truncated")
        magic = self._read_bytes(4)
        if magic != b"\x00asm":
            raise DecodeError(f"Invalid magic number", offset=0, code="bad_magic")

    def _check_version(self):
        """Check WASM version."""
        if len(self.data) < 8:
            raise DecodeError("Truncated version", offset=self.pos, code="truncated")
        version = self._read_bytes(4)
        if version != b"\x01\x00\x00\x00":
            raise DecodeError(f"Invalid version", offset=4, code="bad_version")

    def _read_byte(self) -> int:
        """Read a single byte."""
        if self.pos >= len(self.data):
            raise DecodeError("Unexpected end of data", offset=self.pos, code="truncated")
        byte = self.data[self.pos]
        self.pos += 1
        return byte

    def _read_bytes(self, n: int) -> bytes:
        """Read n bytes."""
        if self.pos + n > len(self.data):
            raise DecodeError("Unexpected end of data", offset=self.pos, code="truncated")
        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result

    def _read_u32(self) -> int:
        """Read unsigned LEB128 u32."""
        result = 0
        shift = 0
        while True:
            if self.pos >= len(self.data):
                raise DecodeError("Truncated LEB128", offset=self.pos, code="truncated")
            byte = self.data[self.pos]
            self.pos += 1

            result |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
            if shift >= 35:  # More than 5 bytes for u32
                raise DecodeError("LEB128 too long for u32", offset=self.pos, code="bad_leb128")

        if result > 0xFFFFFFFF:
            raise DecodeError("LEB128 value exceeds u32", offset=self.pos, code="bad_leb128")

        return result

    def _read_s32(self) -> int:
        """Read signed LEB128 s32."""
        result = 0
        shift = 0
        byte = 0
        while True:
            if self.pos >= len(self.data):
                raise DecodeError("Truncated LEB128", offset=self.pos, code="truncated")
            byte = self.data[self.pos]
            self.pos += 1

            result |= (byte & 0x7F) << shift
            shift += 7
            if (byte & 0x80) == 0:
                break
            if shift >= 35:
                raise DecodeError("LEB128 too long for s32", offset=self.pos, code="bad_leb128")

        # Sign extend
        if shift < 32 and (byte & 0x40):
            result |= -(1 << shift)

        # Check range
        if result < -2147483648 or result > 2147483647:
            raise DecodeError("LEB128 value exceeds s32 range", offset=self.pos, code="bad_leb128")

        return result

    def _read_name(self) -> str:
        """Read a name (opaque bytes, treated as UTF-8 for convenience)."""
        length = self._read_u32()
        name_bytes = self._read_bytes(length)
        # Treat as opaque bytes but decode as UTF-8 for convenience
        try:
            return name_bytes.decode('utf-8')
        except UnicodeDecodeError:
            # If not valid UTF-8, use latin-1 as fallback
            return name_bytes.decode('latin-1')

    def _read_valtype(self) -> ValType:
        """Read a value type."""
        byte = self._read_byte()
        if byte == 0x7F:
            return ValType("i32")
        elif byte == 0x7E:
            return ValType("i64")
        else:
            raise DecodeError(f"Unsupported valtype: 0x{byte:02x}", offset=self.pos-1, code="unsupported_valtype")

    def _read_limits(self) -> TableLimits:
        """Read limits."""
        flags = self._read_byte()
        if flags == 0x00:
            min_val = self._read_u32()
            return TableLimits(min=min_val, max=None)
        elif flags == 0x01:
            min_val = self._read_u32()
            max_val = self._read_u32()
            return TableLimits(min=min_val, max=max_val)
        else:
            raise DecodeError(f"Invalid limits flags: 0x{flags:02x}", offset=self.pos-1, code="bad_limits_flag")

    def _read_vector(self, reader_func):
        """Read a vector of items."""
        count = self._read_u32()
        if count > self.limits.max_vector_length:
            raise DecodeError(f"Vector too long: {count}", offset=self.pos, code="vector_too_long")
        items = []
        for _ in range(count):
            items.append(reader_func())
        return items

    def _decode_custom_section(self, payload_end: int) -> CustomSection:
        """Decode custom section."""
        name = self._read_name()
        data = self._read_bytes(payload_end - self.pos)
        return CustomSection(name=name, data=data)

    def _decode_type_section(self, payload_end: int) -> List[FuncType]:
        """Decode type section."""
        return self._read_vector(self._read_functype)

    def _read_functype(self) -> FuncType:
        """Read a function type."""
        tag = self._read_byte()
        if tag != 0x60:
            raise DecodeError(f"Invalid functype tag: 0x{tag:02x}", offset=self.pos-1, code="bad_functype_tag")
        params = self._read_vector(self._read_valtype)
        results = self._read_vector(self._read_valtype)
        return FuncType(params=params, results=results)

    def _decode_import_section(self, payload_end: int) -> List[Import]:
        """Decode import section."""
        return self._read_vector(self._read_import)

    def _read_import(self) -> Import:
        """Read an import."""
        module = self._read_name()
        name = self._read_name()
        kind = self._read_byte()

        if kind == 0:  # func
            typeidx = self._read_u32()
            desc = ImportDesc(kind="func", typeidx=typeidx)
        elif kind == 1:  # table
            elemtype = self._read_byte()
            if elemtype != 0x70:
                raise DecodeError(f"Unsupported table elemtype: 0x{elemtype:02x}", offset=self.pos-1, code="unsupported_table_elemtype")
            limits = self._read_limits()
            desc = ImportDesc(kind="table", table_type=TableType(elemtype="funcref", limits=limits))
        elif kind == 2:  # mem
            limits = self._read_limits()
            desc = ImportDesc(kind="mem", mem_type=MemoryType(limits=limits))
        elif kind == 3:  # global
            valtype = self._read_valtype()
            mut_byte = self._read_byte()
            if mut_byte == 0x00:
                mutable = False
            elif mut_byte == 0x01:
                mutable = True
            else:
                raise DecodeError(f"Invalid mutability: 0x{mut_byte:02x}", offset=self.pos-1, code="bad_mutability")
            desc = ImportDesc(kind="global", global_type=GlobalType(valtype=valtype, mutable=mutable))
        else:
            raise DecodeError(f"Invalid import kind: {kind}", offset=self.pos-1, code="bad_import_kind")

        return Import(module=module, name=name, desc=desc)

    def _decode_function_section(self, payload_end: int) -> List[int]:
        """Decode function section."""
        return self._read_vector(self._read_u32)

    def _decode_table_section(self, payload_end: int) -> List[TableType]:
        """Decode table section."""
        return self._read_vector(self._read_tabletype)

    def _read_tabletype(self) -> TableType:
        """Read a table type."""
        elemtype = self._read_byte()
        if elemtype != 0x70:
            raise DecodeError(f"Unsupported table elemtype: 0x{elemtype:02x}", offset=self.pos-1, code="unsupported_table_elemtype")
        limits = self._read_limits()
        return TableType(elemtype="funcref", limits=limits)

    def _decode_memory_section(self, payload_end: int) -> List[MemoryType]:
        """Decode memory section."""
        return self._read_vector(self._read_memtype)

    def _read_memtype(self) -> MemoryType:
        """Read a memory type."""
        limits = self._read_limits()
        return MemoryType(limits=limits)

    def _decode_global_section(self, payload_end: int) -> List[Global]:
        """Decode global section."""
        return self._read_vector(self._read_global)

    def _read_global(self) -> Global:
        """Read a global."""
        valtype = self._read_valtype()
        mut_byte = self._read_byte()
        if mut_byte == 0x00:
            mutable = False
        elif mut_byte == 0x01:
            mutable = True
        else:
            raise DecodeError(f"Invalid mutability: 0x{mut_byte:02x}", offset=self.pos-1, code="bad_mutability")

        init_expr = self._read_expr()
        return Global(type=GlobalType(valtype=valtype, mutable=mutable), init=init_expr)

    def _decode_export_section(self, payload_end: int) -> List[Export]:
        """Decode export section."""
        return self._read_vector(self._read_export)

    def _read_export(self) -> Export:
        """Read an export."""
        name = self._read_name()
        kind = self._read_byte()
        index = self._read_u32()
        return Export(name=name, kind=kind, index=index)

    def _decode_start_section(self, payload_end: int) -> int:
        """Decode start section."""
        return self._read_u32()

    def _decode_element_section(self, payload_end: int) -> List[ElementSegment]:
        """Decode element section."""
        return self._read_vector(self._read_element)

    def _read_element(self) -> ElementSegment:
        """Read an element segment (only active mode supported)."""
        tableidx = self._read_u32()
        if tableidx != 0:
            raise DecodeError(f"Unsupported element tableidx: {tableidx}", offset=self.pos, code="unsupported_element_form")

        # Read offset expression
        offset_expr = self._read_const_expr()

        # Read function indices
        init = self._read_vector(self._read_u32)

        return ElementSegment(tableidx=tableidx, offset=offset_expr, init=init)

    def _decode_code_section(self, payload_end: int) -> List[FuncBody]:
        """Decode code section."""
        return self._read_vector(self._read_funcbody)

    def _read_funcbody(self) -> FuncBody:
        """Read a function body."""
        body_size = self._read_u32()
        if body_size > self.limits.max_function_body_bytes:
            raise DecodeError(f"Function body too large: {body_size}", offset=self.pos, code="func_body_too_large")

        body_end = self.pos + body_size

        # Read locals
        locals = self._read_vector(self._read_local_decl)

        # Check total locals count
        total_locals = sum(decl.count for decl in locals)
        if total_locals > self.limits.max_locals_per_function:
            raise DecodeError(f"Too many locals: {total_locals}", offset=self.pos, code="too_many_locals")

        # Read expression
        expr = self._read_expr()

        if self.pos != body_end:
            raise DecodeError("Function body size mismatch", offset=self.pos, code="func_body_size_mismatch")

        return FuncBody(locals=locals, expr=expr)

    def _read_local_decl(self) -> LocalDecl:
        """Read a local declaration."""
        count = self._read_u32()
        valtype = self._read_valtype()
        return LocalDecl(count=count, valtype=valtype)

    def _decode_data_section(self, payload_end: int) -> List[DataSegment]:
        """Decode data section."""
        return self._read_vector(self._read_data)

    def _read_data(self) -> DataSegment:
        """Read a data segment (only active mode supported)."""
        memidx = self._read_u32()
        if memidx != 0:
            raise DecodeError(f"Unsupported data memidx: {memidx}", offset=self.pos, code="unsupported_data_form")

        # Read offset expression
        offset_expr = self._read_const_expr()

        # Read data bytes
        length = self._read_u32()
        data = self._read_bytes(length)

        return DataSegment(memidx=memidx, offset=offset_expr, data=data)

    def _decode_data_count_section(self, payload_end: int) -> int:
        """Decode data count section."""
        return self._read_u32()

    def _read_expr(self) -> Expression:
        """Read an expression."""
        instructions = []
        while True:
            opcode = self._read_byte()

            if opcode == 0x0B:  # end
                instructions.append(Instruction(opcode=opcode))
                break
            elif opcode == 0x41:  # i32.const
                immediate = self._read_s32()
                instructions.append(Instruction(opcode=opcode, immediate=immediate))
            elif opcode == 0x20:  # local.get
                immediate = self._read_u32()
                instructions.append(Instruction(opcode=opcode, immediate=immediate))
            elif opcode == 0x21:  # local.set
                immediate = self._read_u32()
                instructions.append(Instruction(opcode=opcode, immediate=immediate))
            elif opcode == 0x6A:  # i32.add
                instructions.append(Instruction(opcode=opcode))
            elif opcode == 0x10:  # call
                immediate = self._read_u32()
                instructions.append(Instruction(opcode=opcode, immediate=immediate))
            else:
                raise DecodeError(f"Unsupported opcode: 0x{opcode:02x}", offset=self.pos-1, code="unsupported_opcode")

        return Expression(instructions=instructions)

    def _read_const_expr(self) -> Expression:
        """Read a const expression (must be i32.const followed by end)."""
        opcode = self._read_byte()
        if opcode != 0x41:  # i32.const
            raise DecodeError(f"Expected i32.const in const expr, got 0x{opcode:02x}", offset=self.pos-1, code="unsupported_element_form")

        immediate = self._read_s32()

        end_opcode = self._read_byte()
        if end_opcode != 0x0B:  # end
            raise DecodeError(f"Expected end in const expr, got 0x{end_opcode:02x}", offset=self.pos-1, code="unsupported_element_form")

        return Expression(instructions=[
            Instruction(opcode=0x41, immediate=immediate),
            Instruction(opcode=0x0B)
        ])


# ----------------------------
# Public API functions
# ----------------------------

def decode_module(data: bytes, *, limits: Limits = Limits()) -> Module:
    """
    Decode a WASM binary module (subset) into a Module AST.

    Raises:
        DecodeError: on malformed input or unsupported forms.
    """
    # Check module size limit
    if len(data) > limits.max_module_bytes:
        raise DecodeError(f"Module too large: {len(data)} > {limits.max_module_bytes}", code="module_too_large")

    decoder = _Decoder(data, limits)
    return decoder.decode()


def validate_module(module: Module) -> List[ValidationError]:
    """
    Perform structural validation on a decoded module.

    Returns:
        List[ValidationError]: empty if valid.
    """
    errors: List[ValidationError] = []

    # Calculate index spaces
    imported_funcs = sum(1 for imp in module.imports if imp.desc.kind == "func")
    imported_tables = sum(1 for imp in module.imports if imp.desc.kind == "table")
    imported_mems = sum(1 for imp in module.imports if imp.desc.kind == "mem")
    imported_globals = sum(1 for imp in module.imports if imp.desc.kind == "global")

    funcs_total = imported_funcs + len(module.functions)
    tables_total = imported_tables + len(module.tables)
    mems_total = imported_mems + len(module.memories)
    globals_total = imported_globals + len(module.globals)

    # Validate limits (min <= max)
    for i, table in enumerate(module.tables):
        if table.limits.max is not None and table.limits.min > table.limits.max:
            errors.append(ValidationError(
                code="limits_min_gt_max",
                message=f"Table {i}: min ({table.limits.min}) > max ({table.limits.max})"
            ))

    for i, mem in enumerate(module.memories):
        if mem.limits.max is not None and mem.limits.min > mem.limits.max:
            errors.append(ValidationError(
                code="limits_min_gt_max",
                message=f"Memory {i}: min ({mem.limits.min}) > max ({mem.limits.max})"
            ))

    # Check imported table limits
    for i, imp in enumerate(module.imports):
        if imp.desc.kind == "table" and imp.desc.table_type:
            if imp.desc.table_type.limits.max is not None and imp.desc.table_type.limits.min > imp.desc.table_type.limits.max:
                errors.append(ValidationError(
                    code="limits_min_gt_max",
                    message=f"Imported table {i}: min > max"
                ))
        elif imp.desc.kind == "mem" and imp.desc.mem_type:
            if imp.desc.mem_type.limits.max is not None and imp.desc.mem_type.limits.min > imp.desc.mem_type.limits.max:
                errors.append(ValidationError(
                    code="limits_min_gt_max",
                    message=f"Imported memory {i}: min > max"
                ))

    # Validate type indices in function section
    for i, typeidx in enumerate(module.functions):
        if typeidx >= len(module.types):
            errors.append(ValidationError(
                code="type_index_out_of_range",
                message=f"Function {i}: type index {typeidx} out of range (have {len(module.types)} types)"
            ))

    # Validate type indices in imports
    for i, imp in enumerate(module.imports):
        if imp.desc.kind == "func" and imp.desc.typeidx is not None:
            if imp.desc.typeidx >= len(module.types):
                errors.append(ValidationError(
                    code="type_index_out_of_range",
                    message=f"Import {i}: type index {imp.desc.typeidx} out of range"
                ))

    # Validate function/code count match
    if len(module.code) != len(module.functions):
        errors.append(ValidationError(
            code="func_code_count_mismatch",
            message=f"Function count ({len(module.functions)}) != code count ({len(module.code)})"
        ))

    # Validate exports
    export_names = set()
    for i, export in enumerate(module.exports):
        # Check for duplicate names
        if export.name in export_names:
            errors.append(ValidationError(
                code="duplicate_export_name",
                message=f"Duplicate export name: {export.name}"
            ))
        export_names.add(export.name)

        # Validate index
        if export.kind == 0:  # func
            if export.index >= funcs_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export '{export.name}': funcidx {export.index} out of range (have {funcs_total} funcs)"
                ))
        elif export.kind == 1:  # table
            if export.index >= tables_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export '{export.name}': tableidx {export.index} out of range"
                ))
        elif export.kind == 2:  # mem
            if export.index >= mems_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export '{export.name}': memidx {export.index} out of range"
                ))
        elif export.kind == 3:  # global
            if export.index >= globals_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Export '{export.name}': globalidx {export.index} out of range"
                ))

    # Validate start function
    if module.start is not None:
        if module.start >= funcs_total:
            errors.append(ValidationError(
                code="index_out_of_range",
                message=f"Start funcidx {module.start} out of range (have {funcs_total} funcs)"
            ))
        else:
            # Check start function signature
            start_typeidx = _get_func_typeidx(module, module.start, imported_funcs)
            if start_typeidx is not None and start_typeidx < len(module.types):
                start_type = module.types[start_typeidx]
                if len(start_type.params) != 0 or len(start_type.results) != 0:
                    errors.append(ValidationError(
                        code="bad_start_signature",
                        message=f"Start function has invalid signature: must have type [] -> [], got {len(start_type.params)} params, {len(start_type.results)} results"
                    ))

    # Validate element segments
    for i, elem in enumerate(module.elements):
        for j, funcidx in enumerate(elem.init):
            if funcidx >= funcs_total:
                errors.append(ValidationError(
                    code="index_out_of_range",
                    message=f"Element segment {i}, init[{j}]: funcidx {funcidx} out of range"
                ))

    # Validate code bodies
    for i, (funcbody, typeidx) in enumerate(zip(module.code, module.functions)):
        if typeidx < len(module.types):
            functype = module.types[typeidx]
            num_params = len(functype.params)
            num_locals = sum(decl.count for decl in funcbody.locals)
            total_locals = num_params + num_locals

            # Validate local indices in instructions
            for instr in funcbody.expr.instructions:
                if instr.opcode in [0x20, 0x21]:  # local.get, local.set
                    if instr.immediate is not None and instr.immediate >= total_locals:
                        errors.append(ValidationError(
                            code="local_index_out_of_range",
                            message=f"Function {i}: local index {instr.immediate} out of range (have {total_locals} locals)"
                        ))
                elif instr.opcode == 0x10:  # call
                    if instr.immediate is not None and instr.immediate >= funcs_total:
                        errors.append(ValidationError(
                            code="index_out_of_range",
                            message=f"Function {i}: call funcidx {instr.immediate} out of range"
                        ))

    # Validate data count
    if module.data_count is not None:
        if module.data_count != len(module.data):
            errors.append(ValidationError(
                code="data_count_mismatch",
                message=f"Data count ({module.data_count}) != actual data segments ({len(module.data)})"
            ))

    return errors


def _get_func_typeidx(module: Module, funcidx: int, imported_funcs: int) -> Optional[int]:
    """Get the type index for a function index."""
    if funcidx < imported_funcs:
        # It's an imported function
        func_count = 0
        for imp in module.imports:
            if imp.desc.kind == "func":
                if func_count == funcidx:
                    return imp.desc.typeidx
                func_count += 1
        return None
    else:
        # It's a defined function
        defined_idx = funcidx - imported_funcs
        if defined_idx < len(module.functions):
            return module.functions[defined_idx]
        return None


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

