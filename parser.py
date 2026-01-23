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
class TableLimits:
    """Limits for tables and memories."""
    min: int
    max: Optional[int] = None


@dataclass(frozen=True)
class FuncType:
    """Function type signature."""
    params: List[str]  # 'i32' or 'i64'
    results: List[str]  # 'i32' or 'i64'


@dataclass(frozen=True)
class GlobalType:
    """Global variable type."""
    valtype: str  # 'i32' or 'i64'
    mutable: bool


@dataclass(frozen=True)
class Import:
    """Import declaration."""
    module: str
    name: str
    kind: str  # 'func', 'table', 'mem', 'global'
    desc: object  # typeidx (int) or TableLimits or GlobalType


@dataclass(frozen=True)
class TableType:
    """Table type."""
    elemtype: str  # 'funcref'
    limits: TableLimits


@dataclass(frozen=True)
class MemoryType:
    """Memory type."""
    limits: TableLimits


@dataclass(frozen=True)
class Global:
    """Global variable definition."""
    type: GlobalType
    init: List[object]  # Expression instructions


@dataclass(frozen=True)
class Export:
    """Export declaration."""
    name: str
    kind: str  # 'func', 'table', 'mem', 'global'
    index: int


@dataclass(frozen=True)
class Instruction:
    """WASM instruction."""
    opcode: int
    immediate: Optional[int] = None


@dataclass(frozen=True)
class Expression:
    """Expression (sequence of instructions ending with 'end')."""
    instructions: List[Instruction]


@dataclass(frozen=True)
class LocalDecl:
    """Local variable declaration."""
    count: int
    valtype: str  # 'i32' or 'i64'


@dataclass(frozen=True)
class FuncBody:
    """Function body (locals + expression)."""
    locals: List[LocalDecl]
    expr: Expression


@dataclass(frozen=True)
class ElementSegment:
    """Element segment (active mode for table 0)."""
    tableidx: int
    offset: int  # from i32.const
    init: List[int]  # funcidx list


@dataclass(frozen=True)
class DataSegment:
    """Data segment (active mode for memory 0)."""
    memidx: int
    offset: int  # from i32.const
    data: bytes


@dataclass(frozen=True)
class CustomSection:
    """Custom section."""
    name: str
    data: bytes


@dataclass(frozen=True)
class Module:
    """Decoded WASM module AST."""
    raw_size: int
    types: List[FuncType]
    imports: List[Import]
    functions: List[int]  # typeidx list for defined functions
    tables: List[TableType]
    memories: List[MemoryType]
    globals: List[Global]
    exports: List[Export]
    start: Optional[int]  # funcidx
    elements: List[ElementSegment]
    code: List[FuncBody]
    data: List[DataSegment]
    data_count: Optional[int]
    customs: List[CustomSection]


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
        raise DecodeError(f"Module size {len(data)} exceeds limit {limits.max_module_bytes}", code="module_too_large")

    decoder = _Decoder(data, limits)
    return decoder.decode()


def validate_module(module: Module) -> List[ValidationError]:
    """
    Perform structural validation on a decoded module.

    Returns:
        List[ValidationError]: empty if valid.
    """
    validator = _Validator(module)
    return validator.validate()


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


# ----------------------------
# Internal decoder
# ----------------------------

class _Decoder:
    """Internal decoder for WASM binary format."""

    def __init__(self, data: bytes, limits: Limits):
        self.data = data
        self.limits = limits
        self.pos = 0
        self.raw_size = len(data)

    def decode(self) -> Module:
        """Main decode entry point."""
        # Check preamble
        self._check_magic()
        self._check_version()

        # Initialize section data
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

        # Track last non-custom section for ordering
        last_section_id = -1

        # Parse sections
        while self.pos < len(self.data):
            section_id = self._read_byte()
            payload_len = self._read_u32()

            if payload_len > self.limits.max_section_bytes:
                if section_id != 0 or payload_len > self.limits.max_custom_section_bytes:
                    raise DecodeError(f"Section payload too large: {payload_len}", code="section_too_large")

            section_start = self.pos
            section_end = self.pos + payload_len

            if section_end > len(self.data):
                raise DecodeError("Section extends beyond module", code="truncated_section")

            # Custom sections can appear anywhere
            if section_id == 0:
                customs.append(self._decode_custom_section(payload_len))
            else:
                # Check ordering for non-custom sections
                if section_id <= last_section_id:
                    raise DecodeError(f"Section {section_id} out of order", code="section_order")
                last_section_id = section_id

                if section_id == 1:
                    types = self._decode_type_section()
                elif section_id == 2:
                    imports = self._decode_import_section()
                elif section_id == 3:
                    functions = self._decode_function_section()
                elif section_id == 4:
                    tables = self._decode_table_section()
                elif section_id == 5:
                    memories = self._decode_memory_section()
                elif section_id == 6:
                    globals = self._decode_global_section()
                elif section_id == 7:
                    exports = self._decode_export_section()
                elif section_id == 8:
                    start = self._decode_start_section()
                elif section_id == 9:
                    elements = self._decode_element_section()
                elif section_id == 10:
                    code = self._decode_code_section()
                elif section_id == 11:
                    data = self._decode_data_section()
                elif section_id == 12:
                    data_count = self._decode_data_count_section()
                else:
                    raise DecodeError(f"Unsupported section ID: {section_id}", code="unknown_section_id")

            # Verify exact payload consumption
            if self.pos != section_end:
                raise DecodeError(f"Section {section_id} size mismatch", code="section_size_mismatch")

        return Module(
            raw_size=self.raw_size,
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
        """Check magic number."""
        if self.pos + 4 > len(self.data):
            raise DecodeError("Truncated magic number", code="truncated_magic")
        magic = self.data[self.pos:self.pos + 4]
        if magic != b"\x00asm":
            raise DecodeError(f"Invalid magic number: {magic.hex()}", code="invalid_magic")
        self.pos += 4

    def _check_version(self):
        """Check version."""
        if self.pos + 4 > len(self.data):
            raise DecodeError("Truncated version", code="truncated_version")
        version = self.data[self.pos:self.pos + 4]
        if version != b"\x01\x00\x00\x00":
            raise DecodeError(f"Invalid version: {version.hex()}", code="invalid_version")
        self.pos += 4

    def _read_byte(self) -> int:
        """Read single byte."""
        if self.pos >= len(self.data):
            raise DecodeError("Unexpected end of data", code="truncated")
        b = self.data[self.pos]
        self.pos += 1
        return b

    def _read_u32(self) -> int:
        """Read unsigned LEB128 u32."""
        result = 0
        shift = 0
        for i in range(5):  # Max 5 bytes for u32
            if self.pos >= len(self.data):
                raise DecodeError("Truncated LEB128", code="truncated_leb128")
            byte = self.data[self.pos]
            self.pos += 1
            result |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                # Check for overlong encoding
                if i == 4 and (byte & 0xF0) != 0:
                    raise DecodeError("LEB128 overflow", code="leb128_overflow")
                if result > 0xFFFFFFFF:
                    raise DecodeError("LEB128 exceeds u32", code="leb128_overflow")
                return result
            shift += 7
        raise DecodeError("LEB128 too long for u32", code="leb128_overflow")

    def _read_s32(self) -> int:
        """Read signed LEB128 s32."""
        result = 0
        shift = 0
        for i in range(5):  # Max 5 bytes for s32
            if self.pos >= len(self.data):
                raise DecodeError("Truncated LEB128", code="truncated_leb128")
            byte = self.data[self.pos]
            self.pos += 1
            result |= (byte & 0x7F) << shift
            shift += 7
            if (byte & 0x80) == 0:
                # Sign extend
                if shift < 32 and (byte & 0x40):
                    result |= -(1 << shift)
                # Check range
                if result < -(1 << 31) or result >= (1 << 31):
                    raise DecodeError("LEB128 exceeds s32", code="leb128_overflow")
                return result
        raise DecodeError("LEB128 too long for s32", code="leb128_overflow")

    def _read_name(self) -> str:
        """Read name (length-prefixed bytes)."""
        length = self._read_u32()
        if self.pos + length > len(self.data):
            raise DecodeError("Truncated name", code="truncated_name")
        name_bytes = self.data[self.pos:self.pos + length]
        self.pos += length
        # Decode as UTF-8, treating invalid sequences as replacement characters
        try:
            return name_bytes.decode('utf-8')
        except UnicodeDecodeError:
            # Fallback to latin-1 which never fails
            return name_bytes.decode('latin-1')

    def _read_vector(self, item_reader):
        """Read vector of items."""
        count = self._read_u32()
        if count > self.limits.max_vector_length:
            raise DecodeError(f"Vector length {count} exceeds limit", code="vector_too_long")
        items = []
        for _ in range(count):
            items.append(item_reader())
        return items

    def _read_valtype(self) -> str:
        """Read value type."""
        byte = self._read_byte()
        if byte == 0x7F:
            return "i32"
        elif byte == 0x7E:
            return "i64"
        else:
            raise DecodeError(f"Unsupported valtype: 0x{byte:02x}", code="unsupported_valtype")

    def _read_limits(self) -> TableLimits:
        """Read table/memory limits."""
        flags = self._read_byte()
        if flags == 0x00:
            min_val = self._read_u32()
            return TableLimits(min=min_val, max=None)
        elif flags == 0x01:
            min_val = self._read_u32()
            max_val = self._read_u32()
            return TableLimits(min=min_val, max=max_val)
        else:
            raise DecodeError(f"Invalid limits flag: 0x{flags:02x}", code="bad_limits_flag")

    def _decode_custom_section(self, payload_len: int) -> CustomSection:
        """Decode custom section."""
        section_start = self.pos
        section_end = self.pos + payload_len
        name = self._read_name()
        data = self.data[self.pos:section_end]
        self.pos = section_end
        return CustomSection(name=name, data=data)

    def _decode_type_section(self) -> List[FuncType]:
        """Decode type section."""
        def read_functype():
            tag = self._read_byte()
            if tag != 0x60:
                raise DecodeError(f"Invalid functype tag: 0x{tag:02x}", code="invalid_functype_tag")
            params = self._read_vector(self._read_valtype)
            results = self._read_vector(self._read_valtype)
            return FuncType(params=params, results=results)
        return self._read_vector(read_functype)

    def _decode_import_section(self) -> List[Import]:
        """Decode import section."""
        def read_import():
            module = self._read_name()
            name = self._read_name()
            kind_byte = self._read_byte()

            if kind_byte == 0x00:  # func
                typeidx = self._read_u32()
                return Import(module=module, name=name, kind="func", desc=typeidx)
            elif kind_byte == 0x01:  # table
                elemtype = self._read_byte()
                if elemtype != 0x70:
                    raise DecodeError(f"Unsupported table elemtype: 0x{elemtype:02x}", code="unsupported_table_elemtype")
                limits = self._read_limits()
                return Import(module=module, name=name, kind="table", desc=TableType(elemtype="funcref", limits=limits))
            elif kind_byte == 0x02:  # mem
                limits = self._read_limits()
                return Import(module=module, name=name, kind="mem", desc=MemoryType(limits=limits))
            elif kind_byte == 0x03:  # global
                valtype = self._read_valtype()
                mut = self._read_byte()
                if mut not in (0x00, 0x01):
                    raise DecodeError(f"Invalid mutability: 0x{mut:02x}", code="bad_mutability")
                return Import(module=module, name=name, kind="global", desc=GlobalType(valtype=valtype, mutable=(mut == 0x01)))
            else:
                raise DecodeError(f"Unknown import kind: 0x{kind_byte:02x}", code="unknown_import_kind")
        return self._read_vector(read_import)

    def _decode_function_section(self) -> List[int]:
        """Decode function section."""
        return self._read_vector(self._read_u32)

    def _decode_table_section(self) -> List[TableType]:
        """Decode table section."""
        def read_table():
            elemtype = self._read_byte()
            if elemtype != 0x70:
                raise DecodeError(f"Unsupported table elemtype: 0x{elemtype:02x}", code="unsupported_table_elemtype")
            limits = self._read_limits()
            return TableType(elemtype="funcref", limits=limits)
        return self._read_vector(read_table)

    def _decode_memory_section(self) -> List[MemoryType]:
        """Decode memory section."""
        def read_memory():
            limits = self._read_limits()
            return MemoryType(limits=limits)
        return self._read_vector(read_memory)

    def _decode_global_section(self) -> List[Global]:
        """Decode global section."""
        def read_global():
            valtype = self._read_valtype()
            mut = self._read_byte()
            if mut not in (0x00, 0x01):
                raise DecodeError(f"Invalid mutability: 0x{mut:02x}", code="bad_mutability")
            init_expr = self._read_expression()
            return Global(type=GlobalType(valtype=valtype, mutable=(mut == 0x01)), init=init_expr.instructions)
        return self._read_vector(read_global)

    def _decode_export_section(self) -> List[Export]:
        """Decode export section."""
        def read_export():
            name = self._read_name()
            kind_byte = self._read_byte()
            index = self._read_u32()

            kind_map = {0x00: "func", 0x01: "table", 0x02: "mem", 0x03: "global"}
            if kind_byte not in kind_map:
                raise DecodeError(f"Unknown export kind: 0x{kind_byte:02x}", code="unknown_export_kind")

            return Export(name=name, kind=kind_map[kind_byte], index=index)
        return self._read_vector(read_export)

    def _decode_start_section(self) -> int:
        """Decode start section."""
        return self._read_u32()

    def _decode_element_section(self) -> List[ElementSegment]:
        """Decode element section (restricted form only)."""
        def read_elem():
            tableidx = self._read_u32()
            if tableidx != 0:
                raise DecodeError(f"Unsupported element tableidx: {tableidx}", code="unsupported_element_form")

            # Read offset expression (must be i32.const)
            offset = self._read_const_expr()

            # Read init funcidx vector
            init = self._read_vector(self._read_u32)

            return ElementSegment(tableidx=tableidx, offset=offset, init=init)
        return self._read_vector(read_elem)

    def _decode_code_section(self) -> List[FuncBody]:
        """Decode code section."""
        def read_funcbody():
            body_size = self._read_u32()
            if body_size > self.limits.max_function_body_bytes:
                raise DecodeError(f"Function body too large: {body_size}", code="function_body_too_large")

            body_start = self.pos
            body_end = self.pos + body_size

            # Read locals
            def read_local_decl():
                count = self._read_u32()
                valtype = self._read_valtype()
                return LocalDecl(count=count, valtype=valtype)

            locals = self._read_vector(read_local_decl)

            # Check total locals count
            total_locals = sum(decl.count for decl in locals)
            if total_locals > self.limits.max_locals_per_function:
                raise DecodeError(f"Too many locals: {total_locals}", code="too_many_locals")

            # Read expression
            expr = self._read_expression()

            if self.pos != body_end:
                raise DecodeError("Function body size mismatch", code="function_body_size_mismatch")

            return FuncBody(locals=locals, expr=expr)
        return self._read_vector(read_funcbody)

    def _decode_data_section(self) -> List[DataSegment]:
        """Decode data section (restricted form only)."""
        def read_data():
            memidx = self._read_u32()
            if memidx != 0:
                raise DecodeError(f"Unsupported data memidx: {memidx}", code="unsupported_data_form")

            # Read offset expression (must be i32.const)
            offset = self._read_const_expr()

            # Read data bytes
            data_len = self._read_u32()
            if self.pos + data_len > len(self.data):
                raise DecodeError("Truncated data segment", code="truncated_data")
            data = self.data[self.pos:self.pos + data_len]
            self.pos += data_len

            return DataSegment(memidx=memidx, offset=offset, data=data)
        return self._read_vector(read_data)

    def _decode_data_count_section(self) -> int:
        """Decode data count section."""
        return self._read_u32()

    def _read_const_expr(self) -> int:
        """Read restricted const expression (i32.const + end)."""
        opcode = self._read_byte()
        if opcode != 0x41:  # i32.const
            raise DecodeError(f"Expected i32.const in offset expr, got 0x{opcode:02x}", code="unsupported_element_form" if True else "unsupported_data_form")
        value = self._read_s32()
        end = self._read_byte()
        if end != 0x0B:
            raise DecodeError("Expected end after const expr", code="missing_end")
        return value

    def _read_expression(self) -> Expression:
        """Read expression (sequence of instructions ending with end)."""
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
                localidx = self._read_u32()
                instructions.append(Instruction(opcode=opcode, immediate=localidx))
            elif opcode == 0x21:  # local.set
                localidx = self._read_u32()
                instructions.append(Instruction(opcode=opcode, immediate=localidx))
            elif opcode == 0x6A:  # i32.add
                instructions.append(Instruction(opcode=opcode))
            elif opcode == 0x10:  # call
                funcidx = self._read_u32()
                instructions.append(Instruction(opcode=opcode, immediate=funcidx))
            else:
                raise DecodeError(f"Unsupported opcode: 0x{opcode:02x}", code="unsupported_opcode")

        return Expression(instructions=instructions)


# ----------------------------
# Internal validator
# ----------------------------

class _Validator:
    """Internal validator for structural rules."""

    def __init__(self, module: Module):
        self.module = module
        self.errors: List[ValidationError] = []

    def validate(self) -> List[ValidationError]:
        """Main validation entry point."""
        # Compute index spaces
        self.imported_funcs = sum(1 for imp in self.module.imports if imp.kind == "func")
        self.imported_tables = sum(1 for imp in self.module.imports if imp.kind == "table")
        self.imported_mems = sum(1 for imp in self.module.imports if imp.kind == "mem")
        self.imported_globals = sum(1 for imp in self.module.imports if imp.kind == "global")

        self.funcs_total = self.imported_funcs + len(self.module.functions)
        self.tables_total = self.imported_tables + len(self.module.tables)
        self.mems_total = self.imported_mems + len(self.module.memories)
        self.globals_total = self.imported_globals + len(self.module.globals)

        # Run validation checks
        self._validate_limits()
        self._validate_type_indices()
        self._validate_exports()
        self._validate_start()
        self._validate_code()
        self._validate_elements()
        self._validate_data_count()

        return self.errors

    def _add_error(self, code: str, message: str, context: Optional[str] = None):
        """Add validation error."""
        self.errors.append(ValidationError(code=code, message=message, context=context))

    def _validate_limits(self):
        """Validate table/memory limits."""
        for i, table in enumerate(self.module.tables):
            if table.limits.max is not None and table.limits.min > table.limits.max:
                self._add_error("limits_min_gt_max", f"Table {i}: min ({table.limits.min}) > max ({table.limits.max})")

        for i, mem in enumerate(self.module.memories):
            if mem.limits.max is not None and mem.limits.min > mem.limits.max:
                self._add_error("limits_min_gt_max", f"Memory {i}: min ({mem.limits.min}) > max ({mem.limits.max})")

        for i, imp in enumerate(self.module.imports):
            if imp.kind == "table":
                table_type = imp.desc
                if table_type.limits.max is not None and table_type.limits.min > table_type.limits.max:
                    self._add_error("limits_min_gt_max", f"Imported table {i}: min > max")
            elif imp.kind == "mem":
                mem_type = imp.desc
                if mem_type.limits.max is not None and mem_type.limits.min > mem_type.limits.max:
                    self._add_error("limits_min_gt_max", f"Imported memory {i}: min > max")

    def _validate_type_indices(self):
        """Validate type indices in functions and imports."""
        num_types = len(self.module.types)

        # Check function type indices
        for i, typeidx in enumerate(self.module.functions):
            if typeidx >= num_types:
                self._add_error("type_index_out_of_range", f"Function {i} references invalid type index {typeidx}")

        # Check import type indices
        for i, imp in enumerate(self.module.imports):
            if imp.kind == "func":
                typeidx = imp.desc
                if typeidx >= num_types:
                    self._add_error("type_index_out_of_range", f"Imported function {i} references invalid type index {typeidx}")

    def _validate_exports(self):
        """Validate exports."""
        seen_names = set()
        for exp in self.module.exports:
            # Check duplicate names
            if exp.name in seen_names:
                self._add_error("duplicate_export_name", f"Duplicate export name: {exp.name}")
            seen_names.add(exp.name)

            # Check index ranges
            if exp.kind == "func" and exp.index >= self.funcs_total:
                self._add_error("index_out_of_range", f"Export '{exp.name}' references invalid function {exp.index}")
            elif exp.kind == "table" and exp.index >= self.tables_total:
                self._add_error("index_out_of_range", f"Export '{exp.name}' references invalid table {exp.index}")
            elif exp.kind == "mem" and exp.index >= self.mems_total:
                self._add_error("index_out_of_range", f"Export '{exp.name}' references invalid memory {exp.index}")
            elif exp.kind == "global" and exp.index >= self.globals_total:
                self._add_error("index_out_of_range", f"Export '{exp.name}' references invalid global {exp.index}")

    def _validate_start(self):
        """Validate start function."""
        if self.module.start is not None:
            funcidx = self.module.start
            if funcidx >= self.funcs_total:
                self._add_error("index_out_of_range", f"Start function {funcidx} out of range")
            else:
                # Get function type
                func_type = self._get_func_type(funcidx)
                if func_type.params or func_type.results:
                    self._add_error("bad_start_signature", f"Start function signature must be [] -> [], got {func_type.params} -> {func_type.results}")

    def _get_func_type(self, funcidx: int) -> FuncType:
        """Get function type by function index."""
        if funcidx < self.imported_funcs:
            # It's an imported function
            imp_idx = 0
            for imp in self.module.imports:
                if imp.kind == "func":
                    if imp_idx == funcidx:
                        return self.module.types[imp.desc]
                    imp_idx += 1
        else:
            # It's a defined function
            defined_idx = funcidx - self.imported_funcs
            typeidx = self.module.functions[defined_idx]
            return self.module.types[typeidx]

        # Should not reach here
        return FuncType(params=[], results=[])

    def _validate_code(self):
        """Validate code section."""
        # Check function/code count match
        if len(self.module.code) != len(self.module.functions):
            self._add_error("func_code_count_mismatch", f"Function section has {len(self.module.functions)} entries but code section has {len(self.module.code)}")
            return

        # Validate each function body
        for i, func_body in enumerate(self.module.code):
            funcidx = self.imported_funcs + i
            func_type = self._get_func_type(funcidx)

            # Calculate total locals (params + declared locals)
            num_params = len(func_type.params)
            num_locals = sum(decl.count for decl in func_body.locals)
            total_locals = num_params + num_locals

            # Validate local indices in expression
            for instr in func_body.expr.instructions:
                if instr.opcode in (0x20, 0x21):  # local.get, local.set
                    localidx = instr.immediate
                    if localidx >= total_locals:
                        self._add_error("local_index_out_of_range", f"Function {funcidx}: local index {localidx} out of range (total: {total_locals})")
                elif instr.opcode == 0x10:  # call
                    callee = instr.immediate
                    if callee >= self.funcs_total:
                        self._add_error("index_out_of_range", f"Function {funcidx}: call to invalid function {callee}")

    def _validate_elements(self):
        """Validate element segments."""
        for i, elem in enumerate(self.module.elements):
            for funcidx in elem.init:
                if funcidx >= self.funcs_total:
                    self._add_error("index_out_of_range", f"Element segment {i}: invalid funcidx {funcidx}")

    def _validate_data_count(self):
        """Validate data count section."""
        if self.module.data_count is not None:
            if self.module.data_count != len(self.module.data):
                self._add_error("data_count_mismatch", f"Data count section says {self.module.data_count} but data section has {len(self.module.data)}")

