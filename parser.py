"""
parser.py - Public API surface for WASM binary module parsing + structural validation.

Implementation is intentionally omitted in this template.
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
# AST Data Structures
# ----------------------------

class ValType(IntEnum):
    """Supported value types."""
    I32 = 0x7F
    I64 = 0x7E


@dataclass(frozen=True)
class FuncType:
    """Function type: parameters and results."""
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
    limits: TableLimits


@dataclass(frozen=True)
class ImportGlobal:
    """Global import."""
    module: bytes
    name: bytes
    global_type: GlobalType


Import = Union[ImportFunc, ImportTable, ImportMem, ImportGlobal]


@dataclass(frozen=True)
class Global:
    """Global definition."""
    global_type: GlobalType
    init_expr: List['Instruction']


class Opcode(IntEnum):
    """Supported opcodes."""
    END = 0x0B
    CALL = 0x10
    LOCAL_GET = 0x20
    LOCAL_SET = 0x21
    I32_CONST = 0x41
    I32_ADD = 0x6A


@dataclass(frozen=True)
class Instruction:
    """A single instruction."""
    opcode: Opcode
    immediate: Optional[int] = None


@dataclass(frozen=True)
class Export:
    """Export entry."""
    name: bytes
    kind: int  # 0=func, 1=table, 2=mem, 3=global
    index: int


@dataclass(frozen=True)
class LocalDecl:
    """Local variable declaration."""
    count: int
    valtype: ValType


@dataclass(frozen=True)
class FuncBody:
    """Function body with locals and code."""
    locals: List[LocalDecl]
    code: List[Instruction]


@dataclass(frozen=True)
class ElementSegment:
    """Element segment (restricted to active mode for table 0)."""
    offset: int
    funcidxs: List[int]


@dataclass(frozen=True)
class DataSegment:
    """Data segment (restricted to active mode for memory 0)."""
    offset: int
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
    function_typeidxs: List[int]
    tables: List[TableType]
    memories: List[TableLimits]
    globals: List[Global]
    exports: List[Export]
    start: Optional[int]
    elements: List[ElementSegment]
    code: List[FuncBody]
    datas: List[DataSegment]
    datacount: Optional[int]


# ----------------------------
# Decoder Implementation
# ----------------------------

class Decoder:
    """Binary decoder for WASM modules."""

    def __init__(self, data: bytes, limits: Limits):
        self.data = data
        self.pos = 0
        self.limits = limits
        self.seen_sections: set[int] = set()
        self.last_section_id = -1

    def eof(self) -> bool:
        return self.pos >= len(self.data)

    def peek_byte(self) -> Optional[int]:
        if self.eof():
            return None
        return self.data[self.pos]

    def read_byte(self) -> int:
        if self.eof():
            raise DecodeError("Unexpected EOF reading byte", offset=self.pos)
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_bytes(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise DecodeError(f"Unexpected EOF reading {n} bytes", offset=self.pos)
        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result

    def read_u32_leb128(self) -> int:
        """Read unsigned LEB128 u32."""
        result = 0
        shift = 0
        start_pos = self.pos

        while True:
            if self.eof():
                raise DecodeError("Unexpected EOF in LEB128", offset=start_pos)

            byte = self.read_byte()
            result |= (byte & 0x7F) << shift

            if (byte & 0x80) == 0:
                break

            shift += 7
            if shift >= 35:
                raise DecodeError("LEB128 too long for u32", offset=start_pos)

        if result > 0xFFFFFFFF:
            raise DecodeError("LEB128 value exceeds u32", offset=start_pos)

        return result

    def read_s32_leb128(self) -> int:
        """Read signed LEB128 s32."""
        result = 0
        shift = 0
        start_pos = self.pos
        byte = 0

        while True:
            if self.eof():
                raise DecodeError("Unexpected EOF in LEB128", offset=start_pos)

            byte = self.read_byte()
            result |= (byte & 0x7F) << shift
            shift += 7

            if (byte & 0x80) == 0:
                break

            if shift >= 35:
                raise DecodeError("LEB128 too long for s32", offset=start_pos)

        if shift < 32 and (byte & 0x40):
            result |= -(1 << shift)

        if result < -0x80000000 or result > 0x7FFFFFFF:
            raise DecodeError("LEB128 value exceeds s32 range", offset=start_pos)

        return result

    def read_name(self) -> bytes:
        """Read a name (length-prefixed byte string)."""
        length = self.read_u32_leb128()
        return self.read_bytes(length)

    def read_vector(self, read_element) -> List:
        """Read a vector of elements."""
        count = self.read_u32_leb128()
        if count > self.limits.max_vector_length:
            raise DecodeError(f"Vector length {count} exceeds limit {self.limits.max_vector_length}", offset=self.pos)
        return [read_element() for _ in range(count)]

    def read_valtype(self) -> ValType:
        """Read a value type."""
        byte = self.read_byte()
        if byte == ValType.I32:
            return ValType.I32
        elif byte == ValType.I64:
            return ValType.I64
        else:
            raise DecodeError(f"Unsupported valtype: 0x{byte:02X}", offset=self.pos - 1, code="unsupported_valtype")

    def read_functype(self) -> FuncType:
        """Read a function type."""
        tag = self.read_byte()
        if tag != 0x60:
            raise DecodeError(f"Expected functype tag 0x60, got 0x{tag:02X}", offset=self.pos - 1)
        params = self.read_vector(self.read_valtype)
        results = self.read_vector(self.read_valtype)
        return FuncType(params=params, results=results)

    def read_limits(self) -> TableLimits:
        """Read table/memory limits."""
        flags = self.read_byte()
        if flags == 0x00:
            min_val = self.read_u32_leb128()
            return TableLimits(min=min_val, max=None)
        elif flags == 0x01:
            min_val = self.read_u32_leb128()
            max_val = self.read_u32_leb128()
            return TableLimits(min=min_val, max=max_val)
        else:
            raise DecodeError(f"Bad limits flag: 0x{flags:02X}", offset=self.pos - 1, code="bad_limits_flag")

    def read_tabletype(self) -> TableType:
        """Read a table type."""
        elemtype = self.read_byte()
        if elemtype != 0x70:
            raise DecodeError(f"Unsupported table elemtype: 0x{elemtype:02X}", offset=self.pos - 1, code="unsupported_table_elemtype")
        limits = self.read_limits()
        return TableType(limits=limits)

    def read_globaltype(self) -> GlobalType:
        """Read a global type."""
        valtype = self.read_valtype()
        mut = self.read_byte()
        if mut == 0x00:
            mutable = False
        elif mut == 0x01:
            mutable = True
        else:
            raise DecodeError(f"Bad mutability: 0x{mut:02X}", offset=self.pos - 1, code="bad_mutability")
        return GlobalType(valtype=valtype, mutable=mutable)

    def read_expr(self) -> List[Instruction]:
        """Read an expression (sequence of instructions ending with END)."""
        instructions = []
        while True:
            opcode_byte = self.read_byte()

            if opcode_byte == Opcode.END:
                instructions.append(Instruction(opcode=Opcode.END))
                break
            elif opcode_byte == Opcode.I32_CONST:
                imm = self.read_s32_leb128()
                instructions.append(Instruction(opcode=Opcode.I32_CONST, immediate=imm))
            elif opcode_byte == Opcode.LOCAL_GET:
                localidx = self.read_u32_leb128()
                instructions.append(Instruction(opcode=Opcode.LOCAL_GET, immediate=localidx))
            elif opcode_byte == Opcode.LOCAL_SET:
                localidx = self.read_u32_leb128()
                instructions.append(Instruction(opcode=Opcode.LOCAL_SET, immediate=localidx))
            elif opcode_byte == Opcode.I32_ADD:
                instructions.append(Instruction(opcode=Opcode.I32_ADD))
            elif opcode_byte == Opcode.CALL:
                funcidx = self.read_u32_leb128()
                instructions.append(Instruction(opcode=Opcode.CALL, immediate=funcidx))
            else:
                raise DecodeError(f"Unsupported opcode: 0x{opcode_byte:02X}", offset=self.pos - 1, code="unsupported_opcode")

        return instructions


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

    dec = Decoder(data, limits)

    # Read preamble
    magic = dec.read_bytes(4)
    if magic != b"\x00asm":
        raise DecodeError(f"Invalid magic: {magic!r}")

    version = dec.read_bytes(4)
    if version != b"\x01\x00\x00\x00":
        raise DecodeError(f"Invalid version: {version!r}")

    # Initialize module fields
    types: List[FuncType] = []
    imports: List[Import] = []
    function_typeidxs: List[int] = []
    tables: List[TableType] = []
    memories: List[TableLimits] = []
    globals: List[Global] = []
    exports: List[Export] = []
    start: Optional[int] = None
    elements: List[ElementSegment] = []
    code: List[FuncBody] = []
    datas: List[DataSegment] = []
    datacount: Optional[int] = None

    # Parse sections
    while not dec.eof():
        section_id = dec.read_byte()
        payload_len = dec.read_u32_leb128()

        if section_id != 0:
            if payload_len > limits.max_section_bytes:
                raise DecodeError(f"Section {section_id} payload {payload_len} exceeds limit {limits.max_section_bytes}")
        else:
            if payload_len > limits.max_custom_section_bytes:
                raise DecodeError(f"Custom section payload {payload_len} exceeds limit {limits.max_custom_section_bytes}")

        section_start = dec.pos
        section_end = section_start + payload_len

        if section_end > len(data):
            raise DecodeError(f"Section {section_id} extends beyond module", offset=section_start)

        # Check section ordering
        if section_id != 0:
            if section_id in dec.seen_sections:
                raise DecodeError(f"Duplicate section {section_id}", offset=section_start - 2, code="section_order")
            if section_id < dec.last_section_id:
                raise DecodeError(f"Section {section_id} out of order", offset=section_start - 2, code="section_order")
            dec.seen_sections.add(section_id)
            dec.last_section_id = section_id

        # Parse section payload
        if section_id == 0:
            # Custom section - skip
            dec.pos = section_end
        elif section_id == 1:
            # Type section
            types = dec.read_vector(dec.read_functype)
        elif section_id == 2:
            # Import section
            def read_import() -> Import:
                module_name = dec.read_name()
                field_name = dec.read_name()
                kind = dec.read_byte()

                if kind == 0:
                    typeidx = dec.read_u32_leb128()
                    return ImportFunc(module=module_name, name=field_name, typeidx=typeidx)
                elif kind == 1:
                    table_type = dec.read_tabletype()
                    return ImportTable(module=module_name, name=field_name, table_type=table_type)
                elif kind == 2:
                    limits = dec.read_limits()
                    return ImportMem(module=module_name, name=field_name, limits=limits)
                elif kind == 3:
                    global_type = dec.read_globaltype()
                    return ImportGlobal(module=module_name, name=field_name, global_type=global_type)
                else:
                    raise DecodeError(f"Unknown import kind: {kind}", offset=dec.pos - 1)

            imports = dec.read_vector(read_import)
        elif section_id == 3:
            # Function section
            function_typeidxs = dec.read_vector(dec.read_u32_leb128)
        elif section_id == 4:
            # Table section
            tables = dec.read_vector(dec.read_tabletype)
        elif section_id == 5:
            # Memory section
            memories = dec.read_vector(dec.read_limits)
        elif section_id == 6:
            # Global section
            def read_global() -> Global:
                gt = dec.read_globaltype()
                init = dec.read_expr()
                return Global(global_type=gt, init_expr=init)

            globals = dec.read_vector(read_global)
        elif section_id == 7:
            # Export section
            def read_export() -> Export:
                name = dec.read_name()
                kind = dec.read_byte()
                index = dec.read_u32_leb128()
                return Export(name=name, kind=kind, index=index)

            exports = dec.read_vector(read_export)
        elif section_id == 8:
            # Start section
            start = dec.read_u32_leb128()
        elif section_id == 9:
            # Element section
            def read_element() -> ElementSegment:
                tableidx = dec.read_u32_leb128()
                if tableidx != 0:
                    raise DecodeError(f"Unsupported element tableidx: {tableidx}", offset=dec.pos - 1, code="unsupported_element_form")

                # Read offset expression - must be i32.const followed by end
                expr = dec.read_expr()
                if len(expr) != 2 or expr[0].opcode != Opcode.I32_CONST or expr[1].opcode != Opcode.END:
                    raise DecodeError("Unsupported element offset form", offset=dec.pos, code="unsupported_element_form")

                offset_val = expr[0].immediate
                funcidxs = dec.read_vector(dec.read_u32_leb128)
                return ElementSegment(offset=offset_val, funcidxs=funcidxs)

            elements = dec.read_vector(read_element)
        elif section_id == 10:
            # Code section
            def read_funcbody() -> FuncBody:
                body_size = dec.read_u32_leb128()
                if body_size > limits.max_function_body_bytes:
                    raise DecodeError(f"Function body size {body_size} exceeds limit {limits.max_function_body_bytes}")

                body_start = dec.pos
                body_end = body_start + body_size

                # Read locals
                def read_local_decl() -> LocalDecl:
                    count = dec.read_u32_leb128()
                    vt = dec.read_valtype()
                    return LocalDecl(count=count, valtype=vt)

                local_decls = dec.read_vector(read_local_decl)

                # Check total locals
                total_locals = sum(ld.count for ld in local_decls)
                if total_locals > limits.max_locals_per_function:
                    raise DecodeError(f"Total locals {total_locals} exceeds limit {limits.max_locals_per_function}")

                # Read code
                instructions = dec.read_expr()

                # Check exact body size
                if dec.pos != body_end:
                    if dec.pos < body_end:
                        raise DecodeError("Trailing bytes in function body", offset=dec.pos, code="trailing_bytes_in_expr")
                    else:
                        raise DecodeError("Function body size mismatch", offset=body_start, code="section_size_mismatch")

                return FuncBody(locals=local_decls, code=instructions)

            code = dec.read_vector(read_funcbody)
        elif section_id == 11:
            # Data section
            def read_data() -> DataSegment:
                memidx = dec.read_u32_leb128()
                if memidx != 0:
                    raise DecodeError(f"Unsupported data memidx: {memidx}", offset=dec.pos - 1, code="unsupported_data_form")

                # Read offset expression - must be i32.const followed by end
                expr = dec.read_expr()
                if len(expr) != 2 or expr[0].opcode != Opcode.I32_CONST or expr[1].opcode != Opcode.END:
                    raise DecodeError("Unsupported data offset form", offset=dec.pos, code="unsupported_data_form")

                offset_val = expr[0].immediate
                data_bytes = dec.read_name()
                return DataSegment(offset=offset_val, data=data_bytes)

            datas = dec.read_vector(read_data)
        elif section_id == 12:
            # Data count section
            datacount = dec.read_u32_leb128()
        else:
            raise DecodeError(f"Unknown section id: {section_id}", offset=section_start - 2, code="unknown_section_id")

        # Check exact section size
        if dec.pos != section_end:
            raise DecodeError(f"Section {section_id} size mismatch", offset=section_start, code="section_size_mismatch")

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
        datas=datas,
        datacount=datacount
    )


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
    imported_mems = sum(1 for imp in module.imports if isinstance(imp, ImportMem))
    imported_globals = sum(1 for imp in module.imports if isinstance(imp, ImportGlobal))

    funcs_total = imported_funcs + len(module.function_typeidxs)
    tables_total = imported_tables + len(module.tables)
    mems_total = imported_mems + len(module.memories)
    globals_total = imported_globals + len(module.globals)

    # Validate limits
    for table in module.tables:
        if table.limits.max is not None and table.limits.min > table.limits.max:
            errors.append(ValidationError(code="limits_min_gt_max", message=f"Table limits min {table.limits.min} > max {table.limits.max}"))

    for mem in module.memories:
        if mem.max is not None and mem.min > mem.max:
            errors.append(ValidationError(code="limits_min_gt_max", message=f"Memory limits min {mem.min} > max {mem.max}"))

    for imp in module.imports:
        if isinstance(imp, ImportTable):
            if imp.table_type.limits.max is not None and imp.table_type.limits.min > imp.table_type.limits.max:
                errors.append(ValidationError(code="limits_min_gt_max", message=f"Import table limits min > max"))
        elif isinstance(imp, ImportMem):
            if imp.limits.max is not None and imp.limits.min > imp.limits.max:
                errors.append(ValidationError(code="limits_min_gt_max", message=f"Import memory limits min > max"))

    # Validate import function typeidx
    for imp in module.imports:
        if isinstance(imp, ImportFunc):
            if imp.typeidx >= len(module.types):
                errors.append(ValidationError(code="type_index_out_of_range", message=f"Import func typeidx {imp.typeidx} out of range"))

    # Validate function typeidx
    for i, typeidx in enumerate(module.function_typeidxs):
        if typeidx >= len(module.types):
            errors.append(ValidationError(code="type_index_out_of_range", message=f"Function {i + imported_funcs} typeidx {typeidx} out of range"))

    # Validate code count
    if len(module.code) != len(module.function_typeidxs):
        errors.append(ValidationError(code="func_code_count_mismatch", message=f"Code count {len(module.code)} != function count {len(module.function_typeidxs)}"))

    # Validate exports
    export_names = []
    for exp in module.exports:
        export_names.append(exp.name)

        if exp.kind == 0:
            if exp.index >= funcs_total:
                errors.append(ValidationError(code="index_out_of_range", message=f"Export func index {exp.index} out of range"))
        elif exp.kind == 1:
            if exp.index >= tables_total:
                errors.append(ValidationError(code="index_out_of_range", message=f"Export table index {exp.index} out of range"))
        elif exp.kind == 2:
            if exp.index >= mems_total:
                errors.append(ValidationError(code="index_out_of_range", message=f"Export mem index {exp.index} out of range"))
        elif exp.kind == 3:
            if exp.index >= globals_total:
                errors.append(ValidationError(code="index_out_of_range", message=f"Export global index {exp.index} out of range"))

    # Check for duplicate export names
    seen_names = set()
    for name in export_names:
        if name in seen_names:
            errors.append(ValidationError(code="duplicate_export_name", message=f"Duplicate export name: {name!r}"))
        seen_names.add(name)

    # Validate start function
    if module.start is not None:
        if module.start >= funcs_total:
            errors.append(ValidationError(code="index_out_of_range", message=f"Start function index {module.start} out of range"))
        else:
            # Get start function type
            if module.start < imported_funcs:
                # It's an import
                func_imports = [imp for imp in module.imports if isinstance(imp, ImportFunc)]
                typeidx = func_imports[module.start].typeidx
            else:
                # It's a defined function
                typeidx = module.function_typeidxs[module.start - imported_funcs]

            if typeidx < len(module.types):
                ftype = module.types[typeidx]
                if len(ftype.params) != 0 or len(ftype.results) != 0:
                    errors.append(ValidationError(code="bad_start_signature", message=f"Start function must have type [] -> []"))

    # Validate code bodies
    for func_idx, funcbody in enumerate(module.code):
        typeidx = module.function_typeidxs[func_idx]
        if typeidx >= len(module.types):
            continue

        ftype = module.types[typeidx]
        total_locals = len(ftype.params) + sum(ld.count for ld in funcbody.locals)

        # Validate local indices in instructions
        for instr in funcbody.code:
            if instr.opcode in (Opcode.LOCAL_GET, Opcode.LOCAL_SET):
                if instr.immediate >= total_locals:
                    errors.append(ValidationError(code="local_index_out_of_range", message=f"Function {func_idx + imported_funcs} local index {instr.immediate} out of range"))
            elif instr.opcode == Opcode.CALL:
                if instr.immediate >= funcs_total:
                    errors.append(ValidationError(code="index_out_of_range", message=f"Function {func_idx + imported_funcs} call index {instr.immediate} out of range"))

    # Validate element segments
    for elem in module.elements:
        for funcidx in elem.funcidxs:
            if funcidx >= funcs_total:
                errors.append(ValidationError(code="index_out_of_range", message=f"Element funcidx {funcidx} out of range"))

    # Validate data count
    if module.datacount is not None:
        if module.datacount != len(module.datas):
            errors.append(ValidationError(code="data_count_mismatch", message=f"Data count {module.datacount} != actual data segments {len(module.datas)}"))

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

