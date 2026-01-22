"""
WebAssembly binary decoder.

Decodes WASM binary format into AST dataclasses.
"""

from typing import List, Tuple, Optional
from binary_reader import ByteReader, ByteReaderError
import leb128
from wasm_types import (
    Module, FuncType, ValType, RefType, Limits, TableType, MemType,
    GlobalType, Global, Import, ImportKind, Export, Instruction, Opcode,
    Expr, FuncBody, LocalDecl, ElementSegment, DataSegment, CustomSection
)


class DecodeError(Exception):
    """Raised when binary decoding fails."""

    def __init__(self, message: str, offset: Optional[int] = None, code: Optional[str] = None):
        self.message = message
        self.offset = offset
        self.code = code
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        parts = [self.message]
        if self.offset is not None:
            parts.append(f"at offset {self.offset}")
        if self.code:
            parts.append(f"(code: {self.code})")
        return " ".join(parts)


# WASM magic number and version
WASM_MAGIC = b'\x00asm'
WASM_VERSION = 1


# Section IDs
SECTION_CUSTOM = 0
SECTION_TYPE = 1
SECTION_IMPORT = 2
SECTION_FUNCTION = 3
SECTION_TABLE = 4
SECTION_MEMORY = 5
SECTION_GLOBAL = 6
SECTION_EXPORT = 7
SECTION_START = 8
SECTION_ELEMENT = 9
SECTION_CODE = 10
SECTION_DATA = 11
SECTION_DATA_COUNT = 12


def decode_module(data: bytes, limits: Optional['Limits'] = None) -> Module:
    """
    Decode a WebAssembly binary module.

    Args:
        data: Binary module data
        limits: Resource limits for decoding

    Returns:
        Decoded Module AST

    Raises:
        DecodeError: If binary is malformed
    """
    if limits is None:
        # Default limits
        from dataclasses import dataclass
        @dataclass
        class DecodeLimits:
            max_module_bytes: int = 100 * 1024 * 1024  # 100 MB
            max_section_bytes: int = 50 * 1024 * 1024  # 50 MB
            max_vector_length: int = 1000000
            max_function_body_bytes: int = 1024 * 1024  # 1 MB
            max_locals_per_function: int = 50000
            max_custom_section_bytes: int = 10 * 1024 * 1024  # 10 MB

        limits = DecodeLimits()

    # Check module size
    if len(data) > limits.max_module_bytes:
        raise DecodeError(
            f"module too large: {len(data)} bytes exceeds limit of {limits.max_module_bytes}",
            offset=0,
            code="module_too_large"
        )

    reader = ByteReader(data)
    module = Module()

    # Decode magic number and version
    decode_magic_and_version(reader)

    # Decode sections
    last_section_id = -1
    while not reader.at_end():
        section_id = reader.read_byte()

        # Custom sections can appear anywhere and multiple times
        if section_id != SECTION_CUSTOM:
            if section_id <= last_section_id:
                raise DecodeError(
                    f"section {section_id} appears after section {last_section_id}, violates ordering",
                    offset=reader.offset() - 1,
                    code="section_order"
                )
            last_section_id = section_id

        # Read section size
        try:
            section_size, _ = leb128.read_u32(reader)
        except leb128.LEB128Error as e:
            raise DecodeError(f"invalid section size: {e}", offset=reader.offset(), code="invalid_section_size")

        # Check section size limit
        if section_id == SECTION_CUSTOM:
            if section_size > limits.max_custom_section_bytes:
                raise DecodeError(
                    f"custom section too large: {section_size} bytes",
                    offset=reader.offset(),
                    code="custom_section_too_large"
                )
        else:
            if section_size > limits.max_section_bytes:
                raise DecodeError(
                    f"section too large: {section_size} bytes",
                    offset=reader.offset(),
                    code="section_too_large"
                )

        # Create sub-reader for section payload
        try:
            section_reader = reader.slice(section_size)
        except ByteReaderError as e:
            raise DecodeError(f"invalid section: {e}", offset=reader.offset(), code="invalid_section")

        # Decode section content
        try:
            decode_section(section_id, section_reader, module, limits)
        except DecodeError:
            raise
        except Exception as e:
            raise DecodeError(
                f"error decoding section {section_id}: {e}",
                offset=section_reader.offset(),
                code="section_decode_error"
            )

        # Ensure all section bytes were consumed
        if not section_reader.at_end():
            raise DecodeError(
                f"trailing bytes in section {section_id}: {section_reader.remaining()} bytes remain",
                offset=section_reader.offset(),
                code="trailing_section_bytes"
            )

    return module


def decode_magic_and_version(reader: ByteReader) -> None:
    """
    Decode and validate WASM magic number and version.

    Args:
        reader: ByteReader at start of module

    Raises:
        DecodeError: If magic or version is invalid
    """
    offset = reader.offset()

    # Read magic number
    try:
        magic = reader.read_bytes(4)
    except ByteReaderError:
        raise DecodeError("truncated magic number", offset=offset, code="truncated_magic")

    if magic != WASM_MAGIC:
        raise DecodeError(
            f"invalid magic number: expected {WASM_MAGIC.hex()}, got {magic.hex()}",
            offset=offset,
            code="invalid_magic"
        )

    # Read version
    try:
        version_bytes = reader.read_bytes(4)
    except ByteReaderError:
        raise DecodeError("truncated version", offset=reader.offset(), code="truncated_version")

    version = int.from_bytes(version_bytes, byteorder='little')
    if version != WASM_VERSION:
        raise DecodeError(
            f"unsupported version: expected {WASM_VERSION}, got {version}",
            offset=reader.offset() - 4,
            code="unsupported_version"
        )


def decode_section(section_id: int, reader: ByteReader, module: Module, limits) -> None:
    """
    Decode a section and populate module.

    Args:
        section_id: Section ID (0-12)
        reader: ByteReader positioned at section payload
        module: Module to populate
        limits: Resource limits

    Raises:
        DecodeError: If section is malformed
    """
    if section_id == SECTION_CUSTOM:
        custom = decode_custom_section(reader, limits)
        module.customs.append(custom)
    elif section_id == SECTION_TYPE:
        module.types = decode_type_section(reader, limits)
    elif section_id == SECTION_IMPORT:
        module.imports = decode_import_section(reader, limits)
    elif section_id == SECTION_FUNCTION:
        module.functions = decode_function_section(reader, limits)
    elif section_id == SECTION_TABLE:
        module.tables = decode_table_section(reader, limits)
    elif section_id == SECTION_MEMORY:
        module.memories = decode_memory_section(reader, limits)
    elif section_id == SECTION_GLOBAL:
        module.globals = decode_global_section(reader, limits)
    elif section_id == SECTION_EXPORT:
        module.exports = decode_export_section(reader, limits)
    elif section_id == SECTION_START:
        module.start = decode_start_section(reader, limits)
    elif section_id == SECTION_ELEMENT:
        module.elements = decode_element_section(reader, limits)
    elif section_id == SECTION_CODE:
        module.code = decode_code_section(reader, limits)
    elif section_id == SECTION_DATA:
        module.data = decode_data_section(reader, limits)
    elif section_id == SECTION_DATA_COUNT:
        module.data_count = decode_data_count_section(reader, limits)
    else:
        raise DecodeError(f"unknown section id: {section_id}", offset=reader.offset() - 1, code="unknown_section")


# ===== Helper Functions =====

def decode_vector(reader: ByteReader, decode_element, limits) -> List:
    """
    Decode a vector (length-prefixed sequence).

    Args:
        reader: ByteReader
        decode_element: Function to decode each element
        limits: Resource limits

    Returns:
        List of decoded elements

    Raises:
        DecodeError: If vector is malformed or exceeds limits
    """
    try:
        count, _ = leb128.read_u32(reader)
    except leb128.LEB128Error as e:
        raise DecodeError(f"invalid vector length: {e}", offset=reader.offset(), code="invalid_vector_length")

    if count > limits.max_vector_length:
        raise DecodeError(
            f"vector too long: {count} exceeds limit of {limits.max_vector_length}",
            offset=reader.offset(),
            code="vector_too_long"
        )

    elements = []
    for _ in range(count):
        elements.append(decode_element(reader, limits))

    return elements


def decode_name(reader: ByteReader, limits) -> str:
    """
    Decode a UTF-8 name (length-prefixed string).

    Args:
        reader: ByteReader
        limits: Resource limits

    Returns:
        Decoded string

    Raises:
        DecodeError: If name is malformed
    """
    try:
        length, _ = leb128.read_u32(reader)
    except leb128.LEB128Error as e:
        raise DecodeError(f"invalid name length: {e}", offset=reader.offset(), code="invalid_name_length")

    if length > limits.max_vector_length:
        raise DecodeError(
            f"name too long: {length} bytes",
            offset=reader.offset(),
            code="name_too_long"
        )

    try:
        name_bytes = reader.read_bytes(length)
    except ByteReaderError as e:
        raise DecodeError(f"truncated name: {e}", offset=reader.offset(), code="truncated_name")

    try:
        return name_bytes.decode('utf-8')
    except UnicodeDecodeError as e:
        raise DecodeError(f"invalid UTF-8 in name: {e}", offset=reader.offset() - length, code="invalid_utf8")


def decode_limits(reader: ByteReader, limits) -> Limits:
    """
    Decode limits (for memory or table).

    Args:
        reader: ByteReader
        limits: Resource limits

    Returns:
        Decoded Limits

    Raises:
        DecodeError: If limits are malformed
    """
    flags = reader.read_byte()

    try:
        min_val, _ = leb128.read_u32(reader)
    except leb128.LEB128Error as e:
        raise DecodeError(f"invalid limits min: {e}", offset=reader.offset(), code="invalid_limits")

    if flags == 0x00:
        return Limits(min=min_val, max=None)
    elif flags == 0x01:
        try:
            max_val, _ = leb128.read_u32(reader)
        except leb128.LEB128Error as e:
            raise DecodeError(f"invalid limits max: {e}", offset=reader.offset(), code="invalid_limits")
        return Limits(min=min_val, max=max_val)
    else:
        raise DecodeError(f"invalid limits flags: {flags}", offset=reader.offset() - 1, code="invalid_limits_flags")


# ===== Section Decoders (Stubs for now) =====

def decode_custom_section(reader: ByteReader, limits) -> CustomSection:
    """Decode custom section."""
    name = decode_name(reader, limits)
    data = reader.read_bytes(reader.remaining())
    return CustomSection(name=name, data=data)


def decode_type_section(reader: ByteReader, limits) -> List[FuncType]:
    """Decode type section."""
    def decode_functype(r: ByteReader, lim) -> FuncType:
        # Read function type tag (must be 0x60)
        tag = r.read_byte()
        if tag != 0x60:
            raise DecodeError(f"invalid function type tag: expected 0x60, got 0x{tag:02x}", offset=r.offset() - 1, code="invalid_functype_tag")

        # Decode parameter types
        params = decode_valtype_vector(r, lim)

        # Decode result types
        results = decode_valtype_vector(r, lim)

        return FuncType(params=params, results=results)

    return decode_vector(reader, decode_functype, limits)


def decode_valtype_vector(reader: ByteReader, limits) -> List[ValType]:
    """Decode a vector of value types."""
    def decode_valtype(r: ByteReader, lim) -> ValType:
        byte = r.read_byte()
        try:
            return ValType(byte)
        except ValueError:
            raise DecodeError(f"invalid value type: 0x{byte:02x}", offset=r.offset() - 1, code="invalid_valtype")

    return decode_vector(reader, decode_valtype, limits)


def decode_import_section(reader: ByteReader, limits) -> List[Import]:
    """Decode import section."""
    def decode_import(r: ByteReader, lim) -> Import:
        # Read module and name
        module_name = decode_name(r, lim)
        import_name = decode_name(r, lim)

        # Read import kind
        kind_byte = r.read_byte()
        try:
            kind = ImportKind(kind_byte)
        except ValueError:
            raise DecodeError(f"invalid import kind: 0x{kind_byte:02x}", offset=r.offset() - 1, code="invalid_import_kind")

        # Read import descriptor based on kind
        if kind == ImportKind.FUNC:
            try:
                typeidx, _ = leb128.read_u32(r)
            except leb128.LEB128Error as e:
                raise DecodeError(f"invalid import function typeidx: {e}", offset=r.offset(), code="invalid_import_typeidx")
            return Import(module=module_name, name=import_name, kind=kind, typeidx=typeidx)

        elif kind == ImportKind.TABLE:
            table_type = decode_table_type(r, lim)
            return Import(module=module_name, name=import_name, kind=kind, table_type=table_type)

        elif kind == ImportKind.MEM:
            mem_type = decode_mem_type(r, lim)
            return Import(module=module_name, name=import_name, kind=kind, mem_type=mem_type)

        elif kind == ImportKind.GLOBAL:
            global_type = decode_global_type(r, lim)
            return Import(module=module_name, name=import_name, kind=kind, global_type=global_type)

        else:
            raise DecodeError(f"unsupported import kind: {kind}", offset=r.offset() - 1, code="unsupported_import_kind")

    return decode_vector(reader, decode_import, limits)


def decode_table_type(reader: ByteReader, limits) -> TableType:
    """Decode table type."""
    elem_type_byte = reader.read_byte()
    try:
        elem_type = RefType(elem_type_byte)
    except ValueError:
        raise DecodeError(f"invalid table element type: 0x{elem_type_byte:02x}", offset=reader.offset() - 1, code="invalid_table_elem_type")

    if elem_type != RefType.FUNCREF:
        raise DecodeError(
            f"unsupported table element type: {elem_type.name.lower()}",
            offset=reader.offset() - 1,
            code="unsupported_table_elem_type"
        )

    table_limits = decode_limits(reader, limits)
    return TableType(element_type=elem_type, limits=table_limits)


def decode_mem_type(reader: ByteReader, limits) -> MemType:
    """Decode memory type."""
    mem_limits = decode_limits(reader, limits)
    return MemType(limits=mem_limits)


def decode_global_type(reader: ByteReader, limits) -> GlobalType:
    """Decode global type."""
    valtype_byte = reader.read_byte()
    try:
        valtype = ValType(valtype_byte)
    except ValueError:
        raise DecodeError(f"invalid global value type: 0x{valtype_byte:02x}", offset=reader.offset() - 1, code="invalid_global_valtype")

    mut_byte = reader.read_byte()
    if mut_byte == 0x00:
        mutable = False
    elif mut_byte == 0x01:
        mutable = True
    else:
        raise DecodeError(f"invalid global mutability: 0x{mut_byte:02x}", offset=reader.offset() - 1, code="invalid_global_mut")

    return GlobalType(valtype=valtype, mutable=mutable)


def decode_function_section(reader: ByteReader, limits) -> List[int]:
    """Decode function section (vector of type indices)."""
    def decode_typeidx(r: ByteReader, lim) -> int:
        try:
            typeidx, _ = leb128.read_u32(r)
        except leb128.LEB128Error as e:
            raise DecodeError(f"invalid type index: {e}", offset=r.offset(), code="invalid_typeidx")
        return typeidx

    return decode_vector(reader, decode_typeidx, limits)


def decode_table_section(reader: ByteReader, limits) -> List[TableType]:
    """Decode table section."""
    return decode_vector(reader, decode_table_type, limits)


def decode_memory_section(reader: ByteReader, limits) -> List[MemType]:
    """Decode memory section."""
    return decode_vector(reader, decode_mem_type, limits)


def decode_global_section(reader: ByteReader, limits) -> List[Global]:
    """Decode global section."""
    def decode_global(r: ByteReader, lim) -> Global:
        global_type = decode_global_type(r, lim)
        init_expr = decode_expr(r, lim)
        return Global(type=global_type, init=init_expr)

    return decode_vector(reader, decode_global, limits)


def decode_export_section(reader: ByteReader, limits) -> List[Export]:
    """Decode export section."""
    def decode_export(r: ByteReader, lim) -> Export:
        # Read export name
        export_name = decode_name(r, lim)

        # Read export kind
        kind_byte = r.read_byte()
        try:
            kind = ImportKind(kind_byte)  # Export kinds use same values as import kinds
        except ValueError:
            raise DecodeError(f"invalid export kind: 0x{kind_byte:02x}", offset=r.offset() - 1, code="invalid_export_kind")

        # Read export index
        try:
            index, _ = leb128.read_u32(r)
        except leb128.LEB128Error as e:
            raise DecodeError(f"invalid export index: {e}", offset=r.offset(), code="invalid_export_index")

        return Export(name=export_name, kind=kind, index=index)

    return decode_vector(reader, decode_export, limits)


def decode_start_section(reader: ByteReader, limits) -> int:
    """Decode start section."""
    # Will implement in Phase 7
    try:
        funcidx, _ = leb128.read_u32(reader)
    except leb128.LEB128Error as e:
        raise DecodeError(f"invalid start function index: {e}", offset=reader.offset(), code="invalid_start")
    return funcidx


def decode_element_section(reader: ByteReader, limits) -> List[ElementSegment]:
    """
    Decode element section.

    RESTRICTION: Only supports active mode for table 0 with i32.const offset.
    """
    def decode_element_segment(r: ByteReader, lim) -> ElementSegment:
        # Read segment type/flags
        flags = r.read_byte()

        # Only support flags=0x00 (active mode, table 0, funcref, expr offset, vec(funcidx))
        if flags != 0x00:
            raise DecodeError(
                f"unsupported element segment flags: 0x{flags:02x} (only active mode for table 0 supported)",
                offset=r.offset() - 1,
                code="unsupported_element_flags"
            )

        # Decode offset expression
        offset_expr = decode_expr(r, lim)

        # Validate offset is i32.const followed by end
        if not is_i32_const_expr(offset_expr):
            raise DecodeError(
                "element segment offset must be i32.const followed by end",
                offset=r.offset(),
                code="invalid_element_offset"
            )

        # Decode function indices
        def decode_funcidx(reader: ByteReader, limits) -> int:
            try:
                funcidx, _ = leb128.read_u32(reader)
            except leb128.LEB128Error as e:
                raise DecodeError(f"invalid element funcidx: {e}", offset=reader.offset(), code="invalid_element_funcidx")
            return funcidx

        func_indices = decode_vector(r, decode_funcidx, lim)

        return ElementSegment(table_idx=0, offset=offset_expr, init=func_indices)

    return decode_vector(reader, decode_element_segment, limits)


def is_i32_const_expr(expr: Expr) -> bool:
    """Check if expression is exactly 'i32.const <value>; end'."""
    if len(expr.instructions) != 2:
        return False
    if expr.instructions[0].opcode != Opcode.I32_CONST:
        return False
    if expr.instructions[1].opcode != Opcode.END:
        return False
    return True


def decode_code_section(reader: ByteReader, limits) -> List[FuncBody]:
    """Decode code section (vector of function bodies)."""
    def decode_code_entry(r: ByteReader, lim) -> FuncBody:
        # Read code size
        try:
            code_size, _ = leb128.read_u32(r)
        except leb128.LEB128Error as e:
            raise DecodeError(f"invalid code size: {e}", offset=r.offset(), code="invalid_code_size")

        # Check function body size limit
        if code_size > lim.max_function_body_bytes:
            raise DecodeError(
                f"function body too large: {code_size} bytes exceeds limit of {lim.max_function_body_bytes}",
                offset=r.offset(),
                code="function_body_too_large"
            )

        # Create sub-reader for function body
        try:
            body_reader = r.slice(code_size)
        except ByteReaderError as e:
            raise DecodeError(f"invalid function body: {e}", offset=r.offset(), code="invalid_function_body")

        # Decode function body
        func_body = decode_func_body(body_reader, lim)

        # Ensure all bytes consumed
        if not body_reader.at_end():
            raise DecodeError(
                f"trailing bytes in function body: {body_reader.remaining()} bytes remain",
                offset=body_reader.offset(),
                code="trailing_function_bytes"
            )

        return func_body

    return decode_vector(reader, decode_code_entry, limits)


def decode_func_body(reader: ByteReader, limits) -> FuncBody:
    """Decode function body (locals + expression)."""
    # Decode locals vector
    def decode_local_decl(r: ByteReader, lim) -> LocalDecl:
        try:
            count, _ = leb128.read_u32(r)
        except leb128.LEB128Error as e:
            raise DecodeError(f"invalid local count: {e}", offset=r.offset(), code="invalid_local_count")

        valtype_byte = r.read_byte()
        try:
            valtype = ValType(valtype_byte)
        except ValueError:
            raise DecodeError(f"invalid local type: 0x{valtype_byte:02x}", offset=r.offset() - 1, code="invalid_local_type")

        return LocalDecl(count=count, valtype=valtype)

    locals_vec = decode_vector(reader, decode_local_decl, limits)

    # Check total locals limit
    total_locals = sum(local.count for local in locals_vec)
    if total_locals > limits.max_locals_per_function:
        raise DecodeError(
            f"too many locals: {total_locals} exceeds limit of {limits.max_locals_per_function}",
            offset=reader.offset(),
            code="too_many_locals"
        )

    # Decode expression
    expr = decode_expr(reader, limits)

    return FuncBody(locals=locals_vec, expr=expr)


def decode_expr(reader: ByteReader, limits) -> Expr:
    """
    Decode expression (sequence of instructions ending with 'end').

    Reads instructions until the first 'end' opcode.
    Raises error if there are trailing bytes after 'end'.
    """
    instructions = []

    while True:
        if reader.at_end():
            raise DecodeError("expression missing end opcode", offset=reader.offset(), code="missing_end")

        opcode_byte = reader.read_byte()

        try:
            opcode = Opcode(opcode_byte)
        except ValueError:
            raise DecodeError(
                f"unsupported opcode: 0x{opcode_byte:02x}",
                offset=reader.offset() - 1,
                code="unsupported_opcode"
            )

        if opcode == Opcode.END:
            instructions.append(Instruction(opcode=opcode))
            break
        elif opcode == Opcode.I32_CONST:
            # Read i32 immediate (signed LEB128)
            try:
                value, _ = leb128.read_s32(reader)
            except leb128.LEB128Error as e:
                raise DecodeError(f"invalid i32.const immediate: {e}", offset=reader.offset(), code="invalid_i32_const")
            instructions.append(Instruction(opcode=opcode, immediate=value))
        elif opcode in (Opcode.LOCAL_GET, Opcode.LOCAL_SET):
            # Read local index
            try:
                localidx, _ = leb128.read_u32(reader)
            except leb128.LEB128Error as e:
                raise DecodeError(f"invalid local index: {e}", offset=reader.offset(), code="invalid_localidx")
            instructions.append(Instruction(opcode=opcode, immediate=localidx))
        elif opcode == Opcode.CALL:
            # Read function index
            try:
                funcidx, _ = leb128.read_u32(reader)
            except leb128.LEB128Error as e:
                raise DecodeError(f"invalid function index: {e}", offset=reader.offset(), code="invalid_funcidx")
            instructions.append(Instruction(opcode=opcode, immediate=funcidx))
        elif opcode == Opcode.I32_ADD:
            # No immediate
            instructions.append(Instruction(opcode=opcode))
        else:
            raise DecodeError(
                f"unsupported opcode in subset: 0x{opcode_byte:02x}",
                offset=reader.offset() - 1,
                code="unsupported_opcode_subset"
            )

    return Expr(instructions=instructions)


def decode_data_section(reader: ByteReader, limits) -> List[DataSegment]:
    """
    Decode data section.

    RESTRICTION: Only supports active mode for memory 0 with i32.const offset.
    """
    def decode_data_segment(r: ByteReader, lim) -> DataSegment:
        # Read segment type/flags
        flags = r.read_byte()

        # Only support flags=0x00 (active mode, memory 0, expr offset)
        if flags != 0x00:
            raise DecodeError(
                f"unsupported data segment flags: 0x{flags:02x} (only active mode for memory 0 supported)",
                offset=r.offset() - 1,
                code="unsupported_data_flags"
            )

        # Decode offset expression
        offset_expr = decode_expr(r, lim)

        # Validate offset is i32.const followed by end
        if not is_i32_const_expr(offset_expr):
            raise DecodeError(
                "data segment offset must be i32.const followed by end",
                offset=r.offset(),
                code="invalid_data_offset"
            )

        # Decode data bytes
        try:
            byte_count, _ = leb128.read_u32(r)
        except leb128.LEB128Error as e:
            raise DecodeError(f"invalid data byte count: {e}", offset=r.offset(), code="invalid_data_count")

        if byte_count > lim.max_vector_length:
            raise DecodeError(
                f"data segment too large: {byte_count} bytes",
                offset=r.offset(),
                code="data_segment_too_large"
            )

        try:
            data_bytes = r.read_bytes(byte_count)
        except ByteReaderError as e:
            raise DecodeError(f"truncated data segment: {e}", offset=r.offset(), code="truncated_data")

        return DataSegment(memory_idx=0, offset=offset_expr, init=data_bytes)

    return decode_vector(reader, decode_data_segment, limits)


def decode_data_count_section(reader: ByteReader, limits) -> int:
    """Decode data count section."""
    # Will implement in Phase 6
    try:
        count, _ = leb128.read_u32(reader)
    except leb128.LEB128Error as e:
        raise DecodeError(f"invalid data count: {e}", offset=reader.offset(), code="invalid_data_count")
    return count
