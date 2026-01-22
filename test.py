"""
Unit tests for WASM binary module parser and validator.
"""

import pytest
from parser import (
    decode_module, validate_module, decode_and_validate,
    DecodeError, ValidationError, Limits, Module
)


# Helper to encode u32 as LEB128
def u32_leb(val: int) -> bytes:
    result = []
    while True:
        byte = val & 0x7F
        val >>= 7
        if val != 0:
            byte |= 0x80
        result.append(byte)
        if val == 0:
            break
    return bytes(result)


# Helper to encode s32 as LEB128
def s32_leb(val: int) -> bytes:
    result = []
    more = True
    while more:
        byte = val & 0x7F
        val >>= 7
        if (val == 0 and (byte & 0x40) == 0) or (val == -1 and (byte & 0x40) != 0):
            more = False
        else:
            byte |= 0x80
        result.append(byte)
    return bytes(result)


# Helper to encode a name
def encode_name(s: bytes) -> bytes:
    return u32_leb(len(s)) + s


# WASM magic and version
MAGIC = b'\x00asm'
VERSION = b'\x01\x00\x00\x00'
PREAMBLE = MAGIC + VERSION


class TestBasicDecoding:
    def test_minimal_module(self):
        """Test decoding minimal valid module (magic + version only)."""
        module = decode_module(PREAMBLE)
        assert module.raw_size == 8
        assert len(module.types) == 0
        assert len(module.imports) == 0

    def test_bad_magic(self):
        """Test that bad magic bytes raise DecodeError."""
        with pytest.raises(DecodeError) as exc:
            decode_module(b'\x00BAD\x01\x00\x00\x00')
        assert exc.value.code == 'bad_magic'

    def test_bad_version(self):
        """Test that bad version raises DecodeError."""
        with pytest.raises(DecodeError) as exc:
            decode_module(MAGIC + b'\x02\x00\x00\x00')
        assert exc.value.code == 'bad_version'

    def test_truncated_module(self):
        """Test that truncated module raises DecodeError."""
        with pytest.raises(DecodeError) as exc:
            decode_module(b'\x00as')
        assert exc.value.code in ('bad_magic', 'truncated')

    def test_size_limit(self):
        """Test that module size limit is enforced."""
        large_data = PREAMBLE + b'\x00' * 1000
        with pytest.raises(DecodeError) as exc:
            decode_module(large_data, limits=Limits(max_module_bytes=100))
        assert exc.value.code == 'size_limit'


class TestTypeSection:
    def test_empty_type_section(self):
        """Test empty type section."""
        data = PREAMBLE + b'\x01' + u32_leb(1) + u32_leb(0)  # section 1, size 1, vec len 0
        module = decode_module(data)
        assert len(module.types) == 0

    def test_simple_functype(self):
        """Test function type [] -> []."""
        data = PREAMBLE
        data += b'\x01'  # type section
        payload = u32_leb(0) + b'\x60' + u32_leb(0) + u32_leb(0)  # vec[functype]: 0 funcs, then one functype with no params/results
        payload = b'\x60' + u32_leb(0) + u32_leb(0)  # functype
        payload = u32_leb(1) + payload  # vec with 1 element
        data += u32_leb(len(payload)) + payload
        module = decode_module(data)
        assert len(module.types) == 1
        assert module.types[0].params == []
        assert module.types[0].results == []

    def test_functype_with_params_and_results(self):
        """Test function type [i32, i64] -> [i32]."""
        data = PREAMBLE + b'\x01'
        functype = b'\x60'
        functype += u32_leb(2) + b'\x7F\x7E'  # params: i32, i64
        functype += u32_leb(1) + b'\x7F'  # results: i32
        payload = u32_leb(1) + functype
        data += u32_leb(len(payload)) + payload
        module = decode_module(data)
        assert len(module.types) == 1
        assert module.types[0].params == ['i32', 'i64']
        assert module.types[0].results == ['i32']

    def test_unsupported_valtype(self):
        """Test that unsupported valtype (f32) raises DecodeError."""
        data = PREAMBLE + b'\x01'
        functype = b'\x60' + u32_leb(1) + b'\x7D' + u32_leb(0)  # 0x7D = f32
        payload = u32_leb(1) + functype
        data += u32_leb(len(payload)) + payload
        with pytest.raises(DecodeError) as exc:
            decode_module(data)
        assert exc.value.code == 'unsupported_valtype'


class TestSectionOrdering:
    def test_out_of_order_sections(self):
        """Test that out-of-order sections raise DecodeError."""
        # Try to put function section (3) before type section (1)
        data = PREAMBLE
        data += b'\x03' + u32_leb(1) + u32_leb(0)  # function section (empty)
        data += b'\x01' + u32_leb(1) + u32_leb(0)  # type section (empty)
        with pytest.raises(DecodeError) as exc:
            decode_module(data)
        assert exc.value.code == 'section_order'

    def test_custom_sections_allowed_anywhere(self):
        """Test that custom sections can appear anywhere."""
        data = PREAMBLE
        # Custom section before type
        custom1_payload = encode_name(b'a')
        data += b'\x00' + u32_leb(len(custom1_payload)) + custom1_payload
        # Type section
        type_payload = u32_leb(0)
        data += b'\x01' + u32_leb(len(type_payload)) + type_payload
        # Custom section after type
        custom2_payload = encode_name(b'b')
        data += b'\x00' + u32_leb(len(custom2_payload)) + custom2_payload
        # Function section
        func_payload = u32_leb(0)
        data += b'\x03' + u32_leb(len(func_payload)) + func_payload
        module = decode_module(data)
        assert len(module.customs) == 2
        assert module.customs[0].name == b'a'
        assert module.customs[1].name == b'b'


class TestImportSection:
    def test_import_func(self):
        """Test importing a function."""
        data = PREAMBLE
        # Type section: one functype [] -> []
        type_payload = u32_leb(1) + b'\x60' + u32_leb(0) + u32_leb(0)
        data += b'\x01' + u32_leb(len(type_payload)) + type_payload
        # Import section: import func from "env"."fn"
        imp = encode_name(b'env') + encode_name(b'fn') + b'\x00' + u32_leb(0)  # kind=func, typeidx=0
        import_payload = u32_leb(1) + imp
        data += b'\x02' + u32_leb(len(import_payload)) + import_payload
        module = decode_module(data)
        assert len(module.imports) == 1
        assert module.imports[0].module == b'env'
        assert module.imports[0].name == b'fn'
        assert module.imports[0].kind == 'func'
        assert module.imports[0].desc == 0

    def test_import_table(self):
        """Test importing a table."""
        data = PREAMBLE
        # Import section: import table
        imp = encode_name(b'env') + encode_name(b't') + b'\x01' + b'\x70' + b'\x00' + u32_leb(10)
        import_payload = u32_leb(1) + imp
        data += b'\x02' + u32_leb(len(import_payload)) + import_payload
        module = decode_module(data)
        assert len(module.imports) == 1
        assert module.imports[0].kind == 'table'
        assert module.imports[0].desc.elemtype == 'funcref'
        assert module.imports[0].desc.min == 10
        assert module.imports[0].desc.max is None

    def test_import_memory(self):
        """Test importing memory."""
        data = PREAMBLE
        # Import section: import memory with limits
        imp = encode_name(b'env') + encode_name(b'm') + b'\x02' + b'\x01' + u32_leb(1) + u32_leb(10)
        import_payload = u32_leb(1) + imp
        data += b'\x02' + u32_leb(len(import_payload)) + import_payload
        module = decode_module(data)
        assert len(module.imports) == 1
        assert module.imports[0].kind == 'mem'
        assert module.imports[0].desc.min == 1
        assert module.imports[0].desc.max == 10

    def test_import_global(self):
        """Test importing a global."""
        data = PREAMBLE
        # Import section: import mutable i32 global
        imp = encode_name(b'env') + encode_name(b'g') + b'\x03' + b'\x7F\x01'
        import_payload = u32_leb(1) + imp
        data += b'\x02' + u32_leb(len(import_payload)) + import_payload
        module = decode_module(data)
        assert len(module.imports) == 1
        assert module.imports[0].kind == 'global'
        assert module.imports[0].desc.valtype == 'i32'
        assert module.imports[0].desc.mutable is True


class TestExpressions:
    def test_simple_i32_const_expr(self):
        """Test expression with i32.const and end."""
        data = PREAMBLE
        # Type section
        type_payload = u32_leb(1) + b'\x60' + u32_leb(0) + u32_leb(0)
        data += b'\x01' + u32_leb(len(type_payload)) + type_payload
        # Global section with init expr
        globaltype = b'\x7F\x00'  # i32, immutable
        init_expr = b'\x41' + s32_leb(42) + b'\x0B'  # i32.const 42, end
        global_entry = globaltype + init_expr
        global_payload = u32_leb(1) + global_entry
        data += b'\x06' + u32_leb(len(global_payload)) + global_payload
        module = decode_module(data)
        assert len(module.globals) == 1
        assert module.globals[0].init.instrs[0].opcode == 0x41
        assert module.globals[0].init.instrs[0].immediate == 42
        assert module.globals[0].init.instrs[1].opcode == 0x0B

    def test_unsupported_opcode(self):
        """Test that unsupported opcode raises DecodeError."""
        data = PREAMBLE
        # Global section with bad opcode
        globaltype = b'\x7F\x00'
        init_expr = b'\x43\x00\x00\x00\x00' + b'\x0B'  # 0x43 = f32.const
        global_entry = globaltype + init_expr
        global_payload = u32_leb(1) + global_entry
        data += b'\x06' + u32_leb(len(global_payload)) + global_payload
        with pytest.raises(DecodeError) as exc:
            decode_module(data)
        assert exc.value.code == 'unsupported_opcode'


class TestCodeSection:
    def test_simple_function_body(self):
        """Test decoding a simple function body."""
        data = PREAMBLE
        # Type section: [] -> []
        type_payload = u32_leb(1) + b'\x60' + u32_leb(0) + u32_leb(0)
        data += b'\x01' + u32_leb(len(type_payload)) + type_payload
        # Function section: 1 function with typeidx 0
        func_payload = u32_leb(1) + u32_leb(0)
        data += b'\x03' + u32_leb(len(func_payload)) + func_payload
        # Code section: 1 function body
        func_body = u32_leb(0) + b'\x0B'  # no locals, just end
        func_body = u32_leb(len(func_body)) + func_body  # size prefix
        code_payload = u32_leb(1) + func_body
        data += b'\x0A' + u32_leb(len(code_payload)) + code_payload
        module = decode_module(data)
        assert len(module.code) == 1
        assert len(module.code[0].locals) == 0
        assert len(module.code[0].expr.instrs) == 1
        assert module.code[0].expr.instrs[0].opcode == 0x0B

    def test_function_with_locals(self):
        """Test function with local variables."""
        data = PREAMBLE
        # Type section
        type_payload = u32_leb(1) + b'\x60' + u32_leb(0) + u32_leb(0)
        data += b'\x01' + u32_leb(len(type_payload)) + type_payload
        # Function section
        func_payload = u32_leb(1) + u32_leb(0)
        data += b'\x03' + u32_leb(len(func_payload)) + func_payload
        # Code section with locals
        locals_decl = u32_leb(2) + b'\x7F'  # 2 locals of type i32
        func_body = u32_leb(1) + locals_decl + b'\x0B'  # 1 local decl, then end
        func_body = u32_leb(len(func_body)) + func_body
        code_payload = u32_leb(1) + func_body
        data += b'\x0A' + u32_leb(len(code_payload)) + code_payload
        module = decode_module(data)
        assert len(module.code[0].locals) == 1
        assert module.code[0].locals[0].count == 2
        assert module.code[0].locals[0].valtype == 'i32'


class TestValidation:
    def test_valid_module_passes(self):
        """Test that a valid module passes validation."""
        data = PREAMBLE
        # Type section: [] -> []
        type_payload = u32_leb(1) + b'\x60' + u32_leb(0) + u32_leb(0)
        data += b'\x01' + u32_leb(len(type_payload)) + type_payload
        # Function section
        func_payload = u32_leb(1) + u32_leb(0)
        data += b'\x03' + u32_leb(len(func_payload)) + func_payload
        # Code section
        func_body = u32_leb(0) + b'\x0B'
        func_body = u32_leb(len(func_body)) + func_body
        code_payload = u32_leb(1) + func_body
        data += b'\x0A' + u32_leb(len(code_payload)) + code_payload

        module = decode_module(data)
        errors = validate_module(module)
        assert len(errors) == 0

    def test_func_code_count_mismatch(self):
        """Test func/code count mismatch validation."""
        data = PREAMBLE
        # Type section
        type_payload = u32_leb(1) + b'\x60' + u32_leb(0) + u32_leb(0)
        data += b'\x01' + u32_leb(len(type_payload)) + type_payload
        # Function section: 2 functions
        func_payload = u32_leb(2) + u32_leb(0) + u32_leb(0)
        data += b'\x03' + u32_leb(len(func_payload)) + func_payload
        # Code section: 1 function (mismatch!)
        func_body = u32_leb(0) + b'\x0B'
        func_body = u32_leb(len(func_body)) + func_body
        code_payload = u32_leb(1) + func_body
        data += b'\x0A' + u32_leb(len(code_payload)) + code_payload

        module = decode_module(data)
        errors = validate_module(module)
        assert len(errors) == 1
        assert errors[0].code == 'func_code_count_mismatch'

    def test_duplicate_export_name(self):
        """Test duplicate export names validation."""
        data = PREAMBLE
        # Type section
        type_payload = u32_leb(1) + b'\x60' + u32_leb(0) + u32_leb(0)
        data += b'\x01' + u32_leb(len(type_payload)) + type_payload
        # Function section
        func_payload = u32_leb(2) + u32_leb(0) + u32_leb(0)
        data += b'\x03' + u32_leb(len(func_payload)) + func_payload
        # Export section: two exports with same name
        exp1 = encode_name(b'fn') + b'\x00' + u32_leb(0)
        exp2 = encode_name(b'fn') + b'\x00' + u32_leb(1)
        export_payload = u32_leb(2) + exp1 + exp2
        data += b'\x07' + u32_leb(len(export_payload)) + export_payload
        # Code section
        func_body = u32_leb(0) + b'\x0B'
        func_body = u32_leb(len(func_body)) + func_body
        code_payload = u32_leb(2) + func_body + func_body
        data += b'\x0A' + u32_leb(len(code_payload)) + code_payload

        module = decode_module(data)
        errors = validate_module(module)
        assert any(e.code == 'duplicate_export_name' for e in errors)

    def test_export_index_out_of_range(self):
        """Test export index out of range validation."""
        data = PREAMBLE
        # Type section
        type_payload = u32_leb(1) + b'\x60' + u32_leb(0) + u32_leb(0)
        data += b'\x01' + u32_leb(len(type_payload)) + type_payload
        # Function section: 1 function
        func_payload = u32_leb(1) + u32_leb(0)
        data += b'\x03' + u32_leb(len(func_payload)) + func_payload
        # Export section: export function index 5 (out of range)
        exp = encode_name(b'fn') + b'\x00' + u32_leb(5)
        export_payload = u32_leb(1) + exp
        data += b'\x07' + u32_leb(len(export_payload)) + export_payload
        # Code section
        func_body = u32_leb(0) + b'\x0B'
        func_body = u32_leb(len(func_body)) + func_body
        code_payload = u32_leb(1) + func_body
        data += b'\x0A' + u32_leb(len(code_payload)) + code_payload

        module = decode_module(data)
        errors = validate_module(module)
        assert any(e.code == 'index_out_of_range' for e in errors)

    def test_limits_min_gt_max(self):
        """Test limits validation (min > max)."""
        data = PREAMBLE
        # Table section with min > max
        table = b'\x70' + b'\x01' + u32_leb(10) + u32_leb(5)  # min=10, max=5
        table_payload = u32_leb(1) + table
        data += b'\x04' + u32_leb(len(table_payload)) + table_payload

        module = decode_module(data)
        errors = validate_module(module)
        assert any(e.code == 'limits_min_gt_max' for e in errors)

    def test_bad_start_signature(self):
        """Test start function with wrong signature."""
        data = PREAMBLE
        # Type section: [i32] -> []
        type_payload = u32_leb(1) + b'\x60' + u32_leb(1) + b'\x7F' + u32_leb(0)
        data += b'\x01' + u32_leb(len(type_payload)) + type_payload
        # Function section
        func_payload = u32_leb(1) + u32_leb(0)
        data += b'\x03' + u32_leb(len(func_payload)) + func_payload
        # Start section: function 0
        start_payload = u32_leb(0)
        data += b'\x08' + u32_leb(len(start_payload)) + start_payload
        # Code section
        func_body = u32_leb(0) + b'\x0B'
        func_body = u32_leb(len(func_body)) + func_body
        code_payload = u32_leb(1) + func_body
        data += b'\x0A' + u32_leb(len(code_payload)) + code_payload

        module = decode_module(data)
        errors = validate_module(module)
        assert any(e.code == 'bad_start_signature' for e in errors)

    def test_local_index_out_of_range(self):
        """Test local index out of range in function body."""
        data = PREAMBLE
        # Type section: [] -> []
        type_payload = u32_leb(1) + b'\x60' + u32_leb(0) + u32_leb(0)
        data += b'\x01' + u32_leb(len(type_payload)) + type_payload
        # Function section
        func_payload = u32_leb(1) + u32_leb(0)
        data += b'\x03' + u32_leb(len(func_payload)) + func_payload
        # Code section: local.get with out of range index
        func_body = u32_leb(0) + b'\x20' + u32_leb(10) + b'\x0B'  # local.get 10, end
        func_body = u32_leb(len(func_body)) + func_body
        code_payload = u32_leb(1) + func_body
        data += b'\x0A' + u32_leb(len(code_payload)) + code_payload

        module = decode_module(data)
        errors = validate_module(module)
        assert any(e.code == 'local_index_out_of_range' for e in errors)

    def test_call_index_out_of_range(self):
        """Test call index out of range in function body."""
        data = PREAMBLE
        # Type section: [] -> []
        type_payload = u32_leb(1) + b'\x60' + u32_leb(0) + u32_leb(0)
        data += b'\x01' + u32_leb(len(type_payload)) + type_payload
        # Function section
        func_payload = u32_leb(1) + u32_leb(0)
        data += b'\x03' + u32_leb(len(func_payload)) + func_payload
        # Code section: call with out of range funcidx
        func_body = u32_leb(0) + b'\x10' + u32_leb(10) + b'\x0B'  # call 10, end
        func_body = u32_leb(len(func_body)) + func_body
        code_payload = u32_leb(1) + func_body
        data += b'\x0A' + u32_leb(len(code_payload)) + code_payload

        module = decode_module(data)
        errors = validate_module(module)
        assert any(e.code == 'index_out_of_range' for e in errors)

    def test_type_index_out_of_range(self):
        """Test type index out of range."""
        data = PREAMBLE
        # Type section: 1 type
        type_payload = u32_leb(1) + b'\x60' + u32_leb(0) + u32_leb(0)
        data += b'\x01' + u32_leb(len(type_payload)) + type_payload
        # Function section: reference type index 5 (out of range)
        func_payload = u32_leb(1) + u32_leb(5)
        data += b'\x03' + u32_leb(len(func_payload)) + func_payload
        # Code section
        func_body = u32_leb(0) + b'\x0B'
        func_body = u32_leb(len(func_body)) + func_body
        code_payload = u32_leb(1) + func_body
        data += b'\x0A' + u32_leb(len(code_payload)) + code_payload

        module = decode_module(data)
        errors = validate_module(module)
        assert any(e.code == 'type_index_out_of_range' for e in errors)

    def test_data_count_mismatch(self):
        """Test data count mismatch validation."""
        data = PREAMBLE
        # Memory section
        mem_payload = u32_leb(1) + b'\x00' + u32_leb(1)
        data += b'\x05' + u32_leb(len(mem_payload)) + mem_payload
        # Data section: only 1 segment
        data_seg = u32_leb(0) + b'\x41' + s32_leb(0) + b'\x0B' + encode_name(b'hello')
        data_payload = u32_leb(1) + data_seg
        data += b'\x0B' + u32_leb(len(data_payload)) + data_payload
        # Data count section: says 2 segments
        datacount_payload = u32_leb(2)
        data += b'\x0C' + u32_leb(len(datacount_payload)) + datacount_payload

        module = decode_module(data)
        errors = validate_module(module)
        assert any(e.code == 'data_count_mismatch' for e in errors)


class TestElementAndDataSegments:
    def test_element_segment(self):
        """Test decoding element segment."""
        data = PREAMBLE
        # Type section
        type_payload = u32_leb(1) + b'\x60' + u32_leb(0) + u32_leb(0)
        data += b'\x01' + u32_leb(len(type_payload)) + type_payload
        # Function section
        func_payload = u32_leb(1) + u32_leb(0)
        data += b'\x03' + u32_leb(len(func_payload)) + func_payload
        # Table section
        table = b'\x70\x00' + u32_leb(10)
        table_payload = u32_leb(1) + table
        data += b'\x04' + u32_leb(len(table_payload)) + table_payload
        # Element section
        elem = u32_leb(0) + b'\x41' + s32_leb(0) + b'\x0B' + u32_leb(1) + u32_leb(0)
        elem_payload = u32_leb(1) + elem
        data += b'\x09' + u32_leb(len(elem_payload)) + elem_payload
        # Code section
        func_body = u32_leb(0) + b'\x0B'
        func_body = u32_leb(len(func_body)) + func_body
        code_payload = u32_leb(1) + func_body
        data += b'\x0A' + u32_leb(len(code_payload)) + code_payload

        module = decode_module(data)
        assert len(module.elems) == 1
        assert module.elems[0].tableidx == 0
        assert module.elems[0].init == [0]

    def test_data_segment(self):
        """Test decoding data segment."""
        data = PREAMBLE
        # Memory section
        mem_payload = u32_leb(1) + b'\x00' + u32_leb(1)
        data += b'\x05' + u32_leb(len(mem_payload)) + mem_payload
        # Data section
        data_seg = u32_leb(0) + b'\x41' + s32_leb(0) + b'\x0B' + encode_name(b'hello')
        data_payload = u32_leb(1) + data_seg
        data += b'\x0B' + u32_leb(len(data_payload)) + data_payload

        module = decode_module(data)
        assert len(module.datas) == 1
        assert module.datas[0].memidx == 0
        assert module.datas[0].data == b'hello'

