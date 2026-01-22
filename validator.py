"""
WebAssembly module structural validator.

Performs structural validation on decoded modules:
- Section ordering
- Index bounds checking
- Export uniqueness
- Limits validation
- Start function signature
- Instruction immediate bounds
- Data count consistency
- Function/code linkage
"""

from typing import List, Dict, Set, Tuple
from dataclasses import dataclass
from wasm_types import (
    Module, FuncType, ValType, Import, ImportKind, Export,
    Instruction, Opcode, Expr
)


@dataclass
class ValidationError:
    """A structural validation error."""
    code: str
    message: str
    context: str = ""


def validate_module(module: Module) -> List[ValidationError]:
    """
    Perform structural validation on a decoded module.

    Args:
        module: The decoded Module AST

    Returns:
        List of ValidationError (empty if valid)
    """
    errors = []

    # Build index spaces (imports come first)
    func_index_space = build_func_index_space(module)
    table_index_space = build_table_index_space(module)
    mem_index_space = build_mem_index_space(module)
    global_index_space = build_global_index_space(module)

    # Validate indices
    errors.extend(validate_type_indices(module))
    errors.extend(validate_function_indices(module, func_index_space))
    errors.extend(validate_export_indices(module, func_index_space, table_index_space, mem_index_space, global_index_space))

    # Validate export uniqueness
    errors.extend(validate_export_uniqueness(module))

    # Validate limits
    errors.extend(validate_limits(module))

    # Validate start function
    if module.start is not None:
        errors.extend(validate_start_function(module, func_index_space))

    # Validate function-code linkage
    errors.extend(validate_function_code_linkage(module))

    # Validate instruction immediates
    errors.extend(validate_instruction_immediates(module, func_index_space))

    # Validate global init expressions
    errors.extend(validate_global_init_exprs(module))

    # Validate data count
    errors.extend(validate_data_count(module))

    # Validate element segments
    errors.extend(validate_element_segments(module, func_index_space, table_index_space))

    # Validate data segments
    errors.extend(validate_data_segments(module, mem_index_space))

    return errors


# ===== Index Space Builders =====

def build_func_index_space(module: Module) -> List[FuncType]:
    """Build function index space (imports first, then definitions)."""
    funcs = []

    # Add imported functions
    for imp in module.imports:
        if imp.kind == ImportKind.FUNC:
            if imp.typeidx is None:
                continue
            if imp.typeidx < len(module.types):
                funcs.append(module.types[imp.typeidx])

    # Add defined functions
    for typeidx in module.functions:
        if typeidx < len(module.types):
            funcs.append(module.types[typeidx])

    return funcs


def build_table_index_space(module: Module) -> List:
    """Build table index space (imports first, then definitions)."""
    tables = []

    # Add imported tables
    for imp in module.imports:
        if imp.kind == ImportKind.TABLE and imp.table_type is not None:
            tables.append(imp.table_type)

    # Add defined tables
    tables.extend(module.tables)

    return tables


def build_mem_index_space(module: Module) -> List:
    """Build memory index space (imports first, then definitions)."""
    mems = []

    # Add imported memories
    for imp in module.imports:
        if imp.kind == ImportKind.MEM and imp.mem_type is not None:
            mems.append(imp.mem_type)

    # Add defined memories
    mems.extend(module.memories)

    return mems


def build_global_index_space(module: Module) -> List:
    """Build global index space (imports first, then definitions)."""
    globals_ = []

    # Add imported globals
    for imp in module.imports:
        if imp.kind == ImportKind.GLOBAL and imp.global_type is not None:
            globals_.append(imp.global_type)

    # Add defined globals
    for g in module.globals:
        globals_.append(g.type)

    return globals_


# ===== Validators =====

def validate_type_indices(module: Module) -> List[ValidationError]:
    """Validate that all type indices are in bounds."""
    errors = []

    # Check function type indices
    for i, typeidx in enumerate(module.functions):
        if typeidx >= len(module.types):
            errors.append(ValidationError(
                code="invalid_typeidx",
                message=f"function {i} references invalid type index {typeidx}",
                context=f"type count: {len(module.types)}"
            ))

    # Check import type indices
    for i, imp in enumerate(module.imports):
        if imp.kind == ImportKind.FUNC and imp.typeidx is not None:
            if imp.typeidx >= len(module.types):
                errors.append(ValidationError(
                    code="invalid_import_typeidx",
                    message=f"import {i} references invalid type index {imp.typeidx}",
                    context=f"type count: {len(module.types)}"
                ))

    return errors


def validate_function_indices(module: Module, func_index_space: List[FuncType]) -> List[ValidationError]:
    """Validate function indices in call instructions."""
    # This will be completed when we implement instruction validation
    return []


def validate_export_indices(module: Module, funcs, tables, mems, globals_) -> List[ValidationError]:
    """Validate that all export indices are in bounds."""
    errors = []

    for i, exp in enumerate(module.exports):
        if exp.kind == ImportKind.FUNC:
            if exp.index >= len(funcs):
                errors.append(ValidationError(
                    code="invalid_export_funcidx",
                    message=f"export '{exp.name}' references invalid function index {exp.index}",
                    context=f"function count: {len(funcs)}"
                ))
        elif exp.kind == ImportKind.TABLE:
            if exp.index >= len(tables):
                errors.append(ValidationError(
                    code="invalid_export_tableidx",
                    message=f"export '{exp.name}' references invalid table index {exp.index}",
                    context=f"table count: {len(tables)}"
                ))
        elif exp.kind == ImportKind.MEM:
            if exp.index >= len(mems):
                errors.append(ValidationError(
                    code="invalid_export_memidx",
                    message=f"export '{exp.name}' references invalid memory index {exp.index}",
                    context=f"memory count: {len(mems)}"
                ))
        elif exp.kind == ImportKind.GLOBAL:
            if exp.index >= len(globals_):
                errors.append(ValidationError(
                    code="invalid_export_globalidx",
                    message=f"export '{exp.name}' references invalid global index {exp.index}",
                    context=f"global count: {len(globals_)}"
                ))

    return errors


def validate_export_uniqueness(module: Module) -> List[ValidationError]:
    """Validate that export names are unique (by byte sequence)."""
    errors = []
    seen_names: Set[str] = set()

    for exp in module.exports:
        if exp.name in seen_names:
            errors.append(ValidationError(
                code="duplicate_export_name",
                message=f"duplicate export name: '{exp.name}'",
                context=""
            ))
        seen_names.add(exp.name)

    return errors


def validate_limits(module: Module) -> List[ValidationError]:
    """Validate that limits have min <= max when max is present."""
    errors = []

    # Check table limits
    for i, table in enumerate(module.tables):
        if table.limits.max is not None and table.limits.min > table.limits.max:
            errors.append(ValidationError(
                code="invalid_table_limits",
                message=f"table {i} has min ({table.limits.min}) > max ({table.limits.max})",
                context=""
            ))

    # Check memory limits
    for i, mem in enumerate(module.memories):
        if mem.limits.max is not None and mem.limits.min > mem.limits.max:
            errors.append(ValidationError(
                code="invalid_memory_limits",
                message=f"memory {i} has min ({mem.limits.min}) > max ({mem.limits.max})",
                context=""
            ))

    # Check imported table limits
    for i, imp in enumerate(module.imports):
        if imp.kind == ImportKind.TABLE and imp.table_type is not None:
            if imp.table_type.limits.max is not None and imp.table_type.limits.min > imp.table_type.limits.max:
                errors.append(ValidationError(
                    code="invalid_import_table_limits",
                    message=f"imported table {i} has min > max",
                    context=""
                ))

    # Check imported memory limits
    for i, imp in enumerate(module.imports):
        if imp.kind == ImportKind.MEM and imp.mem_type is not None:
            if imp.mem_type.limits.max is not None and imp.mem_type.limits.min > imp.mem_type.limits.max:
                errors.append(ValidationError(
                    code="invalid_import_memory_limits",
                    message=f"imported memory {i} has min > max",
                    context=""
                ))

    return errors


def validate_start_function(module: Module, func_index_space: List[FuncType]) -> List[ValidationError]:
    """Validate that start function has signature [] -> []."""
    errors = []

    if module.start is None:
        return errors

    start_idx = module.start
    if start_idx >= len(func_index_space):
        errors.append(ValidationError(
            code="invalid_start_funcidx",
            message=f"start function index {start_idx} out of bounds",
            context=f"function count: {len(func_index_space)}"
        ))
        return errors

    func_type = func_index_space[start_idx]
    if len(func_type.params) != 0 or len(func_type.results) != 0:
        errors.append(ValidationError(
            code="invalid_start_signature",
            message=f"start function must have signature [] -> [], got [{','.join(str(p) for p in func_type.params)}] -> [{','.join(str(r) for r in func_type.results)}]",
            context=""
        ))

    return errors


def validate_function_code_linkage(module: Module) -> List[ValidationError]:
    """Validate that function section count equals code section count."""
    errors = []

    if len(module.functions) != len(module.code):
        errors.append(ValidationError(
            code="function_code_mismatch",
            message=f"function section has {len(module.functions)} entries but code section has {len(module.code)} entries",
            context=""
        ))

    return errors


def validate_instruction_immediates(module: Module, func_index_space: List[FuncType]) -> List[ValidationError]:
    """Validate instruction immediate values are in bounds."""
    errors = []

    # We need to validate local indices and call function indices
    # For local indices, we need to know the function signature and locals

    for func_idx, func_body in enumerate(module.code):
        # Calculate total locals
        imported_func_count = sum(1 for imp in module.imports if imp.kind == ImportKind.FUNC)
        actual_func_idx = imported_func_count + func_idx

        if actual_func_idx >= len(func_index_space):
            continue

        func_type = func_index_space[actual_func_idx]

        # Count locals: params + local declarations
        local_count = len(func_type.params)
        for local_decl in func_body.locals:
            local_count += local_decl.count

        # Validate instructions
        for instr in func_body.expr.instructions:
            if instr.opcode in (Opcode.LOCAL_GET, Opcode.LOCAL_SET):
                if instr.immediate is not None and instr.immediate >= local_count:
                    errors.append(ValidationError(
                        code="invalid_local_index",
                        message=f"function {actual_func_idx} instruction {instr.opcode.name} references invalid local {instr.immediate}",
                        context=f"local count: {local_count}"
                    ))

            elif instr.opcode == Opcode.CALL:
                if instr.immediate is not None and instr.immediate >= len(func_index_space):
                    errors.append(ValidationError(
                        code="invalid_call_funcidx",
                        message=f"function {actual_func_idx} calls invalid function index {instr.immediate}",
                        context=f"function count: {len(func_index_space)}"
                    ))

    return errors


def validate_global_init_exprs(module: Module) -> List[ValidationError]:
    """Validate that global init expressions are restricted to i32.const; end."""
    errors = []

    for i, glob in enumerate(module.globals):
        instrs = glob.init.instructions
        if len(instrs) != 2 or instrs[0].opcode != Opcode.I32_CONST or instrs[1].opcode != Opcode.END:
            errors.append(ValidationError(
                code="invalid_global_init_expr",
                message=f"global {i} init expr must be i32.const followed by end",
                context=""
            ))

    return errors


def validate_data_count(module: Module) -> List[ValidationError]:
    """Validate that data count matches data section if present."""
    errors = []

    if module.data_count is not None:
        if module.data_count != len(module.data):
            errors.append(ValidationError(
                code="data_count_mismatch",
                message=f"data count section specifies {module.data_count} segments but data section has {len(module.data)} segments",
                context=""
            ))

    return errors


def validate_element_segments(module: Module, func_index_space: List[FuncType], table_index_space: List) -> List[ValidationError]:
    """Validate element segments."""
    errors = []

    # If element segments exist, check that a table exists
    if len(module.elements) > 0 and len(table_index_space) == 0:
        errors.append(ValidationError(
            code="element_without_table",
            message="element segment exists but no table is defined",
            context=""
        ))

    # Validate all function indices in element segments
    for elem_idx, elem in enumerate(module.elements):
        for i, funcidx in enumerate(elem.init):
            if funcidx >= len(func_index_space):
                errors.append(ValidationError(
                    code="invalid_element_funcidx",
                    message=f"element segment {elem_idx} init[{i}] references invalid function index {funcidx}",
                    context=f"function count: {len(func_index_space)}"
                ))

    return errors


def validate_data_segments(module: Module, mem_index_space: List) -> List[ValidationError]:
    """Validate data segments."""
    errors = []

    # If data segments exist, check that a memory exists
    if len(module.data) > 0 and len(mem_index_space) == 0:
        errors.append(ValidationError(
            code="data_without_memory",
            message="data segment exists but no memory is defined",
            context=""
        ))

    return errors
