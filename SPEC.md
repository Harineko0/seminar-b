# External Specification: `wasm_sv` — WASM Binary Module Decoder + Structural Validator

## 0) Purpose

Given a byte string `data` representing a WebAssembly binary module, the program must:

1. **Decode** it into a structured **Module** value (AST).
2. **Validate** the decoded module with **structural rules** (counts, indices, ordering, limits, and restricted forms described below).
3. Produce deterministic, typed errors for malformed input.

This is **not** a compiler or interpreter. It never executes WASM.

---

## 1) Binary module envelope

### 1.1 Preamble

A valid module begins with:

* Magic: `00 61 73 6D`
* Version: `01 00 00 00`

If either differs → decoding fails with a `DecodeError`.

### 1.2 Sections

After the preamble, the module is a sequence of sections. Each section is encoded as:

* `section_id: 1 byte`
* `payload_len: u32` (unsigned LEB128)
* `payload: payload_len bytes`

Decoder must not read past the module length or past a section’s payload.

Unknown `section_id` values (except custom section `0`) are **not supported** and must cause `DecodeError(unknown_section_id)`.

---

## 2) Integer and vector encodings

### 2.1 Unsigned LEB128 for `u32`

All lengths, counts, and indices are decoded as unsigned LEB128 `u32`.

* If the integer encoding is truncated, overlong for `u32`, or does not fit in `u32` → `DecodeError`.

### 2.2 `vec<T>`

A vector is encoded as:

* `n: u32`
* followed by `n` repetitions of `T`

### 2.3 `name`

A `name` is:

* `byte_len: u32`
* `byte_len` raw bytes

Names are treated as **opaque bytes** (no UTF-8 requirement).

---

## 3) Supported sections (subset)

The decoder supports these section IDs:

0 custom, 1 type, 2 import, 3 function, 4 table, 5 memory, 6 global, 7 export, 8 start, 9 element (subset), 10 code (subset), 11 data (subset), 12 data count.

### 3.1 Section ordering

* Custom sections (id=0) may appear **anywhere**.
* Each non-custom section may appear **at most once** and must appear in the canonical WASM order (Type → Import → Function → Table → Memory → Global → Export → Start → Element → Code → Data → DataCount).
  If violated → `DecodeError(section_order)`.

### 3.2 Section payload exactness

If the decoder finishes parsing a section and there are leftover bytes in that section payload, or parsing requires more bytes than available → `DecodeError(section_size_mismatch)`.

---

## 4) Type section (id=1)

Type section payload is `vec<functype>`.

### 4.1 Value types

Only these `valtype` bytes are supported:

* `i32 (0x7F)`
* `i64 (0x7E)`

Other valtypes → `DecodeError(unsupported_valtype)`.

### 4.2 Function type

A `functype` is encoded as:

* `0x60`
* `params: vec<valtype>`
* `results: vec<valtype>`

The decoded module stores `types: list[FuncType(params, results)]`.

---

## 5) Import section (id=2)

Import section payload is `vec<import>`.

Each `import` is:

* `module: name`
* `name: name`
* `kind: byte` (0=func, 1=table, 2=mem, 3=global)
* descriptor depends on kind:

### 5.1 Import func

* `typeidx: u32` (must be validated later)

### 5.2 Import table

* `elemtype: byte` must be `funcref (0x70)` else `DecodeError(unsupported_table_elemtype)`
* `limits` (see §7)

### 5.3 Import memory

* `limits` (see §7)

### 5.4 Import global

* `valtype` (restricted per §4.1)
* `mutability: byte` (`0x00` immutable, `0x01` mutable; otherwise `DecodeError(bad_mutability)`)

---

## 6) Function section (id=3)

Function section payload is `vec<typeidx>`, one entry per **defined** function (imports are not included here).

---

## 7) Table section (id=4) and Memory section (id=5)

### 7.1 Limits encoding

Limits are:

* `flags: byte`

  * `0x00`: `min: u32`
  * `0x01`: `min: u32`, `max: u32`
  * other flags → `DecodeError(bad_limits_flag)`

### 7.2 Limits validation

If `max` exists, must have `min <= max` else `ValidationError(limits_min_gt_max)`.

### 7.3 Table type

Table entries are:

* `elemtype: byte` must be `funcref (0x70)` else `DecodeError(unsupported_table_elemtype)`
* `limits`

Memory entries are:

* `limits`

---

## 8) Global section (id=6)

Global section payload is `vec<global>`.

Each global:

* `GlobalType`: `valtype` (restricted) + `mutability` (0x00/0x01)
* `init_expr`: **restricted expression** (see §11)

---

## 9) Export section (id=7)

Export section payload is `vec<export>`.

Each export:

* `name: name`
* `kind: byte` (0=func, 1=table, 2=mem, 3=global)
* `index: u32`

Validation:

* Export names (byte-wise) must be **unique** else `ValidationError(duplicate_export_name)`.
* `index` must be in range for its kind’s index space (see §12) else `ValidationError(index_out_of_range)`.

---

## 10) Start section (id=8)

Start section payload is:

* `funcidx: u32`

Validation:

* `funcidx` must be `< funcs_total` (see §12) else `ValidationError(index_out_of_range)`.
* The start function’s resolved type must be `params=[]` and `results=[]` else `ValidationError(bad_start_signature)`.

---

## 11) Expression and Code (restricted instruction subset)

### 11.1 Supported opcodes

Only these opcodes are valid:

* `0x41 i32.const` with immediate `s32` (signed LEB128) *(or equivalently define it as u32 if you want; whichever is chosen is the spec)*
* `0x20 local.get` with `localidx: u32`
* `0x21 local.set` with `localidx: u32`
* `0x6A i32.add` no immediate
* `0x10 call` with `funcidx: u32`
* `0x0B end` terminator

Any other opcode → `DecodeError(unsupported_opcode)`.

### 11.2 Expression termination

An expression is a sequence of supported instructions that **must end** with `end (0x0B)`.

* If `end` is missing → `DecodeError(missing_end)`
* If bytes remain in the expression container after `end` → `DecodeError(trailing_bytes_in_expr)`

### 11.3 Local index validation

For each function body expression:

* `localidx` in `local.get/set` must be `< (num_params + num_locals)` else `ValidationError(local_index_out_of_range)`.

### 11.4 Call index validation

For each function body expression:

* `funcidx` in `call` must be `< funcs_total` (see §12) else `ValidationError(index_out_of_range)`.

---

## 12) Index spaces for validation

Index spaces are computed as **imports first, then definitions**:

* `funcs_total = imported_funcs + defined_funcs`
* `tables_total = imported_tables + defined_tables`
* `mems_total = imported_mems + defined_mems`
* `globals_total = imported_globals + defined_globals`

Validation must use these totals for:

* exports
* start
* calls
* element init func indices

---

## 13) Code section (id=10)

Code section payload is `vec<funcbody>`.

Each `funcbody`:

* `body_size: u32`
* `body_bytes: body_size bytes` parsed as:

  * `locals: vec<localdecl>`
  * `expr: expression` (restricted per §11)

Each `localdecl`:

* `count: u32`
* `valtype` (restricted per §4.1)

Validation:

* `len(code_bodies) == len(function_type_indices)` else `ValidationError(func_code_count_mismatch)`.

---

## 14) Element section (id=9) — subset only

Element section payload is `vec<elemseg>`.

Only this form is supported:

* `tableidx: u32` must equal `0` else `DecodeError(unsupported_element_form)`
* `offset_expr` must be exactly: `i32.const <u32-or-s32> ; end` (one const then end) else `DecodeError(unsupported_element_form)`
* `init: vec<funcidx>`

Validation:

* Each `funcidx` in `init` must be `< funcs_total` else `ValidationError(index_out_of_range)`.

Any other element segment encoding/form → `DecodeError(unsupported_element_form)`.

---

## 15) Data section (id=11) — subset only

Data section payload is `vec<dataseg>`.

Only this form is supported:

* `memidx: u32` must equal `0` else `DecodeError(unsupported_data_form)`
* `offset_expr` must be exactly: `i32.const <u32-or-s32> ; end` else `DecodeError(unsupported_data_form)`
* `bytes` is a length-prefixed raw byte string (`u32` length + bytes)

Any other data segment encoding/form → `DecodeError(unsupported_data_form)`.

---

## 16) Data Count section (id=12)

Payload is:

* `count: u32`

Validation:

* If data count section exists, it must equal `len(data_segments)` else `ValidationError(data_count_mismatch)`.

---

## 17) Validation summary (must produce these classes of errors)

The validator must detect and report at least:

* `limits_min_gt_max`
* `index_out_of_range` (exports/start/call/elem init)
* `func_code_count_mismatch`
* `duplicate_export_name`
* `bad_start_signature`
* `local_index_out_of_range`
* `data_count_mismatch`
* `type_index_out_of_range` (any typeidx >= len(types))

Decoding errors (malformed bytes) must be distinct from validation errors (well-formed but invalid module).

---

## 18) Required behaviors on arbitrary bytes

For any `data: bytes` input:

* The decoder must either return a Module AST or fail with a `DecodeError` (no crashes, no hangs).
* If decoding succeeds, validation must either return “valid” or a finite list of `ValidationError` (no crashes, no hangs).
