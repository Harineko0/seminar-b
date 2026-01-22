# Project Spec: `wasm_sv` — WASM Binary Module Parser + Structural Validator (Python)

## 0) Goal

Implement a library that can:

1. **Decode** a WebAssembly **binary module** (`.wasm` bytes) into an **AST** (Python dataclasses).
2. **Validate (structurally)** the decoded module with a deterministic set of rules (counts, indices, section order, basic type consistency), producing **typed validation errors**.

**Not a compiler, not an interpreter.** No execution.

---

## 1) Standards baseline (what we follow)

* Binary module preamble is:

  * magic bytes: `00 61 73 6D` (`\0asm`)
  * version bytes: `01 00 00 00` (binary format version 1) ([webassembly.github.io][1])
* Module is a sequence of **sections**, each encoded as:

  * `section_id: byte`
  * `payload_len: u32` (LEB128)
  * `payload_bytes: payload_len bytes` ([webassembly.github.io][1])
* Unsigned integers are **unsigned LEB128**, with a size constraint (e.g., `u32` must fit within `ceil(32/7)=5` bytes). ([webassembly.github.io][2])

---

## 2) Scope: supported sections and “subset semantics”

We implement **parsing + structural validation** for these section IDs:

| ID | Section                                    |
| -: | ------------------------------------------ |
|  0 | Custom                                     |
|  1 | Type                                       |
|  2 | Import                                     |
|  3 | Function                                   |
|  4 | Table                                      |
|  5 | Memory                                     |
|  6 | Global                                     |
|  7 | Export                                     |
|  8 | Start                                      |
|  9 | Element *(subset form only; see below)*    |
| 10 | Code *(subset instruction set; see below)* |
| 11 | Data *(subset form only; see below)*       |
| 12 | Data Count                                 |

Section IDs and their meaning are per spec. ([webassembly.github.io][1])

### 2.1 Required section ordering rule

* **Custom sections (id=0)** may appear **anywhere**.
* **Non-custom sections** must appear **at most once** and in the **prescribed order** (the canonical order used by the spec’s module grammar). ([webassembly.github.io][1])

### 2.2 Required cross-section count constraints

* `len(function_section) == len(code_section)` (defined function declarations match bodies). ([webassembly.github.io][1])
* If `data_count` section is present, it **must equal** `len(data_section)`. ([webassembly.github.io][1])

---

## 3) Binary encoding primitives (must implement)

### 3.1 LEB128

Implement:

* `read_u32()` for indices, lengths, counts, limits, etc.
* Enforce **max byte length** for the decoded integer type (u32 <= 5 bytes). ([webassembly.github.io][2])
* If the LEB128 sequence is truncated, overlong, or runs past the section boundary → `DecodeError`.

### 3.2 Vectors (“lists”)

Implement `vec<T>` as:

* `n: u32`
* followed by `n` repetitions of `T`

### 3.3 Names

`name` is:

* `byte_len: u32`
* followed by `byte_len` raw bytes

Validation policy:

* **Do not require UTF-8**; treat as opaque bytes (store and compare by bytes). (This avoids turning the project into a Unicode validator.)

---

## 4) AST model (required)

Define dataclasses for:

### 4.1 Types

* `ValType`: allow only `i32 (0x7F)`, `i64 (0x7E)` (restrict on purpose to keep type-space bounded).
* `FuncType`: `(params: list[ValType], results: list[ValType])`
* Type section: `types: list[FuncType]` where each entry is encoded with the function type constructor (`0x60`).

### 4.2 Imports

Each import has:

* `module_name: bytes`
* `name: bytes`
* `kind: {func, table, mem, global}`
* kind-specific descriptor:

  * func: `typeidx: u32`
  * table: `TableType`
  * mem: `MemType`
  * global: `GlobalType`

### 4.3 Tables / Memory (limits)

Represent limits as:

* `min: u32`
* optional `max: u32`
  Validation requires `min <= max` if max present.

Scope restrictions:

* Table element type: allow only `funcref` (0x70).
* Memory is page-based; we *only* validate min/max ordering (no engine-dependent maximum).

### 4.4 Globals

* `GlobalType(valtype, mutable: bool)`
* `init_expr` (see restricted instruction subset)

### 4.5 Functions

* Function section: `func_type_indices: list[typeidx]` (for **defined** funcs only)
* Code section: `func_bodies: list[FuncBody]`
* `FuncBody(locals: list[LocalDecl], expr: Expr)`
* `LocalDecl(count: u32, valtype: ValType)`

### 4.6 Exports

* `name: bytes`
* `kind: {func, table, mem, global}`
* `index: u32`

### 4.7 Start

* `start_funcidx: u32`

### 4.8 Element segments (subset)

To force nontrivial parsing/validation without implementing all proposals, define element segment support as:

**Only “active element segment for table 0”** with:

* `tableidx` must be `0`
* `offset_expr` must be exactly: `i32.const <u32> ; end`
* `init` is `vec<funcidx>`

Any other element segment encoding → `DecodeError` (“unsupported element segment form”).

### 4.9 Data segments (subset)

Similarly, only support:

**Only “active data segment for memory 0”** with:

* `memidx` must be `0`
* `offset_expr` must be exactly: `i32.const <u32> ; end`
* `bytes: vec<byte>` (or `u32` length + raw bytes)

Any other data segment encoding → `DecodeError` (“unsupported data segment form”).

### 4.10 Expressions / instructions (restricted set)

To keep code parsing meaningful but bounded, implement decoding for this instruction subset:

| Opcode | Instruction | Immediate                                                          |
| -----: | ----------- | ------------------------------------------------------------------ |
|   0x41 | `i32.const` | `s32` (LEB128 signed) *(or restrict further to u32 if you prefer)* |
|   0x20 | `local.get` | `localidx: u32`                                                    |
|   0x21 | `local.set` | `localidx: u32`                                                    |
|   0x6A | `i32.add`   | none                                                               |
|   0x10 | `call`      | `funcidx: u32`                                                     |
|   0x0B | `end`       | none                                                               |

Expression decoding rule:

* Read instructions until the first `end (0x0B)` and stop there.
* Any remaining bytes inside the expression container after `end` → `DecodeError` (non-canonical / trailing garbage).

**Note:** This is intentionally stricter than “unknown opcodes allowed”. It makes the oracle crisp and keeps symbolic execution interesting.

---

## 5) Decoder requirements (must)

### 5.1 Section boundary discipline

Decoder must never read past:

* the module byte length, or
* a section payload boundary (`payload_len`)

If the payload bytes do not match the decoded content length → module is malformed. ([webassembly.github.io][1])

### 5.2 Unknown section IDs

* If `section_id` is not one of the supported IDs **and is not 0 (custom)** → `DecodeError(unknown_section_id)`.

### 5.3 Custom section

Parse as:

* `name: name`
* `payload_rest: bytes` (raw)
  Do not validate its contents or placement beyond basic section-length correctness. ([webassembly.github.io][1])

---

## 6) Structural validator requirements (must)

Validation consumes the **decoded AST** and returns a list of `ValidationError` (or raises one aggregated error).

### 6.1 Index spaces

Build index spaces with imports first, then definitions, per WASM conventions:

* `funcs_total = imported_funcs + defined_funcs`
* `tables_total = imported_tables + defined_tables`
* `mems_total = imported_mems + defined_mems`
* `globals_total = imported_globals + defined_globals`

### 6.2 Validate indices

* Every `typeidx` used by:

  * imported func descriptors
  * function section entries
    must be `< len(types)`.
* Every export index must be within the appropriate index space:

  * export func index `< funcs_total`, etc.
* `start_funcidx < funcs_total`

### 6.3 Validate function/code linkage

* Already enforced at decode time if you want, but validator must ensure:

  * `len(func_type_indices) == len(func_bodies)` ([webassembly.github.io][1])

### 6.4 Validate export name uniqueness

* Export `name` bytes must be **unique** across all exports.

### 6.5 Validate limits

* For each table/memory limit with max: `min <= max`.

### 6.6 Validate start function signature (restricted)

Start function must have type:

* `params == []` and `results == []`

Where the function’s type is resolved through its `typeidx` in the type section.

### 6.7 Validate restricted instruction immediates

For each function body and init expr:

* `local.get/set localidx` must be `< number_of_locals_including_params`
* `call funcidx` must be `< funcs_total`

(We do **not** do stack type-checking; this is “structural + bounds” validation.)

### 6.8 Data count consistency

If `data_count` exists:

* it must equal `len(data_segments)` ([webassembly.github.io][1])

---

## 7) Resource limits (must; to prevent DoS / path explosion)

All decoders must accept a `Limits` object, defaulting to conservative values, e.g.:

* `max_module_bytes` (e.g., 1 MiB)
* `max_section_bytes` (e.g., 512 KiB)
* `max_vector_length` (e.g., 50_000)
* `max_function_body_bytes` (e.g., 64 KiB)
* `max_locals_per_function` (e.g., 10_000)
* `max_custom_section_bytes` (e.g., 256 KiB)

Exceeding limits → `DecodeError(limit_exceeded)` with offset.

---

## 8) Public API (must)

Provide these stable entry points:

```python
def decode_module(data: bytes, *, limits: Limits = Limits()) -> Module: ...
def validate_module(module: Module) -> list[ValidationError]: ...
def decode_and_validate(data: bytes, *, limits: Limits = Limits()) -> Module: ...
```

* `decode_and_validate` must raise if validation errors exist (or return a `(module, errors)` variant—pick one and lock it).

Errors must include:

* category enum/code
* byte offset (where available)
* human-readable message
