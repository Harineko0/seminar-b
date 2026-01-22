---
name: crosshair
description: Use pschanely/CrossHair (crosshair-tool) to find contract counterexamples, generate high-coverage inputs/tests, and prove refactors equivalent via diffbehavior.
triggers:
  - crosshair
  - symbolic execution
  - contract checking
  - design by contract
  - cover
  - diffbehavior
  - "crosshair check"
  - "crosshair watch"
tools:
  - Read
  - Grep
  - Glob
  - Edit
  - Write
  - Bash
---

# CrossHair (pschanely/CrossHair) Skill

CrossHair repeatedly executes Python functions with **symbolic inputs** and uses an SMT solver (Z3) to explore paths and find **counterexamples**. It’s “best-effort”: no counterexample ≠ proven correct.

## Guardrails (must follow)
- Run CrossHair **in the project’s Python environment** (same venv/conda). Install with: `pip install crosshair-tool`.
- CrossHair *executes code*: avoid code with side effects (disk/network/subprocess). Prefer pure/deterministic logic.
- Ensure **good type hints** on parameters (and `__init__` for classes you pass around).

## Contract styles (pick the lowest-friction that fits)
1) **asserts** (fastest to adopt)
   - Preconditions = leading `assert ...` statements at the top of the function.
   - Postconditions = later `assert ...` statements.
   - If you want analysis but have no preconditions, add `assert True` at the top.

2) **PEP316** (docstring contracts)
3) **icontract** / **deal** (decorator contracts; IDE-friendly)

Tip: If the codebase mixes styles, set a default per package/module with directives (below) or pass `--analysis_kind`.

## Workflow A: “Keep it running while I code” (recommended)
**Goal:** continuous feedback while editing.

Command:
- `crosshair watch <target>`

Targets can be: directory, file, module, class, function/method.
Examples:
- `crosshair watch src/`
- `crosshair watch mypkg/foo.py`
- `crosshair watch mypkg.foo.MyClass.method`

Use when:
- You’re iterating on contracts or tricky edge cases.
- You want fast “red flags” during refactoring.

## Workflow B: CI-friendly contract checking
**Goal:** deterministic command + machine-readable output + exit code.

Command:
- `crosshair check [OPTIONS] <target...>`

Output format (mypy-like):
- `<filename>:<line>: error: <message>`
Exit codes:
- `0` no counterexamples
- `1` counterexample(s) found
- `2` tool/runtime error

Practical defaults:
- Start small: `--max_uninteresting_iterations 3` for quick checks.
- For deeper checks, increase iterations and/or set timeouts:
  - `--per_condition_timeout <seconds>`
  - `--per_path_timeout <seconds>`
- Add more debugging context when needed:
  - `--report_verbose`
  - `--verbose`

Contract kinds:
- `--analysis_kind=asserts`
- `--analysis_kind=PEP316`
- `--analysis_kind=icontract`
- `--analysis_kind=deal`
(Comma-separated kinds allowed.)

## Workflow C: Configure scope and behavior in-code (directives)
Use directives to avoid huge CLI flag plumbing, and to keep rules near code.

Common directives (as comments):
- `# crosshair: off` / `# crosshair: on`
- `# crosshair: analysis_kind=<KIND>`

Placement:
- Inside a function body, top-level module scope, or package `__init__.py`.
Precedence:
- Lower-level overrides higher-level.

## Workflow D: Generate high-coverage inputs (and jumpstart tests)
**Goal:** get example inputs that hit different branches/paths.

Command:
- `crosshair cover <target...>`

Most useful flags:
- `--example_output_format=pytest`  (outputs pytest stubs)
- `--coverage_type=opcode|path`
- `--max_uninteresting_iterations N`
- `--per_condition_timeout S`
- `--per_path_timeout S`

Heuristics:
- If examples are huge/ugly, try increasing `--per_condition_timeout`.
- Treat generated tests as *starting points*: they encode “what code does”, not “what it should do”.

## Workflow E: Verify refactors / compare two implementations
**Goal:** find an input where two functions differ.

Command:
- `crosshair diffbehavior <func1> <func2>`

Useful flags:
- `--exception_equivalence=ALL|SAME_TYPE|TYPE_AND_MESSAGE`
- `--per_condition_timeout`, `--per_path_timeout`, `--max_uninteresting_iterations`

Refactor safety pattern (git worktree):
1) `git worktree add --detach clean`
2) `crosshair diffbehavior mypkg.foo.func clean.mypkg.foo.func`
3) `git worktree remove clean`

## IDE integration (high leverage)
Preferred: run CrossHair as an **LSP server** so it stays warm and finds counterexamples sooner.

Command your IDE should start (must use project’s python):
- `<path-to-project-python> -m crosshair server`

Alternative (simpler): run `crosshair check <file>` on save and parse mypy-like output.

## Interpreting counterexamples (how to act)
When CrossHair reports a failing call:
1) Reproduce: copy the invocation into a small test (or use `cover --example_output_format=pytest`).
2) Decide: bug in implementation vs contract too strong/incorrect.
3) Fix:
   - Strengthen preconditions, or
   - Correct postcondition, or
   - Fix implementation, then re-run `check`/`watch`.
4) Regression: keep the minimized counterexample test.

## Safety & performance notes
- Avoid printing/logging symbolic values (it can force concretization and reduce analysis power).
- Prefer deterministic pure functions (time/rand/global state break assumptions).
- If you *must* allow side effects, use `--unblock` narrowly (or isolate in a container).

## “Claude Code” operating procedure
When asked to “use CrossHair on this repo”:
1) Identify candidate targets (pure-ish modules, critical functions).
2) Ensure type hints exist; add/repair minimal annotations where missing.
3) Add contracts in the lowest-friction style (asserts first).
4) Run `crosshair check` on a narrow target; iterate until signal is clean.
5) If refactoring: use `diffbehavior` before/after; lock counterexamples into tests.
6) For test generation: use `cover` to hit branches, then curate outputs.

## Minimal command templates (copy/paste)
- Install: `python -m pip install crosshair-tool`
- Watch: `crosshair watch src/`
- Check asserts: `crosshair check --analysis_kind=asserts src/mypkg/foo.py`
- Check deeper: `crosshair check --per_condition_timeout 20 --max_uninteresting_iterations 200 src/mypkg/foo.py`
- Cover → pytest: `crosshair cover --example_output_format=pytest mypkg.foo.average`
- Diff refactor: `crosshair diffbehavior mypkg.foo.cut1 mypkg.foo.cut2`
