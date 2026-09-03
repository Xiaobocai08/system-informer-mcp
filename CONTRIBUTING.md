# Contributing

Thanks for your interest in improving **system-informer-mcp**! Contributions of
all sizes are welcome — bug reports, new tools, better docs, and tests.

## Getting started

1. Install **Visual Studio 2022** (or the Build Tools) with the *Desktop
   development with C++* workload and a Windows 10/11 SDK.
2. Clone the repo and run `build.bat`. The `phnt` headers are vendored, so no
   extra setup is needed.
3. Run the tests: `python test\test_all.py` (Python 3.8+).

## Adding a new tool

Each tool group lives in its own `src/tools_*.c` file. To add a tool:

1. Implement a handler with the signature `cJSON *fn(const cJSON *args, int *isError)`.
2. Add a `Tool` entry to that file's registration array with:
   - a unique `name`,
   - a short `title`,
   - a **detailed `description`** (when to use it, what it returns),
   - a complete **JSON Schema** for `inputSchema` (document every argument,
     with `enum`/`default` where relevant),
   - `destructive = 1` if it mutates the system or is irreversible.
3. Destructive tools must check nothing extra for the guard — the core enforces
   `confirm: true` automatically based on the `destructive` flag.
4. Keep output as structured JSON. Use the helpers in `ntutil.h` / `mcp.h`.
5. Add a check to `test/test_all.py`.

The guiding principle: **the AI should never have to guess.** If an argument or
behavior isn't obvious from the schema and description, document it.

## Style

- C11, MSVC. Match the surrounding code.
- Prefer the NT (`Nt*`) APIs already used across the codebase.
- No new third-party dependencies without discussion.

## Pull requests

- Keep PRs focused. One feature/fix per PR where possible.
- Describe what changed and why. Note any new tools in the PR body.
- Make sure `build.bat` is clean and `test/test_all.py` passes.
