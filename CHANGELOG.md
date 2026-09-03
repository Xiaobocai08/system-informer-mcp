# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-09-03

First public release.

### Added
- Native C MCP server (`si-mcp.exe`, ~340 KB, no runtime dependencies) speaking
  Model Context Protocol over stdio.
- 54 tools mirroring System Informer's data views and actions:
  system, processes, process control, threads, memory, handles, services,
  network, modules/drivers, windows, files/signatures, and GUI hand-off.
- Startup `instructions`, fully documented JSON Schemas for every tool, and five
  workflow prompts (high CPU, suspicious-process triage, what-locks-this-file,
  what-owns-this-port, inspect-process).
- `confirm: true` guard on all destructive/irreversible tools; extra
  `allow_critical` gate for Windows-critical processes; SEH isolation per call.
- Timeout-guarded object-name resolution so wedged named pipes cannot hang the
  server (same approach as System Informer).
- Vendored System Informer `phnt` headers so the repo builds standalone.
- MSVC `build.bat`, GitHub Actions CI (build + smoke test) and tag-driven
  release workflow, Python end-to-end test suite (56 checks / 54 tools).
- English and Simplified Chinese READMEs.

[1.0.0]: https://github.com/Xiaobocai08/system-informer-mcp/releases/tag/v1.0.0
