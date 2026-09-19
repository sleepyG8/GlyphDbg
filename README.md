## GlyphDbg — A Introspection Engine for Windows

GlyphDbg is not a traditional debugger. It is a byte‑accurate introspection engine designed for deep memory analysis, remote process exploration, and structural understanding of Windows binaries.

GlyphDbg lives inside the target process and gives you direct, deterministic access to:

PEB and TEB structures
Loader lists
Thread state
Memory regions
Heap metadata
Pointer graphs

It is written in pure C, matching the language of Windows NT itself, to ensure maximum clarity, determinism, and machine‑level control.

Core Capabilities

1. VEH‑Driven Execution Engine
Exception‑based breakpoints, symbolic fault lineage, and zero use of DebugActiveProcess.

2. Remote PE Reconstruction
Extract live code from memory and rebuild valid PE images, ideal for packers, malware, and JIT‑generated regions.

3. Memory and Pointer Tools
Commands for raw dumps, pre‑RIP context, pointer scanning, hotspot detection, heap walking, and region metadata.

4. Thread and Stack Exploration
Enumerate threads, swap active threads, walk stacks without symbols, and capture register state at any address.

5. Import, Export, and DLL Mapping
Remote IAT parsing, section walking, export scanning, and syscall stub extraction.

6. Function Boundary Engine
High‑accuracy function boundary detection across massive binaries, including those with hundreds of thousands of functions.

7. Snapshot Diffing (Rift Engine)
Compare two snapshots and highlight mutated functions, altered imports, and new DLLs.

8. Optional Kernel Driver (glass.sys)
Kernel memory reads, protected usermode reads, and kernel base discovery.

9. Extension Engine
Load custom DLLs, write extensions, and expand GlyphDbg without modifying the core.

Philosophy

GlyphDbg is built on a simple belief:

Introspection should speak the same language as the machine.

Windows NT is written in C, so GlyphDbg is written in C. It prioritizes determinism, clarity, and byte‑level truth over abstractions or UI layers.

GlyphDbg does not debug. It interprets execution, memory, and structure directly.
