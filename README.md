GlyphDbg: A Ritual Engine for Remote Introspection

GlyphDbg is not a debugger in the traditional sense.
It is a byte‑honest introspection engine — a deterministic ritual machine for walking memory, fracturing binaries, and interpreting execution as mythology.

It lives inside the target processes guts and builds a house.

It uses pure VEH, no debugging APIs, no hardware breakpoints, no instrumentation frameworks.

Compile

cl /MD GlyphDbg.c
*requires capstone libs

No C++
No abstractions
Just raw NT rituals

Core Features

PEB & TEB Ritualization
Deep walking of PEB/TEB structures, loader lists, bitfields, process parameters, and ancestry.
GlyphDbg treats the PEB as scripture — not metadata.

Pure VEH Execution Engine
Exception based breakpoints
access‑violations as signals
symbolic fault lineage
zero use of DebugActiveProcess

Remote PE Reconstruction
The !rebuild command extracts live code from memory and reconstructs a valid PE image:
Ideal for malware, packers, and JIT‑generated regions.

Memory & Pointer Introspection
!dump for raw memory
!sub for pre‑RIP context
!pointers for .data pointer scanning
!hot for hotspot detection
!heap for heap walking
!mbi for memory region metadata

Thread & Stack Rituals
Enumerate threads
Swap active thread
Walk stacks without symbols
Capture register state at any address
Threads become navigable and swappable.

Remote Import & DLL Mapping
!imports for remote IAT parsing
!dllcheck for section walking
!dllexp for export scanning and syscall stub extraction
Hook detection through import anomalies.

Function Boundary Engine
!func enumerates function boundaries across massive binaries, including 400k+ function images such as VS Code.
Boundary heuristics, control‑flow scanning, section‑aware disassembly, and mutation‑zone detection.
?? selects a random function using hardware entropy for exploration and chaos‑driven analysis.

Undocumented API Glyphs
Direct invocation of internal NT routines such as EtwpGetCpuSpeed, LsaGetUserName, and others.

Stealth Engine
Fiber‑based execution
DR register manipulation
Anti‑debug bypasses
No debug handles
No detectable footprint
GlyphDbg remains unseen.

Symbolic CLI
A full command surface exceeding sixty commands, covering memory, threads, handles, DLLs, heap, PEB/TEB, CFG, networking, registry, CPU, kernel memory, snapshot diffing, and extension loading.

Snapshot Diffing (Rift Engine) for bending time
!rift compares two .slp snapshots and highlights:
mutated functions
altered imports
new DLLs

Kernel‑Assisted Rituals (glass.sys)
Optional kernel driver enabling:
kernel memory reads
protected usermode reads
kernel base discovery
GlyphDbg becomes omniscient.

Extension Engine
!ext, !packs, !unload, !edit
Load custom DLLs, write extensions, and expand the debugger without modifying the core.

and much more!

Philosophy

GlyphDbg is written in pure C because Windows NT is written in C.
Introspection should speak the same language as the machine.

GlyphDbg does not debug — it interprets.
It treats faults as lineage, offsets as identity, memory as scripture, and mutation as meaning.

Authored By
SleepyG8
Systems engineer and author of the GlyphDbg.
