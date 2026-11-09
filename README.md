# Oculus — Windows Runtime Debugging REPL

## 1. Project brief

**Project name:** Oculus  
**Executable:** `oculus.exe`  
**Language:** C (C11)  
**Initial platform:** Windows 10/11, x64  
**Interface:** Interactive command-line REPL  
**Build system:** CMake + MSVC (preferably also compatible with clang-cl)

Build **Oculus**, a native C application for inspecting and instrumenting a running Windows process that the operator owns or is explicitly authorized to debug. The initial release is a REPL with commands to attach to a process, detach from it, inspect loaded DLLs, enumerate exported DLL functions, inject a user-selected DLL, and install/remove **inline function hooks**.

This is an implementation specification, not a mock-up. Implement functional Windows APIs, error handling, resource cleanup, and basic tests. Prioritize correctness and debuggability over cosmetic features.

### Core requirements

1. Open a target process by PID or executable name.
2. Close the current Oculus process **session** (detach and release handles; do not kill the target).
3. List DLLs loaded by the target process.
4. List PE exports of a DLL already loaded in the target process.
5. Load a DLL into the selected target process.
6. Install an **inline hook** by replacing a function's prologue with a control-transfer jump to a replacement function.
7. Remove an installed hook and restore its original bytes.
8. Offer helpful REPL output, commands such as `help`, and actionable Win32 error messages.


## 2. Expected REPL experience

Launch:

```text
C:\> oculus.exe
Oculus — Windows Runtime Debugging REPL
Type 'help' for commands.
oculus> 
```

Typical session:

```text
oculus> open 1234
[+] Attached to example.exe (PID 1234, x64)

oculus> list dlls
BASE ADDRESS        MODULE                 PATH
0x00007FFB...       KERNEL32.dll           C:\Windows\System32\KERNEL32.dll
0x00007FFB...       USER32.dll             C:\Windows\System32\USER32.dll
...

oculus> list functions:USER32.dll
EXPORT                      ORDINAL       ADDRESS
MessageBoxA                 ...           0x00007FFB...
MessageBoxW                 ...           0x00007FFB...
...

oculus> load "C:\debug\mydll.dll"
[+] Loaded mydll.dll in target (module base: 0x...)

oculus> hook MessageBoxA:USER32.dll MyMessageBoxA:mydll.dll
[+] Inline hook installed: USER32.dll!MessageBoxA -> mydll.dll!MyMessageBoxA
[+] Hook ID: 1

oculus> hooks
ID   TARGET                     REPLACEMENT                  STATUS
1    USER32.dll!MessageBoxA     mydll.dll!MyMessageBoxA       active

oculus> unhook 1
[+] Hook 1 removed; original instructions restored

oculus> close
[+] Detached from PID 1234 (target is still running)

oculus> exit
```

**Important correction:** `MessageBoxA` is exported by `USER32.dll`, **not** `KERNEL32.dll`. Use `USER32.dll!MessageBoxA` in the example and tests. Treat names and ordinals as case-sensitive where required for accurate export resolution; DLL filename matching can be case-insensitive.

### Mandatory command syntax

| Command | Description |
|---|---|
| `help` | Display syntax and examples. |
| `open <pid>` | Attach to a process by decimal PID. |
| `open <process.exe>` | Find and attach to a process by executable name. |
| `close` | Detach, free resources, and close handles without terminating the target. |
| `list process` | List running processes with PID, parent PID, thread count, and executable name. |
| `list dlls` | List loaded DLLs/modules of the selected process. |
| `list functions:<module.dll>` | List exports of the selected loaded module. |
| `load <path-to-dll>` | Load a DLL into the selected process. Paths with spaces must be quoted. |
| `hook <TargetExport>:<TargetDll> <ReplacementExport>:<ReplacementDll>` | Install an inline prologue hook. |
| `hooks` | List hooks installed by this Oculus session. |
| `unhook <id>` | Remove a hook and restore its original prologue. |
| `status` | Show the current target PID, architecture, and hook count. |
| `exit` / `quit` | Clean up and exit Oculus. |

For consistency with the requested interaction, **accept the exact** `list functions:kernel32.dll` form. Optionally also accept `list functions kernel32.dll`. Provide sensible error messages for unrecognized commands and missing arguments.

### Parser behavior

- Handle leading/trailing whitespace, repeated spaces, quoted Windows paths, and EOF cleanly.
- Do not use unsafe tokenization or fixed-size buffer assumptions.
- A PID or executable name is required for `open`.
- If several processes match `open <process.exe>`, list matching PIDs and request an explicit PID rather than silently choosing one.
- Require a selected process for `list`, `load`, `hook`, `hooks`, and `unhook` where applicable.
- If `open` is issued while a session is attached, safely close the old session only after the new target has been validated, or require an explicit `close` first. Document whichever behavior is implemented.
- Distinguish **detach** (`close`) from **terminate**. Do not add process termination to v1.

## 3. Platform and process access

Use the native Win32 API, not PowerShell or external utilities. Design a clean, Windows-specific backend that can later be replaced for other operating systems.

Suggested APIs:

- `CreateToolhelp32Snapshot`, `Process32FirstW`, `Process32NextW` for process discovery.
- `OpenProcess` for obtaining a target process handle.
- `IsWow64Process2` (with an appropriate fallback) to detect architecture compatibility.
- `Module32FirstW`, `Module32NextW`, and/or `EnumProcessModulesEx` and `GetModuleInformation` for module discovery.
- `ReadProcessMemory` and `VirtualQueryEx` for inspection.
- `VirtualAllocEx`, `VirtualFreeEx`, `WriteProcessMemory`, `VirtualProtectEx`, `FlushInstructionCache`, and appropriate thread/process synchronization where needed for instrumentation.
- PE headers (`IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS`, `IMAGE_EXPORT_DIRECTORY`) for export parsing.
- `FormatMessageW` for readable errors.

### Attaching and detaching

- Start with **same-bitness x64 Oculus -> x64 target** support. Reject unsupported combinations gracefully rather than attempting unsafe cross-architecture instrumentation.
- Request only the process access rights needed for each operation; report access denied clearly. Avoid automatically elevating or changing system security settings.
- Retain a target handle, PID, detected architecture, and a session-owned hook registry.
- On `close`, attempt to remove session-installed hooks **before** releasing required remote resources; report any hooks that could not be safely removed. Never leave a target running with a jump into replacement code that Oculus has unloaded.
- Handle the target exiting unexpectedly between commands.

## 4. Module enumeration (`list dlls`)

- Enumerate modules that are actually loaded in the target process.
- Print module name, full path (if accessible), and target process base address. Display size if available.
- Do not assume the enumerated list will remain stable; tolerate modules loading/unloading during enumeration.
- Differentiate errors from an empty list.
- Support case-insensitive lookup by module filename for subsequent commands.
- Reject ambiguous module names or require a full path when multiple loaded modules have the same filename.

## 5. Export enumeration (`list functions:<module.dll>`)

Read and interpret the PE export directory of the **module loaded in the target**. Do not assume the DLL's file on the controller filesystem has the same image or load address.

- Validate all remote memory reads and all PE offsets / RVAs against the mapped image boundaries.
- Enumerate named and ordinal-only exports.
- Show the export name (or `<ordinal-only>`), ordinal, resolved address, and forwarder information when relevant.
- Handle forwarded exports correctly. A forwarder entry is a string (for example `OTHERDLL.SomeFunction`), **not an executable function prologue**.
- Respect ASLR: calculate addresses from the target process's actual module bases rather than local `GetProcAddress` pointers.
- Provide clear errors for nonexistent module names, malformed export directories, and modules that unload during inspection.

## 6. DLL loading (`load <path>`)

Implement explicit DLL loading into the attached process for authorized debugging.

### Requirements

- Accept a fully qualified DLL path and normalize it; preserve quoted paths with spaces.
- Verify that the DLL exists, is a supported architecture, and is a PE DLL before requesting remote loading.
- Use the documented Windows loader behavior rather than manual PE mapping for v1.
- A possible implementation uses a remote Unicode path buffer and a bounded remote execution mechanism to invoke the target process's Windows loader, then waits for completion and verifies the module appeared in the target's module list. Encapsulate this in a dedicated backend function.
- Return a success result only after verifying the loaded module, not merely after creating a remote thread.
- Ensure remote allocations, handles, and temporary resources are cleaned up on **all** failure paths.
- Avoid calling `LoadLibrary` with an untrusted relative DLL name. Prefer an absolute path and explicit DLL dependencies.
- Do not attempt kernel injection, process protection bypasses, stealth loading, persistence, or security software evasion.
- Warn that injected DLL initialization can execute arbitrary code inside the target process.

### Recommended safety mechanism

For initial development, test injection against a provided sample target executable and replacement DLL. Treat arbitrary production processes as out of scope for automated tests.

## 7. Inline hooking (`hook ...`)

The required method is **inline prologue patching**: overwrite the first complete instructions of the target function with a jump to the replacement function **in the same target process**.

Example:

```text
hook MessageBoxA:USER32.dll MyMessageBoxA:mydll.dll
```

Semantics:

- Resolve `USER32.dll!MessageBoxA` in the target process, following forwarders if necessary.
- Resolve `mydll.dll!MyMessageBoxA` in that **same** target process. Require the replacement module to already be loaded (or display an instruction to run `load` first).
- Check that the resolved endpoints are executable, architecture-compatible, and distinct.
- Install a session-registered inline hook with a stable numeric ID.

### Mandatory correctness requirements

1. **Instruction-boundary safety:** use a proven x86-64 instruction-length decoder (for example Zydis or a similarly maintained library); never overwrite a fixed number of bytes without decoding full instructions.
2. **Jump encoding:** choose a valid x64 branch encoding. A direct `rel32` jump only works if the destination is within the signed 32-bit displacement range. Otherwise use an appropriate absolute-indirect or other architecture-correct jump sequence. Calculate the minimum patch size **after** selecting the encoding.
3. **Original byte preservation:** save the exact overwritten prologue instructions and their original protection metadata in a per-hook record before patching.
4. **Trampoline:** allocate executable memory for a callable original-function trampoline; relocate copied instructions when required, including RIP-relative operands and relative control-flow instructions, then branch back to the first non-overwritten instruction. If relocation cannot be done safely, **reject the hook rather than generating an incorrect trampoline**.
5. **Page protection and cache:** temporarily adjust protection as needed, restore the original protection, and flush the target instruction cache after writes.
6. **Concurrency:** consider threads executing or entering the patched function. Implement a documented safe patching strategy for the initial supported target type. Do not assume a multi-byte patch is atomic; reject unsafe scenarios instead of silently writing while other threads may execute partial instructions.
7. **Rollback:** if any install step fails, restore the original bytes and protections where possible, free unused remote allocations, and report a clear error. Never claim that a partially applied hook succeeded.
8. **Idempotence:** detect duplicate hooks, overlapping prologue patches, targets that are already modified, and missing/unloaded replacement modules. Refuse conflicts by default.
9. **Unhook:** restore original bytes safely, flush the instruction cache, remove the registry entry, and release trampolines only when no executing thread could be using them.
10. **Lifetime:** never unload a replacement DLL while an active hook still jumps into that DLL. The `close` path must preserve target safety even if cleanup encounters errors.
11. **ABI compatibility:** a replacement must match the original function's calling convention, signature, and return type. On Windows x64, preserve the ABI's stack alignment and nonvolatile registers.
12. **Clear limitations:** explicitly document when hooking exported stubs, hotpatchable code, shared DLL pages, protected processes, or functions with unsupported instruction relocations is rejected.

### Replacement DLL contract

The replacement function must be exported by a DLL loaded into the target process. For example, a sample DLL can export `MyMessageBoxA` with the same signature as `MessageBoxA`.

Define a **documented way for replacement code to call the original function**, such as a companion interface for obtaining the hook's trampoline address or a dedicated sample integration mechanism. Never advise calling the patched entry address directly from the replacement: that would recurse into the hook.

### Expected hook registry fields

```text
id
process_id
target_module
target_export
target_address
replacement_module
replacement_export
replacement_address
patch_length
saved_original_bytes
trampoline_address
trampoline_size
status
```

The hook should remain installed while Oculus runs, and `unhook` should restore the target to its prior state. Define and test the process-exit and Oculus-abnormal-exit limitations explicitly. Ideally use a cooperative test target capable of automatic cleanup, or make any potential residual modifications very clear.

## 8. Code organization

Suggested repository layout:

```text
Oculus/
├── CMakeLists.txt
├── README.md
├── LICENSE
├── include/
│   └── oculus/
│       ├── app.h
│       ├── repl.h
│       ├── process.h
│       ├── modules.h
│       ├── pe_exports.h
│       ├── injection.h
│       ├── hook.h
│       └── errors.h
├── src/
│   ├── main.c
│   ├── repl.c
│   ├── process.c
│   ├── modules.c
│   ├── pe_exports.c
│   ├── injection.c
│   ├── hook.c
│   └── errors.c
├── third_party/
│   └── README.md
├── samples/
│   ├── target/
│   └── replacement_dll/
└── tests/
    ├── test_parser.c
    ├── test_exports.c
    └── test_integration.c
```

Keep headers small and interfaces explicit. Prefix public functions and types with `oculus_` / `Oculus`. Minimize globals. Prefer wide-character Win32 APIs (`...W`) for process names, module paths, and DLL paths. Use the C runtime carefully for UTF-8 input/output and Windows UTF-16 conversions.

## 9. API and data model

Design an `OculusSession` structure that owns:

- Target process handle and PID.
- Target architecture and basic process metadata.
- Hook registry and associated remote allocations.
- Last structured error (Win32 error code plus Oculus-specific context).

Suggested high-level interfaces (exact signatures may differ):

```c
typedef struct OculusSession OculusSession;
typedef struct OculusHookInfo OculusHookInfo;

bool oculus_open_pid(OculusSession *session, uint32_t pid);
bool oculus_open_name(OculusSession *session, const wchar_t *exe_name);
bool oculus_close(OculusSession *session);
bool oculus_list_modules(OculusSession *session);
bool oculus_list_exports(OculusSession *session, const wchar_t *module);
bool oculus_load_library(OculusSession *session, const wchar_t *absolute_path);
bool oculus_install_hook(OculusSession *session,
                         const char *target_export, const wchar_t *target_module,
                         const char *replacement_export, const wchar_t *replacement_module,
                         uint64_t *hook_id);
bool oculus_remove_hook(OculusSession *session, uint64_t hook_id);
```

Separate REPL parsing, console formatting, and Windows API calls so the core components can be tested without interactive input.

## 10. Error handling and diagnostics

- Every Windows API failure should include the operation, process/module/function context, numeric Win32 error code, and a readable explanation.
- Print user-level errors without immediately exiting the REPL.
- Return a nonzero process exit code for fatal startup errors; do not crash on malformed commands.
- Never truncate 64-bit addresses to 32-bit values.
- Provide a `--verbose` option for detailed debug logs, keeping the default output readable.
- Avoid logging secrets, reading unrelated target memory, or writing dumps unless explicitly requested in future requirements.

## 11. Testing and acceptance criteria

Create a small, intentionally instrumentable **x64 sample target** and a sample **x64 replacement DLL** specifically for Oculus integration tests. Use a deterministic function in the sample target as the primary hook test, and use `USER32.dll!MessageBoxA` as an additional optional demonstration when appropriate.

### Required acceptance tests

- [ ] `oculus.exe` launches and displays its prompt and `help` output.
- [ ] `open <pid>` attaches to a sample x64 target and `status` shows accurate data.
- [ ] `open <exe_name>` handles zero, one, and multiple name matches.
- [ ] `close` releases the attachment without terminating the target.
- [ ] `list dlls` displays DLL names and their actual remote base addresses.
- [ ] `list functions:USER32.dll` shows `MessageBoxA` if USER32 is loaded in the test target.
- [ ] Export enumeration handles forwarded exports and ordinal-only exports.
- [ ] `load "C:\...\mydll.dll"` demonstrably loads the sample DLL in the test target, or reports an informative error.
- [ ] `hook ...` redirects calls from the target function to the replacement function.
- [ ] A documented trampoline enables the replacement to call the original behavior safely.
- [ ] `hooks` lists the installed hook and `unhook <id>` restores original behavior.
- [ ] `close` attempts safe hook cleanup before detaching and reports failures clearly.
- [ ] Incorrect DLL/export names, denied access, invalid PID, unsupported architecture, and exited targets do not crash Oculus.
- [ ] No remote allocation or thread/process handle leaks on successful or failed operations (verify with available Windows diagnostics).
- [ ] Hook installation is refused when instruction relocation or safe concurrency handling is unsupported.

## 12. Delivery requirements for the coding agent

Deliver all of the following in the repository:

1. Compilable C source code and headers.
2. CMake configuration and exact Windows build commands.
3. A README with purpose, supported Windows versions, architecture limitations, command reference, practical examples, and safety considerations.
4. A working x64 sample target and sample replacement DLL to validate injection and inline hooking.
5. Automated parser/unit tests and runnable integration tests for the sample target.
6. A short explanation of the selected instruction decoder, jump encoding, trampoline relocation strategy, thread safety strategy, and known unsupported situations.

### Definition of done

The project is complete for v1 only when the commands above **work against the controlled sample target**, hooks are installed using real instruction-aligned prologue overwrites, `unhook` correctly restores the original behavior, and failures are handled without corrupting or terminating the target. No placeholder implementations, fake results, or unexplained `TODO` paths for core commands.

## 13. Explicitly out of scope for v1

- GUI, Linux/macOS support, and 32-bit target support.
- Kernel drivers, protected-process bypasses, privilege escalation, or stealth/EDR evasion.
- Persistence, automatic injection into other processes, or broad process scanning.
- Manual PE mapping, reflective loading, and undocumented loader tricks.
- Breakpoints, disassembly UI, memory editing, stack traces, symbol servers, and scripting engines.
- Forcefully killing a target process.
- DLL unloading while an active hook depends on the DLL.

Keep the code modular so future functionality can be added without rewriting the REPL.

---

## 14. Implemented v1

This repository contains a self-contained Windows x64 implementation. It uses only
the C11 runtime and Win32; no package manager or external runtime library is
required. The controller supports Windows 10/11 x64 and intentionally rejects
32-bit targets, self-attachment, protected/inaccessible processes, ambiguous
process names, and unsupported hook prologues.

### Build with MinGW-w64 GCC (recommended)

From a 64-bit MinGW shell or PowerShell with MinGW on `PATH`:

```powershell
mingw32-make -j4
mingw32-make test
```

Outputs are written to `build/`. The Makefile uses C11 and warning-clean GCC
flags. A clean rebuild is:

```powershell
mingw32-make clean
mingw32-make -j4
```

### Build with CMake

```powershell
cmake -S . -B build-cmake -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build-cmake --parallel
ctest --test-dir build-cmake --output-on-failure
```

MSVC x64 is also supported by the main application. The sample target has a
GCC-specific deterministic NOP prologue when built by MinGW; on MSVC its normal
compiler prologue is used and may be conservatively rejected by the v1 decoder.

### Controlled demonstration

Start `build\oculus_sample_target.exe`, note its PID, then run
`build\oculus.exe` and enter:

```text
open <pid>
list process
list dlls
list functions:USER32.dll
load "C:\absolute\path\to\build\oculus_sample_replacement.dll"
hook OculusSampleAdd:oculus_sample_target.exe OculusReplacementAdd:oculus_sample_replacement.dll
hooks
unhook 1
close
quit
```

The target prints `result=42` before the hook, `result=1042` while it is active,
and `result=42` after removal. `tests/test_integration.c` automates that complete
transition against a child process created by the test itself.

For a direct MinGW build without Make or CMake, the repository root also contains:

```text
build_oculus.bat       builds build\oculus.exe
build_example_dll.bat  builds build\oculus_example_injected.dll
```

The source and usage notes for the additional injectable DLL are in
`dll_examples/`. It can be loaded on its own or used against the sample target;
its replacement changes the sample result from `42` to `2042`.

### Hook design and limitations

- The x64 patch is a 14-byte absolute indirect jump (`FF 25 00 00 00 00`
  followed by the 64-bit destination), so it is independent of `rel32` range.
- The internal instruction-length decoder accepts a deliberately bounded subset
  of Intel x86-64 encodings. Instructions are decoded to whole boundaries and
  expose displacement metadata. The trampoline is allocated within ±2 GB of the
  target; RIP-relative 32-bit displacements and supported 8/32-bit relative
  branches/calls are recalculated for the new address. Branches into the copied
  prologue are redirected to the corresponding trampoline instruction. A short
  branch that no longer fits, VEX/EVEX instruction, unknown encoding, or any
  relocation that cannot be represented safely is rejected before patching.
  The relocated prologue is followed by an absolute jump to the remainder of
  the target function.
- Existing target threads are enumerated repeatedly until the thread list is
  stable, suspended, and checked to ensure no instruction pointer is inside the
  patch or trampoline range. Patching is refused if a thread cannot be inspected
  or a stable snapshot cannot be obtained. This strategy is intended for the
  controlled sample and quiescent debugging targets, not highly concurrent or
  adversarial processes that continually create threads.
- Remote code pages use an RW-to-RX transition. The target prologue protection is
  restored after each write and the instruction cache is flushed. Rollback
  restores saved bytes when installation fails.
- Duplicate/overlapping hooks and externally modified hook bytes are refused.
  Forwarded exports are followed before patching; a forwarder string is never
  treated as executable code.
- The optional replacement-DLL export `DWORD WINAPI OculusSetOriginal(void *)`
  receives the trampoline address after installation. The sample replacement
  uses this to call the original without recursing through the patched entry.
  Production replacement functions must exactly match the original Windows x64
  ABI, parameters, and return type.
- `close` removes session hooks before releasing the process handle and refuses
  to detach if safe restoration fails. If Oculus is forcibly killed or crashes,
  it cannot perform this cleanup; the controlled target should then be restarted.
  Oculus never unloads replacement DLLs and has no process-termination command.

Only use DLL loading and hooking on processes you own or are explicitly
authorized to debug. DLL initialization and replacement functions execute code
inside the target process and can crash or corrupt it if their ABI or behavior is
incorrect.
