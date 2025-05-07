# NOPe

A flexible payload execution toolkit that prepends randomized NOP sleds to shellcode for obfuscation and executes it in memory.

> **Tradecraft Note:** Demonstrates NOP sled obfuscation (MITRE ATT&CK T1027) and in-memory shellcode execution (T1059) to bypass static and dynamic defenses.

## Prerequisites

- Python 3.6 or higher
- 32-bit Python interpreter for x86 payloads
- 64-bit Python interpreter for x64 payloads

## Installation

```bash
git clone https://github.com/cyberchancer/NOPe.git
cd NOPe
python3 -m venv venv
source venv/bin/activate
```

*(No external dependencies; uses standard `ctypes`, `mmap`, and `argparse`.)*

## Features

- Dual-architecture support: x86 and x64 shellcode
- Randomized NOP sled variants to evade static analysis (T1027)
- In-memory shellcode execution to minimize disk artifacts (T1059)
- Listing and selection of NOP variants for tailored payload crafting

## Tradecraft & MITRE Mapping

| Technique ID | Technique Name                    | Description                                          |
|--------------|-----------------------------------|------------------------------------------------------|
| T1027        | Obfuscated Files or Information   | Prepends randomized NOP-like instructions to payload |
| T1059        | Command and Scripting Interpreter | Executes payloads in memory without dropping files   |

## Usage

```bash
# Default payload (x64 message box)
python3 NOPe.py

# Custom shellcode
python3 NOPe.py -f my_shellcode.bin

# Specify architecture
python3 NOPe.py -f payload.bin --arch x86

# Verbose mode
python3 NOPe.py -f payload.bin --arch x64 --verbose

# List available NOP variants
python3 NOPe.py --arch x86 --list-nops
```

## Generating Shellcode

Use MSFVenom to create sample payloads:

```bash
# x64 messagebox
msfvenom -p windows/x64/messagebox TEXT="NOPe64" TITLE="Hello" -f raw > msgbox.x64.bin

# x86 messagebox
msfvenom -p windows/messagebox   TEXT="NOPe32" TITLE="Hello" -f raw > msgbox.x86.bin
```

---

# bin2sc

A helper script to convert raw shellcode binaries into source-code snippets.

> **Tradecraft Note:** Facilitates payload embedding and staging for diverse delivery mechanisms (T1105, T1027).

## Usage

```bash
# Print C array
python3 bin2sc.py shellcode.bin

# Write to file
python3 bin2sc.py shellcode.bin -o output.h

# Select style: c-string or rust
python3 bin2sc.py shellcode.bin -s c-string
python3 bin2sc.py shellcode.bin -s rust

# Customize variable name and bytes per line
python3 bin2sc.py shellcode.bin --name mypayload --bytes-per-line 8
```

## Example Output (C Array)

```c
unsigned char payload[] = {
    0x90, 0x90, 0xCC, 0xCC, 0xEB, 0xFE
};
```

## Changelog

- `README.md`: Reorganized structure; added Prerequisites, Installation, Features, Tradecraft & MITRE Mapping sections; fixed command hyphens for consistent copy-paste; updated Usage and Generating Shellcode examples.
- Added full definitions for `X64_NOPS` and `X86_NOPS` in `NOPe.py` to resolve the NameError and enable dual-architecture/OS (Windows/Unix) support.
- Annotated `NOPe.py` and `bin2sc.py` with in-code comments mapping to red team tradecraft (obfuscation, execution, staging) and MITRE ATT&CK techniques.
- Introduced file-level headers in both scripts clarifying purpose and tradecraft context.
