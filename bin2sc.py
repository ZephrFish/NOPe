#!/usr/bin/env python3
import sys
import os


def read_shellcode_file(filepath: str) -> bytes:
    """Read binary shellcode file."""
    try:
        with open(filepath, "rb") as file:
            return file.read()
    except IOError as e:
        print(f"[!] Error reading file '{filepath}': {e}")
        sys.exit(1)


def format_shellcode_as_hex(shellcode: bytes) -> str:
    """Format shellcode bytes into C-style hex array (16 bytes per line)."""
    hex_bytes = [f'0x{byte:02X}' for byte in shellcode]
    lines = []

    for i in range(0, len(hex_bytes), 16):
        line = ', '.join(hex_bytes[i:i + 16])
        lines.append(f'    {line}')

    return "payload[] = {\n" + ",\n".join(lines) + "\n};"


def main():
    if len(sys.argv) != 2:
        print("Usage: python bin2sc.py <shellcode_file>")
        sys.exit(1)

    shellcode_file = sys.argv[1]

    if not os.path.isfile(shellcode_file):
        print(f"[!] File not found: {shellcode_file}")
        sys.exit(1)

    shellcode = read_shellcode_file(shellcode_file)
    formatted = format_shellcode_as_hex(shellcode)

    print("Shellcode in hex bytes format:")
    print(formatted)


if __name__ == "__main__":
    main()