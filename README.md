# NOPe

A quick and hacky script to test alternatives to traditional NOP sleds by prepending various x86 or x64 "NOP-like" instructions to shellcode and executing it in memory.

Note: You must use the correct architecture of Python for the type of shellcode you're testing.

- Use 32-bit Python for x86 shellcode
- Use 64-bit Python for x64 shellcode

## Usage

Run with the default payload (x64 message box shellcode):
```
python NOPe.py
```

Run with your own shellcode binary:
```
python NOPe.py -f my_shellcode.bin
```

Specify architecture:
```
python NOPe.py -f msgbox.x86.bin –arch x86
```

Enable verbose output:
```
python NOPe.py -f msgbox.x64.bin –arch x64 –verbose
```

List supported NOP variants for a given architecture:
```
python NOPe.py –arch x86 –list-nops
```

## Generating Shellcode

To regenerate the message box payloads using `MSFVenom`:

x64 shellcode
```
msfvenom -p windows/x64/messagebox TEXT=“NOPe64” TITLE=“Hello” -f raw > msgbox.x64.bin
```

x86 shellcode
```
msfvenom -p windows/messagebox TEXT=“NOPe32” TITLE=“Hello” -f raw > msgbox.x86.bin
```

# bin2sc

A simple script for converting raw `.bin` shellcode files into formatted C or Rust source code.

## Usage

Convert and print shellcode in C-style hex array format:
```
python bin2sc.py shellcode.bin
```
Write the output to a file:

```
python bin2sc.py shellcode.bin -o output.h
```

Change output format:

```
python bin2sc.py shellcode.bin -s c-array      # Default
python bin2sc.py shellcode.bin -s c-string     # “\x90\x90…” style
python bin2sc.py shellcode.bin -s rust         # Rust-style byte array
```
Customise the variable name and bytes per line:
```
python bin2sc.py shellcode.bin –name my_shellcode –bytes-per-line 8
```

## Example Output (C Array)

```c
unsigned char payload[] = {
    0x90, 0x90, 0xCC, 0xCC, 0xEB, 0xFE
};
```