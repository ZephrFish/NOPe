import sys

# Check if file argument is provided
if len(sys.argv) != 2:
    print("Usage: python shellcode_to_hex.py <shellcode_file>")
    sys.exit(1)

shellcode_file = sys.argv[1]

try:
    # Read the shellcode file
    with open(shellcode_file, "rb") as file:
        shellcode = file.read()
except IOError as e:
    print("Error reading file:", e)
    sys.exit(1)

# Convert shellcode to hex bytes format with a maximum of 16 bytes per line
hex_bytes = [f'0x{x:02X}' for x in shellcode]
num_bytes = len(hex_bytes)
num_rows = (num_bytes + 15) // 16

# Print the hex bytes format with a maximum of 16 bytes per line
print(f'Shellcode in hex bytes format:')
print('payload[] = {')
for i in range(num_rows):
    row_start = i * 16
    row_end = min(row_start + 16, num_bytes)
    row_hex = ', '.join(hex_bytes[row_start:row_end])
    if i == num_rows - 1:
        # Remove the last comma for the last row
        print(f'    {row_hex}')
    else:
        print(f'    {row_hex},')
print('};')