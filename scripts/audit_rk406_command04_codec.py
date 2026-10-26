"""Read-only, hash-pinned static witnesses for the offline command-4 codec.

Uses existing pefile/capstone. Never executes the target, opens HID, or writes files.
Disassembly starts at the two true entries and covers each complete function body.
This is an evidence regression check, NOT proof of equivalence of the C# codec.
"""
import argparse
import hashlib
from pathlib import Path

import capstone
import pefile


SHA256 = "c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6"
BODIES = (
    (0x411700, 0x4118F4, "54371ac6a9c5ba64aab87c2dac661b406bdb1e5d492b902cc2c8103c77475f9b"),
    (0x411900, 0x411B4B, "72814998b7e7ef359266102808b3c9943bed53921ec4aaaba6c9218ff783cd55"),
)
WITNESSES = {
    0x411786: ("881c3e", "mov byte ptr [esi + edi], bl"),
    0x4117E7: ("744c", "je 0x411835"),
    0x4117F6: ("8b47f4", "mov eax, dword ptr [edi - 0xc]"),
    0x4117F9: ("8b4ff8", "mov ecx, dword ptr [edi - 8]"),
    0x411818: ("885c6e54", "mov byte ptr [esi + ebp*2 + 0x54], bl"),
    0x411820: ("884c6e53", "mov byte ptr [esi + ebp*2 + 0x53], cl"),
    0x411824: ("3b13", "cmp edx, dword ptr [ebx]"),
    0x411826: ("750d", "jne 0x411835"),
    0x41182C: ("885622", "mov byte ptr [esi + 0x22], dl"),
    0x41182F: ("884e23", "mov byte ptr [esi + 0x23], cl"),
    0x411832: ("884624", "mov byte ptr [esi + 0x24], al"),
    0x4118BB: ("885609", "mov byte ptr [esi + 9], dl"),
    0x411921: ("0378c4", "add edi, dword ptr [eax - 0x3c]"),
    0x411924: ("0308", "add ecx, dword ptr [eax]"),
    0x411926: ("03503c", "add edx, dword ptr [eax + 0x3c]"),
    0x411929: ("05b4000000", "add eax, 0xb4"),
    0x41192E: ("3dd01d6100", "cmp eax, 0x611dd0"),
    0x411933: ("7cec", "jl 0x411921"),
    0x4119A6: ("881c3e", "mov byte ptr [esi + edi], bl"),
    0x4119CB: ("7e08", "jle 0x4119d5"),
    0x411A2F: ("753c", "jne 0x411a6d"),
    0x411A33: ("7e0c", "jle 0x411a41"),
    0x411A39: ("8b39", "mov edi, dword ptr [ecx]"),
    0x411A3B: ("8d7c3f38", "lea edi, [edi + edi + 0x38]"),
    0x411A41: ("8bfb", "mov edi, ebx"),
    0x411A43: ("837a2000", "cmp dword ptr [edx + 0x20], 0"),
    0x411A4D: ("8b4af8", "mov ecx, dword ptr [edx - 8]"),
    0x411A50: ("0fb68968186100", "movzx ecx, byte ptr [ecx + 0x611868]"),
    0x411A57: ("880c3e", "mov byte ptr [esi + edi], cl"),
    0x411A65: ("884c3e01", "mov byte ptr [esi + edi + 1], cl"),
    0x411A9B: ("8b941944210000", "mov edx, dword ptr [ecx + ebx + 0x2144]"),
    0x411AA8: ("88465e", "mov byte ptr [esi + 0x5e], al"),
    0x411B07: ("884618", "mov byte ptr [esi + 0x18], al"),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", default=r"C:\Program Files (x86)\RK Keyboard Software\DeviceDriver.exe")
    args = parser.parse_args()
    data = Path(args.binary).read_bytes()
    require(hashlib.sha256(data).hexdigest() == SHA256, "Target SHA-256 mismatch; refusing address attribution")
    pe = pefile.PE(data=data)
    require(pe.OPTIONAL_HEADER.ImageBase == 0x400000 and pe.FILE_HEADER.Machine == 0x14C, "Unexpected PE architecture/base")
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    instructions = {}
    for start, end, digest in BODIES:
        body = pe.get_data(start - pe.OPTIONAL_HEADER.ImageBase, end - start)
        require(hashlib.sha256(body).hexdigest() == digest, f"Function body mismatch at {start:#x}")
        decoded = list(decoder.disasm(body, start))
        require(decoded and decoded[0].address == start and decoded[-1].address + decoded[-1].size == end,
                f"Incomplete entry-aligned decoding at {start:#x}")
        require(sum(i.size for i in decoded) == len(body), "Disassembly gap")
        instructions.update({i.address: i for i in decoded})
        print(f"PASS body {start:#010x}..{end:#010x} ({len(body)} bytes), SHA-256 {digest}")
    for address, (hex_bytes, assembly) in WITNESSES.items():
        require(address in instructions, f"Not an entry-aligned instruction: {address:#x}")
        instruction = instructions[address]
        require(instruction.bytes.hex() == hex_bytes and f"{instruction.mnemonic} {instruction.op_str}" == assembly,
                f"Witness mismatch at {address:#x}")
        print(f"PASS {address:#010x} {hex_bytes}: {assembly}")
    print(f"PASS: target SHA-256, 2 complete bodies, {len(WITNESSES)} instruction witnesses. Static evidence only.")


if __name__ == "__main__":
    main()
