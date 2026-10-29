"""Check selected 4.06 macro-serializer byte witnesses; no program execution."""
import hashlib
from pathlib import Path
import sys

import pefile

SHA = 'c03f88bc4e2d78aa4392d7445b0fd62182dc824f97f5d5db40bd009e547a9ab6'
DEFAULT = Path(r'C:\Program Files (x86)\RK Keyboard Software\DeviceDriver.exe')
WITNESSES = {
    0x410f89: '0fb7566a',      # first code at record+0x6a
    0x410f9d: '83c672',        # next record row, +0x72
    0x410fc6: '8b5f04',        # current row DWORD +4
    0x411009: '8bfe0fb71733c083c608663bc27588',  # next code, +8 and loop
    0x411018: '8b44241085c0740f',  # optional output-buffer copy
    0x411037: '8bc5',          # output length in EAX
}


def verify(data):
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('Unexpected executable SHA-256')
    pe = pefile.PE(data=data, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    if base != 0x400000:
        raise ValueError('Unexpected image base')
    for address, expected in WITNESSES.items():
        wanted = bytes.fromhex(expected)
        offset = pe.get_offset_from_rva(address - base)
        if data[offset:offset + len(wanted)] != wanted:
            raise ValueError(f'Instruction witness mismatch at {address:08X}')
    return (0x342 - 0x6a) // 8


if __name__ == '__main__':
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT
    rows = verify(path.read_bytes())
    print(f'Hash and {len(WITNESSES)} selected witnesses verified; {rows} row positions fit in a 0x342-byte record.')
    print('Static candidate only: no claim about runtime allocation, reachability, or device acceptance.')
