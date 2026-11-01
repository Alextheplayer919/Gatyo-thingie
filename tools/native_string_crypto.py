#!/usr/bin/env python3
"""Reproduce the native-code findings of the Gatyo analysis (optional capstone).

Looks at libReverseSigma.so and:
  * lists the ELF/rodata facts (keys, tables, mask)
  * emulates the rotate-XOR keystream block that initialises the two 0x78-byte
    .bss buffers (0x61d2b8 and 0x61d234)
  * with capstone installed, also finds every adrp/add reference to given
    addresses so the telemetry call chain can be re-walked

Usage:
  python3 native_string_crypto.py /tmp/apk/lib/arm64-v8a/libReverseSigma.so
  python3 native_string_crypto.py <so> --xref 0x61d2b8 0x5dfec

The two 64-bit keys below are hard-coded immediates in the library; they are
loaded with movz/movk and widened to a 2-lane vector (dup v3.2d, x9).
"""
import argparse
import struct
import sys

# .rodata tables used by the keystream loop (file offset == vaddr for this .so)
COUNTER_TABLES = {
    'v6 (counters 0,1)': 0x704a0,
    'v5 (counters 2,3)': 0x70f40,
    'v1 (counters 4,5)': 0x711d0,
    'v0 (counters 6,7)': 0x71400,
}
SHUFFLE_MASK = 0x712c0
KEYS = {
    'buffer 0x61d2b8': 0xe9cfff4b37a95fed,
    'buffer 0x61d234': 0xc177ebb56dc19985,
}
BLOCK = 0x78            # 120 bytes are processed
STRIDE = 0x18           # loop compares the byte index against 0x78


def q2(data, off):
    return list(struct.unpack_from('<QQ', data, off))


def keystream(key, data, blocks=BLOCK // 8):
    mask = data[SHUFFLE_MASK:SHUFFLE_MASK + 16]
    v0 = q2(data, COUNTER_TABLES['v0 (counters 6,7)'])
    v1 = q2(data, COUNTER_TABLES['v1 (counters 4,5)'])
    v5 = q2(data, COUNTER_TABLES['v5 (counters 2,3)'])
    v6 = q2(data, COUNTER_TABLES['v6 (counters 0,1)'])
    out = b''

    def lanes(vec):
        # ushl with a negated shift amount == logical right shift
        return [(key >> (((x << 3) & 0x38) % 64)) & 0xFFFFFFFFFFFFFFFF for x in vec]

    for _ in range(blocks):
        table = b''.join(struct.pack('<QQ', *lanes(v)) for v in (v6, v5, v1, v0))
        out += bytes(table[mask[j]] if mask[j] < len(table) else 0 for j in range(8))
        v0 = [x + 8 for x in v0]
        v1 = [x + 8 for x in v1]
        v5 = [x + 8 for x in v5]
        v6 = [x + 8 for x in v6]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('so')
    ap.add_argument('--xref', nargs='*', default=[])
    args = ap.parse_args()
    data = open(args.so, 'rb').read()

    print('file size           : %d bytes (%#x)' % (len(data), len(data)))
    for name, off in COUNTER_TABLES.items():
        print('table %-22s %#08x -> %s' % (name, off, [hex(v) for v in q2(data, off)]))
    print('shuffle mask %#08x : %s' % (SHUFFLE_MASK, data[SHUFFLE_MASK:SHUFFLE_MASK + 16].hex(' ')))
    for buf, key in KEYS.items():
        ks = keystream(key, data)
        print('\n%s  key=%#018x' % (buf, key))
        print('  keystream(64B): %s' % ks[:64].hex(' '))
        print('  distinct 8-byte blocks: %d of %d  -> repeating pattern: %s'
              % (len({ks[i:i + 8] for i in range(0, len(ks), 8)}), len(ks) // 8,
                 len({ks[i:i + 8] for i in range(0, len(ks), 8)}) == 1))
        print('  printable?    : %s' % all(0x20 <= b < 0x7f for b in ks))
    print('\nNOTE: both buffers are in .bss (zero-filled at load) and are only '
          'touched by the two routines\n      around 0x39ed78/0x39eee8; the '
          'init-once flags are never written by any other code,\n      so the '
          'XOR produces the key pattern above rather than a stored string.')

    if args.xref:
        try:
            import capstone
        except ImportError:
            print('\ncapstone not installed - skipping xrefs (pip install capstone)')
            return
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        md.detail = True
        text_off, text_size = 0x1dfe10, 0x2999b0
        want = {int(a, 16) for a in args.xref}
        reg_adrp = {}
        print('\nreferences:')
        for ins in md.disasm(data[text_off:text_off + text_size], text_off):
            ops = ins.operands
            if ins.mnemonic == 'adrp' and len(ops) == 2 and ops[1].type == capstone.arm64.ARM64_OP_IMM:
                reg_adrp[ops[0].reg] = ops[1].imm
            elif len(ops) >= 3 and ops[1].type == capstone.arm64.ARM64_OP_REG \
                    and ops[1].reg in reg_adrp and ops[2].type == capstone.arm64.ARM64_OP_IMM:
                addr = reg_adrp[ops[1].reg] + ops[2].imm
                if addr in want:
                    print('  %#010x -> %#010x  %s %s'
                          % (ins.address, addr, ins.mnemonic, ins.op_str))


if __name__ == '__main__':
    sys.exit(main())
