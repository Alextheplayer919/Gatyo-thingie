#!/usr/bin/env python3
"""Minimal Android binary XML (AXML) parser - pure stdlib, no dependencies.

Usage:  python3 axml.py AndroidManifest.xml
        python3 axml.py res/xml/network_security_config.xml

Prints one line per start tag, indented by depth, with every attribute value
already resolved (strings resolved out of the string pool, references shown as
@0x7fxxxxxx). Written for the Gatyo APK analysis; handles manifests and
compiled res/xml resources alike.
"""
import struct
import sys

RES_STRING_POOL = 0x0001
RES_XML = 0x0003
RES_XML_START_ELEMENT = 0x0102
RES_XML_END_ELEMENT = 0x0103
RES_XML_RESOURCE_MAP = 0x0180

TYPE_REFERENCE = 0x01
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12


class Pool:
    def __init__(self, data, off):
        (self.type, self.hsize, self.size, self.count, self.styles,
         self.flags, self.strings_start, self.styles_start) = struct.unpack_from('<HHIIIIII', data, off)
        self.utf8 = bool(self.flags & 0x100)
        self.offsets = [struct.unpack_from('<I', data, off + self.hsize + 4 * i)[0]
                        for i in range(self.count)]
        self.data = data
        self.base = off
        self.cache = {}

    def get(self, i):
        if i is None or i < 0 or i >= self.count:
            return None
        if i in self.cache:
            return self.cache[i]
        p = self.base + self.strings_start + self.offsets[i]
        d = self.data
        if self.utf8:
            n = d[p]; p += 1
            if n & 0x80:
                p += 1; n = ((n & 0x7f) << 8) | d[p - 1]
            n = d[p]; p += 1
            if n & 0x80:
                p += 1; n = ((n & 0x7f) << 8) | d[p - 1]
            s = d[p:p + n].decode('utf-8', 'replace')
        else:
            n = struct.unpack_from('<H', d, p)[0]; p += 2
            if n & 0x8000:
                n = ((n & 0x7fff) << 16) | struct.unpack_from('<H', d, p)[0]; p += 2
            s = d[p:p + n * 2].decode('utf-16le', 'replace')
        self.cache[i] = s
        return s


def parse(path):
    """Yield ('start'|'end', namespace, tag, attrs) events in document order."""
    d = open(path, 'rb').read()
    typ, hsize, _ = struct.unpack_from('<HHI', d, 0)
    assert typ == RES_XML, 'not an AXML file (type %#x)' % typ
    off = hsize
    pool = None
    resmap = []
    while off < len(d):
        ctyp, chsize, csize = struct.unpack_from('<HHI', d, off)
        if csize == 0:
            break
        if ctyp == RES_STRING_POOL and pool is None:
            pool = Pool(d, off)
        elif ctyp == RES_XML_RESOURCE_MAP:
            resmap = [struct.unpack_from('<I', d, off + chsize + 4 * i)[0]
                      for i in range((csize - chsize) // 4)]
        elif ctyp == RES_XML_START_ELEMENT:
            ns, name = struct.unpack_from('<iI', d, off + chsize)
            attr_start, attr_size, attr_count = struct.unpack_from('<HHH', d, off + chsize + 8)
            attrs = []
            for i in range(attr_count):
                a = off + chsize + attr_start + i * attr_size
                a_ns, a_name, a_raw = struct.unpack_from('<iiI', d, a)
                vtype = d[a + 15]
                vdata = struct.unpack_from('<I', d, a + 16)[0]
                res_id = resmap[a_name] if 0 <= a_name < len(resmap) else None
                if vtype == TYPE_STRING:
                    val = pool.get(vdata)
                elif vtype == TYPE_INT_BOOLEAN:
                    val = vdata != 0
                elif vtype == TYPE_INT_HEX:
                    val = hex(vdata)
                elif vtype == TYPE_INT_DEC:
                    val = vdata
                elif vtype == TYPE_REFERENCE:
                    val = '@0x%08x' % vdata
                else:
                    val = ('type0x%02x' % vtype, vdata)
                attrs.append({'name': pool.get(a_name), 'value': val,
                              'res': ('0x%08x' % res_id) if res_id else None,
                              'raw': pool.get(a_raw) if a_raw >= 0 else None})
            yield ('start', pool.get(ns) if ns >= 0 else None, pool.get(name), attrs)
        elif ctyp == RES_XML_END_ELEMENT:
            ns, name = struct.unpack_from('<iI', d, off + chsize)
            yield ('end', pool.get(ns) if ns >= 0 else None, pool.get(name), [])
        off += csize


def elements(path):
    """Return list of (tag, {attr: value}) for every start tag."""
    out = []
    for kind, _ns, tag, attrs in parse(path):
        if kind == 'start':
            out.append((tag, {a['name']: a['value'] for a in attrs}, attrs))
    return out


if __name__ == '__main__':
    depth = 0
    for kind, _ns, tag, attrs in parse(sys.argv[1]):
        if kind == 'start':
            pad = '  ' * depth
            print(pad + '<' + (tag or '?') + '>')
            for a in attrs:
                print(pad + '   @%s=%r  (%s)' % (a['name'], a['value'], a['res']))
            depth += 1
        else:
            depth = max(0, depth - 1)
