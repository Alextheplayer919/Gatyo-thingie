#!/usr/bin/env python3
"""Independent verifier for the Gatyo-1.21.111-Iris-build118 APK.

Pure stdlib. Re-derives, from the actual bytes, every claim made in
Gatyo_APK_Analysis/REPORT_Gatyo_APK_Analysis.txt and prints a JSON ledger.

Usage:
  python3 verify_apk.py --apk /tmp/apkout/Gatyo-1.21.111-Iris-build118.apk \
                        --tree /tmp/apk \
                        --json verification.json

  --apk   the .apk file (needed for signature work)
  --tree  a fully unzipped copy of that apk (needed for per-file hashing)
"""
import argparse
import base64
import hashlib
import json
import os
import re
import struct
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import axml  # noqa: E402

# sha256 values published in evidence/01_hashes.txt
EXPECTED = {
    'AndroidManifest.xml': '6a2527f35035b46db9ee11d98c434baa45988884521c59ac945c0a32a8256ad9',
    'classes.dex': '46ce0d1571e120693de0209cc4d9fc8c4eb80cc6e6a7515aa6e78b32f1d9136a',
    'classes2.dex': '63776a5512d17768e329f5821ac4b1d22d59692f80538d78c5480aed04d25a36',
    'classes3.dex': '52819d218978f69afd3fc0831ab8c9826f5c08078999c39615d4606ceaf524e1',
    'classes4.dex': '959476ee3b317f41453c4bc973fd2341dfbb8e98260e2a89c9d0b2afb791b0ba',
    'classes5.dex': '9f9ea5a440ab66f2b60f12509679b1780c017f3921ea25a7691a46d19741b9ec',
    'classes6.dex': '816ed03ab02c29648f1ab3ca94f3dd76458c6ae9d393d7938a310668f39c4aa3',
    'lib/arm64-v8a/libReverseSigma.so': 'ecb779812304c09745cfd343b638dda3b0e16a85e406a7b314aa339fb346d9e6',
    'assets/assets/icu/demo.dat': 'ecb779812304c09745cfd343b638dda3b0e16a85e406a7b314aa339fb346d9e6',
    'lib/arm64-v8a/libminecraftpe.so': '65b9a43178a8b2cde19b6e000613b1453f8f2ea964b094faaf6e206ef041fed1',
    'META-INF/MANIFEST.MF': '7d1eaef6b16ac71572f2e648de342ec73b350db24ca54ad77cedad9b97a69ed2',
    'META-INF/ANDROIDD.SF': '241bba8b181a5f6e8f073ac8ef28f98068e3674c02c93b6998a71a7b259aae79',
    'META-INF/ANDROIDD.RSA': 'ee1bbe2f118dfe246d3f3d1020c06f156a325bbbb6ba93acd5862063a08917f5',
}
EXPECTED_APK = '2d985a17b9885a6e3918b8b15c9f29aae593ed8662e9356297cf5af58ab7d45f'
EXPECTED_7Z = '9164084f2473c42b860fe0aff9103686d703a524302e93ad7b3d7fd5d01d5fea'

SIG_V2 = 0x7109871a
SIG_V3 = 0xf05368c0
SIG_PADDING = 0x42726577

NETWORK_IMPORTS = re.compile(
    rb'(?:^|\x00)(socket|connect|send|sendto|recv|gethostbyname|getaddrinfo|SSL_|BIO_|EVP_)')


def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(chunk), b''):
            h.update(block)
    return h.hexdigest()


def dex_class_count(path):
    with open(path, 'rb') as f:
        hdr = f.read(0x70)
    if hdr[:4] not in (b'dex\n',):
        return None
    return struct.unpack_from('<I', hdr, 0x60)[0]


def manifest_report(path):
    els = axml.elements(path)
    out = {'package': None, 'version_code': None, 'version_name': None,
           'min_sdk': None, 'target_sdk': None, 'app_label': None,
           'application_class': None, 'permissions': [], 'components': [],
           'meta_data_keys': []}
    for tag, attrs, _raw in els:
        if tag == 'manifest':
            out['package'] = attrs.get('package')
            out['version_code'] = attrs.get('versionCode')
            out['version_name'] = attrs.get('versionName')
        elif tag == 'uses-sdk':
            out['min_sdk'] = attrs.get('minSdkVersion')
            out['target_sdk'] = attrs.get('targetSdkVersion')
        elif tag == 'uses-permission':
            if attrs.get('name'):
                out['permissions'].append(attrs['name'])
        elif tag == 'application':
            out['app_label'] = attrs.get('label')
            out['application_class'] = attrs.get('name')
            out['network_security_config'] = attrs.get('networkSecurityConfig')
            out['request_legacy_external_storage'] = attrs.get('requestLegacyExternalStorage')
            out['preserve_legacy_external_storage'] = attrs.get('preserveLegacyExternalStorage')
            out['has_fragile_user_data'] = attrs.get('hasFragileUserData')
        elif tag in ('activity', 'service', 'receiver', 'provider', 'activity-alias'):
            out['components'].append({
                'kind': tag, 'name': attrs.get('name'),
                'exported': attrs.get('exported'),
                'permission': attrs.get('permission'),
                'authorities': attrs.get('authorities'),
                'init_order': attrs.get('initOrder'),
                'label': attrs.get('label'),
            })
        elif tag == 'meta-data' and attrs.get('name'):
            out['meta_data_keys'].append(attrs['name'])
    out['permissions'] = sorted(set(out['permissions']))
    return out


def _lp(buf, off):
    n = struct.unpack_from('<I', buf, off)[0]
    return buf[off + 4:off + 4 + n], off + 4 + n


def signing_report(apk_path):
    with open(apk_path, 'rb') as f:
        f.seek(0, 2)
        size = f.tell()
        f.seek(size - 65557)
        tail = f.read()
        eocd = size - len(tail) + tail.rfind(b'PK\x05\x06')
        f.seek(eocd)
        _, _, _, _, _, cd_size, cd_off, _ = struct.unpack('<IHHHHIIH', f.read(22))
        f.seek(cd_off - 24)
        foot = f.read(24)
        block_size = struct.unpack('<Q', foot[:8])[0]
        magic = foot[8:24]
        out = {'cd_offset': cd_off, 'cd_size': cd_size,
               'signing_block_magic': magic.decode('latin1'),
               'signing_block_size': block_size, 'schemes': {}}
        if magic != b'APK Sig Block 42':
            return out
        start = cd_off - (block_size + 8)
        f.seek(start + 8)
        body = f.read(block_size - 8)
    off = 0
    ids = {SIG_V2: 'v2', SIG_V3: 'v3', SIG_PADDING: 'verity_padding'}
    while off + 16 <= len(body):
        length = struct.unpack_from('<Q', body, off)[0]
        if length < 4 or off + 8 + length > len(body):
            break
        sid = struct.unpack_from('<I', body, off + 8)[0]
        out['schemes'][ids.get(sid, '%#x' % sid)] = length
        if sid in (SIG_V2, SIG_V3):
            block = body[off + 12:off + 8 + length]
            try:
                seq, _ = _lp(block, 0)
                signer, _ = _lp(seq, 0)
                signed, outer = _lp(signer, 0)
                _digests, o = _lp(signed, 0)
                certs, o = _lp(signed, o)
                cert, _ = _lp(certs, 0)
                info = out['schemes'].setdefault(ids[sid] + '_detail', {})
                info['signer_cert_sha256'] = hashlib.sha256(cert).hexdigest()
                if ids[sid] == 'v3':
                    info['min_sdk'], info['max_sdk'] = struct.unpack_from('<II', signed, o)
            except struct.error:
                pass
        off += 8 + length
    return out


def v1_digest_report(apk_path, tree):
    """Verify every MANIFEST.MF SHA-256-Digest against the real entry bytes."""
    raw = open(os.path.join(tree, 'META-INF', 'MANIFEST.MF'), 'rb').read()
    sections, attrs = [], {}
    for line in raw.split(b'\r\n'):
        if not line.strip():
            if attrs:
                sections.append(attrs)
                attrs = {}
            continue
        if line.startswith(b' ') and attrs:
            attrs[list(attrs)[-1]] += line[1:]   # unfold (keeps trailing spaces)
        elif b':' in line:
            k, v = line.split(b':', 1)
            if v.startswith(b' '):
                v = v[1:]
            attrs[k.strip()] = v
    if attrs:
        sections.append(attrs)
    z = zipfile.ZipFile(apk_path)
    ok = bad = absent = 0
    bad_names = []
    for s in sections:
        name = s.get(b'Name')
        if not name:
            continue
        try:
            data = z.read(name.decode())
        except KeyError:
            absent += 1
            bad_names.append(name.decode())
            continue
        want = s.get(b'SHA-256-Digest')
        got = base64.b64encode(hashlib.sha256(data).digest())
        if want == got:
            ok += 1
        else:
            bad += 1
            bad_names.append(name.decode())
    sf = open(os.path.join(tree, 'META-INF', 'ANDROIDD.SF'), 'rb').read()
    m = re.search(rb'SHA-256-Digest-Manifest:\s*(\S+)', sf)
    return {'entries_verified': ok, 'mismatch': bad, 'absent': absent,
            'problems': bad_names[:20],
            'sf_manifest_digest_ok': bool(m) and
            base64.b64encode(hashlib.sha256(raw).digest()) == m.group(1)}


def _elf_needed(data):
    """Return DT_NEEDED entries of an ELF64 shared object (pure stdlib)."""
    if data[:4] != b'\x7fELF' or data[4] != 2:
        return []
    e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from('<HH', data, 0x36)
    dyn = None
    loads = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from('<II', data, off)
        p_offset, p_vaddr, _p_paddr, p_filesz = struct.unpack_from('<QQQQ', data, off + 8)
        if p_type == 1:            # PT_LOAD
            loads.append((p_vaddr, p_offset, p_filesz))
        elif p_type == 2:          # PT_DYNAMIC
            dyn = (p_offset, p_filesz)
    if not dyn:
        return []
    strtab = None
    needed_offsets = []
    for i in range(dyn[1] // 16):
        tag, val = struct.unpack_from('<QQ', data, dyn[0] + i * 16)
        if tag == 5:               # DT_STRTAB (virtual address)
            for vaddr, offset, filesz in loads:
                if vaddr <= val < vaddr + filesz:
                    strtab = offset + (val - vaddr)
                    break
        elif tag == 1:             # DT_NEEDED (offset into strtab)
            needed_offsets.append(val)
        elif tag == 0:
            break
    out = []
    if strtab is None:
        return out
    for o in needed_offsets:
        end = data.index(b'\x00', strtab + o)
        out.append(data[strtab + o:end].decode('latin1'))
    return out


def native_report(tree):
    so = os.path.join(tree, 'lib', 'arm64-v8a', 'libReverseSigma.so')
    data = open(so, 'rb').read()
    needed = _elf_needed(data)
    hits = []
    for m in re.finditer(rb'[\x20-\x7e]{5,}', data):
        for mm in re.finditer(rb'gat[oy]', m.group(), re.I):
            hits.append((m.start() + mm.start(), m.group().decode('latin1')))
    urls = sorted(set(re.findall(rb'https?://[\x21-\x7e]+', data)))
    dynsym = data
    exports = {
        'dobby': len(re.findall(rb'\x00(DobbyHook|MSHookFunction|MSHookThumb|MSHookX86_64|'
                                rb'A64HookFunctionV?|CodePatch)\x00', dynsym)),
        'jni_platform2': len(set(re.findall(
            rb'Java_com_mojang_minecraftpe_platforms_Platform2_([A-Za-z_0-9]+)', data))),
        'jni_onload': data.count(b'\x00JNI_OnLoad\x00'),
        'jni_onunload': data.count(b'\x00JNI_OnUnload\x00'),
    }
    return {
        'path': 'lib/arm64-v8a/libReverseSigma.so',
        'size': len(data),
        'elf_magic': data[:4].hex(),
        'needed_libs': needed,
        'network_imports_found': sorted({m.group(1).decode() for m in NETWORK_IMPORTS.finditer(data)}),
        'gatyo_gato_string_hits': len(hits),
        'gatyo_gato_first_hits': [{'offset': hex(o), 'text': t[:80]} for o, t in hits[:6]],
        'urls_in_binary': [u.decode('latin1') for u in urls],
        'exports': exports,
        'crash_strings': {s: data.count(s.encode()) for s in
                          ('gatyo_crash.txt', 'hooks %u/63', 'Iris requiere Bedrock',
                           'Dispatcher Iris incompatible', 'vtable no esta')},
        'identical_to_asset': sha256_file(so) == sha256_file(
            os.path.join(tree, 'assets', 'assets', 'icu', 'demo.dat')),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--apk', required=True)
    ap.add_argument('--tree', required=True)
    ap.add_argument('--json')
    args = ap.parse_args()

    rep = {'apk': args.apk}
    rep['apk_sha256'] = sha256_file(args.apk)
    rep['apk_matches_expected'] = rep['apk_sha256'] == EXPECTED_APK
    rep['apk_size'] = os.path.getsize(args.apk)

    nfiles = sum(len(f) for _, _, f in os.walk(args.tree))
    rep['file_count'] = nfiles

    ledger = {}
    for rel, want in EXPECTED.items():
        p = os.path.join(args.tree, rel)
        got = sha256_file(p) if os.path.exists(p) else None
        ledger[rel] = {'sha256': got, 'expected': want, 'match': got == want}
    rep['hash_ledger'] = ledger
    rep['hashes_all_match'] = all(v['match'] for v in ledger.values())

    rep['dex_class_counts'] = {
        n: dex_class_count(os.path.join(args.tree, n))
        for n in ('classes.dex', 'classes2.dex', 'classes3.dex',
                  'classes4.dex', 'classes5.dex', 'classes6.dex')
    }

    rep['manifest'] = manifest_report(os.path.join(args.tree, 'AndroidManifest.xml'))
    nsc = os.path.join(args.tree, 'res', 'xml', 'network_security_config.xml')
    if os.path.exists(nsc):
        rep['network_security_config'] = [
            {'tag': t, **{k: v for k, v in a.items() if k in ('cleartextTrafficPermitted', 'src')}}
            for t, a, _ in axml.elements(nsc)]

    rep['signatures'] = signing_report(args.apk)
    rep['v1_digests'] = v1_digest_report(args.apk, args.tree)
    rep['native'] = native_report(args.tree)

    # cheap cross-checks between the payload and the stock game library
    mcpe = os.path.join(args.tree, 'lib', 'arm64-v8a', 'libminecraftpe.so')
    if os.path.exists(mcpe):
        blob = open(mcpe, 'rb').read()
        rep['stock_game_lib'] = {
            'size': len(blob),
            'references_reversesigma': blob.count(b'ReverseSigma'),
            'references_gatyo': blob.lower().count(b'gatyo'),
        }

    text = json.dumps(rep, indent=2, default=str)
    if args.json:
        open(args.json, 'w').write(text + '\n')
        print('wrote', args.json)
    else:
        print(text)


if __name__ == '__main__':
    main()
