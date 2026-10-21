#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent synthetic archive/bitstream contracts; contains no external assets."""
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

TYPES = {'u16': (2, '>H'), 'u32': (4, '>I'), 's32': (5, '>i'), 'u64': (6, '>Q')}


def utf(name, columns, rows):
    strings = bytearray()
    def string(text):
        off = len(strings)
        strings.extend(text.encode('ascii') + b'\0')
        return off
    table_name = string(name)
    schema = bytearray()
    for key, kind in columns:
        schema.extend(bytes([0x50 | (11 if kind == 'blob' else TYPES[kind][0])]))
        schema.extend(struct.pack('>I', string(key)))
    values, blobs = bytearray(), bytearray()
    width = sum(8 if kind == 'blob' else struct.calcsize(TYPES[kind][1]) for _, kind in columns)
    for row in rows:
        for key, kind in columns:
            if kind == 'blob':
                values.extend(struct.pack('>II', len(blobs), len(row[key])))
                blobs.extend(row[key])
            else:
                values.extend(struct.pack(TYPES[kind][1], row[key]))
    at_rows = 32 + len(schema)
    at_strings = at_rows + len(values)
    at_data = at_strings + len(strings)
    total = at_data + len(blobs)
    return (b'@UTF' + struct.pack('>IHHIIIHHI', total - 8, 0, at_rows - 8,
            at_strings - 8, at_data - 8, table_name, len(columns), width, len(rows)) +
            schema + values + strings + blobs)


def encrypt(data):
    seed = 0x655f
    out = bytearray()
    for value in data:
        out.append(value ^ (seed & 255))
        seed = seed * 0x4115 & 0xffffffff
    return out


def packet(tag, data, encrypted=False):
    return tag + struct.pack('<IQ', 255, len(data)) + (encrypt(data) if encrypted else data)


def archive(mode='extended', encrypted=False, bad=None, payload=None, extract_size=None):
    toc_at, itoc_at, content = 0x400, 0x800, 0x1000
    rows = [dict(ID=42, FileSize=4, ExtractSize=4, FileOffset=content-toc_at),
            dict(ID=7, FileSize=3, ExtractSize=3, FileOffset=content+0x100-toc_at)]
    if payload is not None:
        rows[0]['FileSize'] = len(payload)
        rows[0]['ExtractSize'] = extract_size
        rows[1]['FileOffset'] = content+0x1000-toc_at
    if bad == 'duplicate_id': rows[1]['ID'] = 42
    if bad == 'offset_overflow': rows[0]['FileOffset'] = 0xffffffffffffffff
    if bad == 'range': rows[0]['FileSize'] = 0xffffffff
    cols = [('ID', 'u32'), ('FileSize', 'u32'), ('ExtractSize', 'u32'), ('FileOffset', 'u64')]
    if bad == 'no_id': cols = cols[1:]
    if bad == 'duplicate_column': cols = cols + [('ID', 'u32')]
    toc = utf('CpkTocInfo', cols, rows)
    maps = [dict(ID=7, TocIndex=1), dict(ID=42, TocIndex=0)]
    if bad == 'map_index': maps[0]['TocIndex'] = 2
    if bad == 'map_id': maps[0]['ID'] = 8
    if bad == 'map_duplicate': maps[1] = maps[0].copy()
    if bad == 'map_negative': maps[0]['TocIndex'] = -1
    if bad == 'map_short': maps.pop()
    itoc = utf('CpkExtendId', [('ID', 's32'), ('TocIndex', 's32')], maps)
    if mode == 'legacy':
        high = utf('ItocH', [('ID', 'u16'), ('FileSize', 'u32'), ('ExtractSize', 'u32')],
                   [dict(ID=42, FileSize=4, ExtractSize=4)])
        low = utf('ItocL', [('ID', 'u16'), ('FileSize', 'u16'), ('ExtractSize', 'u16')],
                  [dict(ID=7, FileSize=3, ExtractSize=3)])
        itoc = utf('CpkItocInfo', [('DataH', 'blob'), ('DataL', 'blob')], [dict(DataH=high, DataL=low)])
    header = dict(ContentOffset=content, TocOffset=0 if mode == 'legacy' else toc_at,
                  TocSize=0 if mode == 'legacy' else len(toc)+16,
                  ItocOffset=0 if mode == 'toc' else itoc_at,
                  ItocSize=0 if mode == 'toc' else len(itoc)+16, Files=2, Align=0x100)
    if bad == 'count': header['Files'] = 3
    if bad == 'align': header['Align'] = 0
    if bad == 'extent': header['TocSize'] = 24
    hdr = utf('CpkHeader', [(key, 'u64') for key in header], [header])
    if bad in ('version', 'schema', 'rows', 'strings'):
        hdr = bytearray(hdr)
        if bad == 'version': struct.pack_into('>H', hdr, 8, 1)
        elif bad == 'schema': struct.pack_into('>H', hdr, 10, 1)
        elif bad == 'rows': struct.pack_into('>I', hdr, 28, 2)
        else: struct.pack_into('>I', hdr, 20, 0xffffffff)
    buf = bytearray(content+(0x2000 if payload is not None else 0x200))
    for at, tag, data in [(0, b'CPK ', hdr), (toc_at, b'TOC ', toc), (itoc_at, b'ITOC', itoc)]:
        p = packet(tag, data, encrypted)
        assert at + len(p) <= content
        buf[at:at+len(p)] = p
    if bad == 'packet_size': struct.pack_into('<Q', buf, toc_at+8, 0xffffffffffffffff)
    buf[content:content+4] = b'ABCD'
    second = content+(0x1000 if payload is not None else 0x100)
    buf[second:second+3] = b'xyz'
    if payload is not None: buf[content:content+len(payload)] = payload
    return bytes(buf)


PREFIX = bytes(range(256))


def compressed(tokens, body_size):
    bits = ''
    for token in tokens:
        if token[0] == 'literal': bits += '0' + f'{token[1]:08b}'
        else:
            _, distance, length = token
            bits += '1' + f'{distance-3:013b}'
            remaining = length - 3
            for width in (2, 3, 5):
                chunk = min(remaining, (1 << width)-1)
                bits += f'{chunk:0{width}b}'
                remaining -= chunk
                if chunk < (1 << width)-1: break
            else:
                while remaining >= 255:
                    bits += '11111111'; remaining -= 255
                bits += f'{remaining:08b}'
    bits += '0' * (-len(bits) % 8)
    stream = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))[::-1]
    return b'CRILAYLA' + struct.pack('<II', body_size, len(stream)) + stream + PREFIX


def main():
    probe, case = sys.argv[1:]
    with tempfile.TemporaryDirectory(prefix='cpkrt-contract-') as folder:
        path = Path(folder) / 'synthetic.bin'
        def run(command, data, ok=True, *args):
            path.write_bytes(data)
            result = subprocess.run([probe, command, str(path), *args], capture_output=True)
            if (result.returncode == 0) != ok or result.returncode < 0:
                raise AssertionError(f'{case}/{command}: exit {result.returncode}: {result.stderr!r}')
            if b'Sanitizer' in result.stderr or b'runtime error:' in result.stderr:
                raise AssertionError(result.stderr)
            return result.stdout
        def index(data, command='index'):
            return [list(map(int, line.split())) for line in run(command, data).splitlines()]
        if case in ('toc', 'extended', 'encrypted'):
            data = archive('toc' if case == 'toc' else 'extended', case == 'encrypted')
            assert index(data) == [[2, 256, 2], [7, 1, 4352, 3, 3], [42, 0, 4096, 4, 4]]
            assert run('extract', data, True, '2a') == b'ABCD'
            assert run('extract', data, True, '7') == b'xyz'
            run('extract', data, False, '8')
        elif case == 'legacy':
            data = archive('legacy')
            assert index(data) == [[2, 256, 2], [7, 1, 4096, 3, 3], [42, 0, 4352, 4, 4]]
            assert index(data, 'table') == [[2, 256, 2], [7, 1, 4352, 3, 3], [42, 0, 4096, 4, 4]]
        elif case == 'bounds':
            for bad in ('duplicate_id', 'offset_overflow', 'range', 'no_id', 'duplicate_column',
                        'map_index', 'map_id', 'map_duplicate', 'map_negative', 'map_short',
                        'count', 'align', 'extent', 'version', 'schema', 'rows', 'strings', 'packet_size'):
                run('index', archive(bad=bad), False)
            run('index', archive()[:30], False)
        elif case == 'provider_raw':
            data = archive()
            assert run('files', data, True, '2a') == b'ABCD'
            assert run('read_into', data, True, '2a') == b'ABCD'
            assert run('files', data, True, '7') == b'xyz'
            assert run('read_into', data, True, '7') == b'xyz'
            run('files', data, False, '8')
            run('read_into', data, False, '8')
        elif case == 'provider_packed':
            tail = b'ABC'+bytes(b'ABC'[i % 3] for i in range(600))
            packed = compressed([('literal', value) for value in b'ABC']+[('ref', 3, 600)], len(tail))
            data = archive(payload=packed, extract_size=256+len(tail))
            assert run('files', data, True, '2a') == PREFIX+tail[::-1]
            assert run('read_into', data, True, '2a') == run('files', data, True, '2a')
            run('files', archive(payload=packed, extract_size=257+len(tail)), False, '2a')
            run('read_into', archive(payload=packed, extract_size=257+len(tail)), False, '2a')
            run('files', archive(payload=b'badcompressed', extract_size=300), False, '2a')
            run('read_into', archive(payload=b'badcompressed', extract_size=300), False, '2a')
            run('files', archive(payload=packed, extract_size=67108865), False, '2a')
            run('read_into', archive(payload=packed, extract_size=67108865), False, '2a')
            run('read_into', archive(payload=b'', extract_size=300), False, '2a')
            run('files', archive(payload=b'', extract_size=0), True, '2a')
        elif case == 'provider_contracts': run('provider_contracts', archive())
        elif case == 'files_errors':
            for bad in ('map_index', 'no_id', 'count', 'range'):
                run('files', archive(bad=bad), False, '2a')
            path.unlink()
            result = subprocess.run([probe, 'files', str(path), '2a'], capture_output=True)
            assert result.returncode == 1 and b'file open status 1' in result.stderr
            result = subprocess.run([probe, 'files', folder, '2a'], capture_output=True)
            assert result.returncode == 1
        elif case == 'fixture_cli':
            generated = Path(folder) / 'generated.cpk'
            subprocess.run([sys.executable, str(Path(__file__).with_name('make_fixture.py')),
                            str(generated), '--mode', 'extended', '--encrypt'],
                           check=True, capture_output=True)
            data = generated.read_bytes()
            assert index(data) == [[2, 256, 2], [7, 1, 4352, 3, 3], [42, 0, 4096, 4, 4]]
            assert run('extract', data, True, '2a') == b'ABCD'
        elif case == 'lifecycle': run('lifecycle', archive())
        elif case == 'literals':
            for tail in (b'', b'A', bytes(range(256)), b'Literal\x00\xff\n\r stream'):
                data = compressed([('literal', value) for value in tail[::-1]], len(tail))
                assert run('decode', data) == PREFIX+tail
                assert run('decode', data+b'padding') == PREFIX+tail
        elif case == 'references':
            for length in (3, 6, 10, 13, 41, 45, 300, 600):
                decoded_reverse = b'ABC' + bytes(b'ABC'[i % 3] for i in range(length))
                tokens = [('literal', value) for value in b'ABC']+[('ref', 3, length)]
                assert run('decode', compressed(tokens, len(decoded_reverse))) == PREFIX+decoded_reverse[::-1]
        elif case == 'decode_errors':
            valid = compressed([('literal', 65)], 1)
            for data in (b'', valid[:15], b'badmagic'+valid[8:], valid[:-1],
                         compressed([], 1), compressed([('ref', 3, 3)], 3),
                         compressed([('literal', 65)]*3+[('ref', 3, 6)], 6)):
                run('decode', data, False)
        else: raise ValueError(case)
    print(f'{case}: independent CPK/CRILAYLA contracts pass')


if __name__ == '__main__': main()
