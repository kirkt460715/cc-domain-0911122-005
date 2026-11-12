"""WARC 1.1 本地解析器。

只处理字节：不执行页面、不访问网络。支持未压缩与单成员/拼接 gzip，
按 WARC/1.1 十进制 Content-Length 分帧，记录块摘要与正文摘要分开校验，
HTTP 头不计入正文。
"""
import hashlib
import re
import zlib
from sealvault.codec import fail, VaultError

DEFAULT_MAX_TOTAL = 67108864
DEFAULT_MAX_RECORD = 16777216
SUPPORTED_TYPES = {'warcinfo', 'response', 'revisit', 'metadata'}
RESPONSE_TYPES = {'response', 'revisit'}
REVISIT_PROFILE = 'http://netpreserve.org/warc/1.1/revisit/identical-payload-digest'
RECORD_ID_RE = re.compile(r'^<[!-~]{1,500}>$')
TOKEN_RE = re.compile(rb'^[!-~]+$')


def _gunzip_members(data, max_total):
    """解压单成员或拼接 gzip，限制解压总量。返回 (解压字节, 成员数)。"""
    output = bytearray()
    members = 0
    position = 0
    while position < len(data):
        members += 1
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            part = decompressor.decompress(data[position:], max_total + 1)
            output.extend(part)
            if decompressor.unconsumed_tail or len(output) > max_total:
                fail('warc_limit', 'Decompressed WARC stream exceeds total byte limit', limit=max_total)
            if not decompressor.eof:
                fail('warc_gzip', 'gzip member is truncated or corrupt', member=members)
        except zlib.error as exc:
            raise VaultError('warc_gzip', 'Cannot decompress gzip member', member=members) from exc
        position += len(data[position:]) - len(decompressor.unused_data)
        if not decompressor.unused_data:
            break
    if members == 0:
        fail('warc_gzip', 'Empty gzip container')
    return bytes(output), members


def _read_headers(blob, offset):
    """读取 WARC 记录头，返回 (头字段列表, 块起点)。"""
    boundary = blob.find(b'\r\n\r\n', offset)
    if boundary < 0:
        fail('warc_frame', 'Record header is not terminated by CRLF CRLF', offset=offset)
    head = blob[offset:boundary]
    lines = head.split(b'\r\n')
    if not lines or lines[0] != b'WARC/1.1':
        fail('warc_version', 'Only WARC/1.1 records are supported', offset=offset)
    headers = []
    seen = set()
    for line in lines[1:]:
        if b':' not in line or any(byte < 32 or byte > 126 for byte in line):
            fail('warc_header', 'Malformed WARC header line', offset=offset)
        name, value = line.split(b':', 1)
        key = name.decode('ascii').lower()
        if not TOKEN_RE.match(name):
            fail('warc_header', 'Malformed WARC header field name', offset=offset)
        text_value = value.strip().decode('iso-8859-1')
        if not text_value or any(ord(char) < 32 or ord(char) > 126 for char in text_value):
            fail('warc_header', 'Malformed WARC header field value', field=key)
        if key in seen:
            fail('warc_header', 'Repeated WARC header field', field=key)
        seen.add(key)
        headers.append((key, text_value))
    return headers, boundary + 4


def _header(headers, name):
    matches = [value for key, value in headers if key == name]
    return matches[0] if matches else None


def _parse_http(block):
    """解析 application/http 块，返回 (状态码, HTTP 头, 实体字节)。

    实体严格按 HTTP Content-Length 切分，HTTP 头不属于正文。
    """
    boundary = block.find(b'\r\n\r\n')
    if boundary < 0:
        fail('warc_http', 'HTTP message lacks a header/body boundary')
    status_line = block[:block.find(b'\r\n')]
    pieces = status_line.split(b' ', 2)
    if len(pieces) < 2 or not pieces[0].startswith(b'HTTP/') or not pieces[1].isdigit() or not 100 <= int(pieces[1]) <= 599:
        fail('warc_http_status', 'Malformed HTTP status line')
    status = int(pieces[1])
    http_headers = {}
    for line in block[block.find(b'\r\n') + 2:boundary].split(b'\r\n'):
        if not line:
            continue
        if b':' not in line:
            fail('warc_http', 'Malformed HTTP header line')
        name, value = line.split(b':', 1)
        http_headers[name.decode('iso-8859-1').strip().lower()] = value.strip().decode('iso-8859-1')
    declared = http_headers.get('content-length')
    if declared is None or not re.fullmatch(r'\d+', declared):
        fail('warc_http_length', 'HTTP entity requires a decimal Content-Length')
    entity_length = int(declared)
    start = boundary + 4
    entity = block[start:start + entity_length]
    if len(entity) != entity_length:
        fail('warc_http_length', 'HTTP entity is shorter than its Content-Length')
    # WARC 块到实体即结束；块结束的 CRLF CRLF 属于 WARC 分帧，不进入块字节。
    if start + entity_length != len(block):
        fail('warc_http', 'HTTP block contains bytes beyond the declared entity')
    return status, http_headers, entity


def _digest_value(value):
    """解析 'sha256:<hex>'，返回十六进制摘要；无法识别返回 None。"""
    if value is None:
        return None
    match = re.fullmatch(r'sha256:([0-9a-f]{64})', value)
    return match.group(1) if match else False


def parse_archive(data, max_total=DEFAULT_MAX_TOTAL, max_record=DEFAULT_MAX_RECORD, partial=False):
    """解析整个 WARC 归档（字节在内存中，但总量受限）。

    返回 {'records': [...], 'errors': [...], 'gzip_members': n,
          'compressed': bool, 'decompressed_bytes': n, 'fatal': 错误描述或 None}。
    记录级语义问题进入 errors 并保留记录摘要；分帧/截断/超限为致命错误：
    partial=False 时抛出，partial=True 时在 fatal 中返回原因，且此前已解析的
    记录全部保留——损坏尾部不能让前面已暂存内容被当成整包成功。
    """
    if not isinstance(data, (bytes, bytearray)):
        fail('warc_input', 'WARC source must be raw bytes')
    data = bytes(data)
    compressed = data[:2] == b'\x1f\x8b'
    try:
        if compressed:
            blob, members = _gunzip_members(data, max_total)
        else:
            blob, members = data, 0
            if len(blob) > max_total:
                fail('warc_limit', 'WARC stream exceeds total byte limit', limit=max_total)
    except VaultError as exc:
        if partial:
            return {'records': [], 'errors': [], 'gzip_members': 0, 'compressed': compressed,
                    'decompressed_bytes': 0, 'fatal': exc.payload()}
        raise
    records = []
    errors = []
    fatal = None
    offset = 0
    ordinal = 0
    while offset < len(blob):
        if blob[offset:offset + 5] != b'WARC/':
            fatal = VaultError('warc_frame', 'Unexpected bytes between records', ordinal=ordinal, offset=offset).payload()
            break
        ordinal += 1
        # 分帧阶段：头、Content-Length、整块读取与尾部 CRLF。任何失败都会让
        # 整个归档中止，但 records 中此前已解析的记录仍然保留给调用方暂存。
        try:
            headers, block_start = _read_headers(blob, offset)
            length_text = _header(headers, 'content-length')
            if length_text is None or not re.fullmatch(r'\d+', length_text):
                fail('warc_length', 'Record requires a decimal WARC Content-Length', ordinal=ordinal)
            length = int(length_text)
            if length > max_record:
                fail('warc_record_limit', 'Record exceeds single-record byte limit', ordinal=ordinal, limit=max_record, declared=length)
            block = blob[block_start:block_start + length]
            if len(block) != length:
                fail('warc_truncated', 'Record block is shorter than its Content-Length', ordinal=ordinal)
            if blob[block_start + length:block_start + length + 4] != b'\r\n\r\n':
                fail('warc_frame', 'Record must end with CRLF CRLF after its block', ordinal=ordinal)
        except VaultError as exc:
            fatal = exc.payload()
            break
        record = {'ordinal': ordinal, 'errors': [], 'block': block, 'block_length': length,
                  'headers': dict(headers)}
        try:
            record['record_id'] = _require(headers, 'warc-record-id')
            if not RECORD_ID_RE.match(record['record_id']):
                fail('warc_record_id', 'WARC-Record-ID must be a bounded bracketed token')
            kind = _require(headers, 'warc-type').lower()
            if kind not in SUPPORTED_TYPES:
                fail('warc_type', 'Unsupported WARC record type', supported=sorted(SUPPORTED_TYPES), actual=kind)
            record['type'] = kind
            record['date'] = _require(headers, 'warc-date')
            record['target_uri'] = _header(headers, 'warc-target-uri')
            record['refers_to'] = _header(headers, 'warc-refers-to')
            record['profile'] = _header(headers, 'warc-profile')
            record['declared_block_digest'] = _digest_value(_header(headers, 'warc-block-digest'))
            record['declared_payload_digest'] = _digest_value(_header(headers, 'warc-payload-digest'))
            record['actual_block_digest'] = hashlib.sha256(block).hexdigest()
            _validate_record(record, headers)
        except VaultError as exc:
            record['errors'].append(exc.payload())
            errors.append({'ordinal': ordinal, **exc.payload()})
        records.append(record)
        offset = block_start + length + 4
    if not records and fatal is None:
        fatal = VaultError('warc_empty', 'Archive contains no WARC records').payload()
    result = {'records': records, 'errors': errors, 'gzip_members': members,
              'compressed': compressed, 'decompressed_bytes': len(blob), 'fatal': fatal}
    if fatal and not partial:
        fail(fatal['code'], fatal['message'], **fatal['details'])
    return result


def _require(headers, name):
    value = _header(headers, name)
    if value is None:
        fail('warc_header', 'Required WARC header is absent', field=name)
    return value


def _validate_record(record, headers):
    if record['declared_block_digest'] is None:
        fail('warc_digest', 'Record requires a sha256 WARC-Block-Digest')
    if record['declared_block_digest'] is False:
        fail('warc_digest', 'WARC-Block-Digest uses an unsupported algorithm or form')
    if record['actual_block_digest'] != record['declared_block_digest']:
        fail('warc_block_digest', 'Record block digest differs from declaration',
             declared=record['declared_block_digest'], actual=record['actual_block_digest'])
    if record['type'] in RESPONSE_TYPES:
        if _header(headers, 'content-type') != 'application/http; msgtype=response':
            fail('warc_content_type', 'Response records must carry application/http; msgtype=response')
        status, http_headers, entity = _parse_http(record['block'])
        record['http_status'] = status
        record['http_headers'] = http_headers
        record['payload'] = entity
        record['actual_payload_digest'] = hashlib.sha256(entity).hexdigest()
        if record['type'] == 'response':
            if record['declared_payload_digest'] is None:
                fail('warc_digest', 'Response record requires a sha256 WARC-Payload-Digest')
            if record['declared_payload_digest'] is False:
                fail('warc_digest', 'WARC-Payload-Digest uses an unsupported algorithm or form')
            if record['actual_payload_digest'] != record['declared_payload_digest']:
                fail('warc_payload_digest', 'Payload digest differs from declaration; HTTP headers are not payload',
                     declared=record['declared_payload_digest'], actual=record['actual_payload_digest'])
        else:
            if record['profile'] != REVISIT_PROFILE:
                fail('warc_profile', 'Only identical-payload-digest revisit records are supported')
            if not record['refers_to'] or not RECORD_ID_RE.match(record['refers_to']):
                fail('warc_refers_to', 'Revisit record requires a bracketed WARC-Refers-To target')
            if record['declared_payload_digest'] in (None, False):
                fail('warc_digest', 'Revisit record requires a sha256 WARC-Payload-Digest')
            # revisit 块是独立摘要（自己的小响应头块）；其正文摘要沿引用链与目标正文核对。
    elif record['type'] == 'metadata':
        record['payload'] = record['block']
        record['actual_payload_digest'] = record['actual_block_digest']
    if record['type'] in RESPONSE_TYPES and not record.get('target_uri'):
        fail('warc_target', 'Capture record requires WARC-Target-URI')
