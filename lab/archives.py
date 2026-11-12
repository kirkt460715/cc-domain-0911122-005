import gzip
import hashlib
from pathlib import Path

BASE = '00000000-0000-0000-0000-'


def identity(n):
    return '<urn:uuid:' + BASE + f'{n:012d}>'


def record(n, kind, body, extra=None):
    headers = {'WARC-Type': kind, 'WARC-Record-ID': identity(n), 'WARC-Date': '2026-11-01T00:00:00Z',
               'WARC-Target-URI': 'https://example.invalid/maintenance',
               'Content-Type': 'application/http; msgtype=response' if kind in ['response', 'revisit'] else 'application/warc-fields',
               'WARC-Block-Digest': 'sha256:' + hashlib.sha256(body).hexdigest(),
               'Content-Length': str(len(body))}
    headers.update(extra or {})
    return ('WARC/1.1\r\n' + ''.join(k + ': ' + v + '\r\n' for k, v in headers.items()) + '\r\n').encode() + body + b'\r\n\r\n'


def http_response(status, payload, content_type='text/plain; charset=utf-8'):
    return (f'HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {len(payload)}\r\n\r\n').encode() + payload


def samples():
    payload = '合成维护正文。'.encode()
    http = http_response('200 OK', payload)
    sha = 'sha256:' + hashlib.sha256(payload).hexdigest()
    response = record(1, 'response', http, {'WARC-Payload-Digest': sha})
    revisit_block = http_response('200 OK', b'')
    revisit = record(2, 'revisit', revisit_block,
                     {'WARC-Refers-To': identity(1), 'WARC-Payload-Digest': sha,
                      'WARC-Profile': 'http://netpreserve.org/warc/1.1/revisit/identical-payload-digest'})
    meta = record(3, 'metadata', 'collector: 合成归档器\r\n'.encode(), {'WARC-Refers-To': identity(1)})
    cycle = record(4, 'revisit', revisit_block, {'WARC-Refers-To': identity(5), 'WARC-Payload-Digest': sha,
                                                 'WARC-Profile': 'http://netpreserve.org/warc/1.1/revisit/identical-payload-digest'}) + \
        record(5, 'revisit', revisit_block, {'WARC-Refers-To': identity(4), 'WARC-Payload-Digest': sha,
                                             'WARC-Profile': 'http://netpreserve.org/warc/1.1/revisit/identical-payload-digest'})
    return {'forward.warc': revisit + response + meta, 'first.warc': response, 'later.warc': revisit,
            'cycle.warc': cycle, 'truncated.warc': response + revisit[:-8],
            'repeated.warc': response + response,
            'joined.warc.gz': gzip.compress(revisit, mtime=0) + gzip.compress(response + meta, mtime=0)}


def conflict_sample():
    """同一 record-id 换了正文：必须报冲突，不能按 URL 合并。"""
    original_payload = '原始正文。'.encode()
    changed_payload = '被替换的正文。'.encode()
    first = record(10, 'response', http_response('200 OK', original_payload),
                   {'WARC-Payload-Digest': 'sha256:' + hashlib.sha256(original_payload).hexdigest()})
    second = record(10, 'response', http_response('200 OK', changed_payload),
                    {'WARC-Payload-Digest': 'sha256:' + hashlib.sha256(changed_payload).hexdigest()})
    return {'conflict.warc': first + second}


def cross_package_samples():
    """跨包引用：later 包中的 revisit 指向 earlier 包已收录的捕获。"""
    payload = '跨包共享正文。'.encode()
    sha = 'sha256:' + hashlib.sha256(payload).hexdigest()
    response = record(20, 'response', http_response('200 OK', payload), {'WARC-Payload-Digest': sha})
    revisit = record(21, 'revisit', http_response('200 OK', b''),
                     {'WARC-Refers-To': identity(20), 'WARC-Payload-Digest': sha,
                      'WARC-Profile': 'http://netpreserve.org/warc/1.1/revisit/identical-payload-digest'})
    return {'earlier.warc': response, 'later-ref.warc': revisit}


def build(directory):
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    for name, content in {**samples(), **conflict_sample(), **cross_package_samples()}.items():
        (d / name).write_bytes(content)
    return d


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('directory')
    print(build(p.parse_args().directory))
