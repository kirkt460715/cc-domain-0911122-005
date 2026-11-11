import hashlib,gzip
from pathlib import Path
BASE='00000000-0000-0000-0000-'
def identity(n):return '<urn:uuid:'+BASE+f'{n:012d}>'
def record(n,kind,body,extra=None):
    headers={'WARC-Type':kind,'WARC-Record-ID':identity(n),'WARC-Date':'2026-11-01T00:00:00Z','WARC-Target-URI':'https://example.invalid/maintenance','Content-Type':'application/http; msgtype=response' if kind in ['response','revisit'] else 'application/warc-fields','WARC-Block-Digest':'sha256:'+hashlib.sha256(body).hexdigest(),'Content-Length':str(len(body))}
    headers.update(extra or {})
    return ('WARC/1.1\r\n'+''.join(k+': '+v+'\r\n' for k,v in headers.items())+'\r\n').encode()+body+b'\r\n\r\n'
def samples():
    payload='合成维护正文。'.encode();http=b'HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: '+str(len(payload)).encode()+b'\r\n\r\n'+payload
    sha='sha256:'+hashlib.sha256(payload).hexdigest()
    response=record(1,'response',http,{'WARC-Payload-Digest':sha})
    revisit=record(2,'revisit',b'HTTP/1.1 200 OK\r\n\r\n',{'WARC-Refers-To':identity(1),'WARC-Payload-Digest':sha,'WARC-Profile':'http://netpreserve.org/warc/1.1/revisit/identical-payload-digest'})
    meta=record(3,'metadata','collector: 合成归档器\r\n'.encode(),{'WARC-Refers-To':identity(1)})
    cycle=record(4,'revisit',b'HTTP/1.1 200 OK\r\n\r\n',{'WARC-Refers-To':identity(5),'WARC-Payload-Digest':sha})+record(5,'revisit',b'HTTP/1.1 200 OK\r\n\r\n',{'WARC-Refers-To':identity(4),'WARC-Payload-Digest':sha})
    return {'forward.warc':revisit+response+meta,'first.warc':response,'later.warc':revisit,'cycle.warc':cycle,'truncated.warc':response+revisit[:-8],'repeated.warc':response+response,'joined.warc.gz':gzip.compress(revisit,mtime=0)+gzip.compress(response+meta,mtime=0)}
def build(directory):
    d=Path(directory);d.mkdir(parents=True,exist_ok=True)
    for name,content in samples().items():(d/name).write_bytes(content)
    return d
if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('directory');print(build(p.parse_args().directory))
