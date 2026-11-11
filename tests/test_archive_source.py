import unittest,gzip,re
from lab.archives import samples,identity
class ArchiveSource(unittest.TestCase):
    def test_forward_reference_and_gzip(self):
        s=samples();self.assertEqual(gzip.decompress(s['joined.warc.gz']),s['forward.warc'])
        self.assertLess(s['forward.warc'].index(b'WARC-Type: revisit'),s['forward.warc'].index(b'WARC-Type: response'))
        self.assertIn(identity(1).encode(),s['later.warc'])
    def test_declared_length(self):
        header,body=samples()['first.warc'].split(b'\r\n\r\n',1)
        length=int(re.search(rb'Content-Length: (\d+)',header).group(1))
        self.assertEqual(len(body),length+4)
