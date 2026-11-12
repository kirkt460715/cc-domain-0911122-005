import gzip
import unittest
from sealvault.codec import VaultError, sha256
from sealvault.webarchive import warc
from lab.archives import samples, record, http_response, identity


class WarcParser(unittest.TestCase):
    def test_response_payload_digest_excludes_http_headers(self):
        payload = '正文。'.encode()
        http = http_response('200 OK', payload)
        block = record(1, 'response', http, {'WARC-Payload-Digest': 'sha256:' + sha256(payload)})
        result = warc.parse_archive(block)
        self.assertIsNone(result['fatal'])
        parsed = result['records'][0]
        self.assertEqual(parsed['http_status'], 200)
        self.assertEqual(parsed['payload'], payload)
        # 块摘要覆盖整个 HTTP 块；正文摘要只覆盖实体，二者不同。
        self.assertNotEqual(parsed['actual_block_digest'], parsed['actual_payload_digest'])
        self.assertEqual(parsed['actual_payload_digest'], sha256(payload))
        self.assertEqual(parsed['actual_block_digest'], sha256(http))

    def test_wrong_payload_digest_is_record_error_not_frame_failure(self):
        payload = b'x'
        http = http_response('200 OK', payload)
        block = record(1, 'response', http, {'WARC-Payload-Digest': 'sha256:' + '0' * 64})
        result = warc.parse_archive(block, partial=True)
        self.assertIsNone(result['fatal'])
        self.assertEqual([e['code'] for e in result['errors']], ['warc_payload_digest'])

    def test_wrong_block_digest_is_detected(self):
        payload = b'x'
        block = record(1, 'response', http_response('200 OK', payload),
                       {'WARC-Payload-Digest': 'sha256:' + sha256(payload)})
        tampered = block.replace(b'200 OK', b'201 OK')
        self.assertEqual(len(tampered), len(block))
        result = warc.parse_archive(tampered, partial=True)
        self.assertIn('warc_block_digest', [e['code'] for e in result['errors']])

    def test_forward_revisit_then_response_parses_in_order(self):
        result = warc.parse_archive(samples()['forward.warc'], partial=True)
        self.assertIsNone(result['fatal'])
        self.assertEqual([r['type'] for r in result['records']], ['revisit', 'response', 'metadata'])

    def test_joined_gzip_members_are_split(self):
        bundle = samples()['joined.warc.gz']
        result = warc.parse_archive(bundle)
        self.assertTrue(result['compressed'])
        self.assertEqual(result['gzip_members'], 2)
        self.assertEqual(len(result['records']), 3)
        plain = warc.parse_archive(samples()['forward.warc'])
        self.assertEqual([r['record_id'] for r in result['records']],
                         [r['record_id'] for r in plain['records']])

    def test_truncated_tail_is_fatal_but_earlier_records_survive(self):
        result = warc.parse_archive(samples()['truncated.warc'], partial=True)
        self.assertEqual(result['fatal']['code'], 'warc_truncated')
        self.assertEqual(len(result['records']), 1)
        self.assertEqual(result['records'][0]['type'], 'response')
        with self.assertRaises(VaultError) as raised:
            warc.parse_archive(samples()['truncated.warc'])
        self.assertEqual(raised.exception.code, 'warc_truncated')

    def test_total_and_record_limits_enforced(self):
        data = samples()['first.warc']
        with self.assertRaises(VaultError) as raised:
            warc.parse_archive(data, max_total=10)
        self.assertEqual(raised.exception.code, 'warc_limit')
        with self.assertRaises(VaultError) as raised:
            warc.parse_archive(data, max_record=10)
        self.assertEqual(raised.exception.code, 'warc_record_limit')

    def test_gzip_bomb_is_capped(self):
        bomb = gzip.compress(b'0' * 100000)
        with self.assertRaises(VaultError) as raised:
            warc.parse_archive(bomb, max_total=1000)
        self.assertEqual(raised.exception.code, 'warc_limit')

    def test_corrupt_gzip_member_is_fatal(self):
        good = gzip.compress(b'WARC/1.1\r\n\r\n', mtime=0)
        corrupt = good[:-6] + b'XXXXXX'
        result = warc.parse_archive(corrupt, partial=True)
        self.assertEqual(result['fatal']['code'], 'warc_gzip')
        joined = good + corrupt
        self.assertEqual(warc.parse_archive(joined, partial=True)['fatal']['code'], 'warc_gzip')

    def test_unsupported_type_and_bad_version_rejected(self):
        bad = record(1, 'request', b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
        result = warc.parse_archive(bad, partial=True)
        self.assertIn('warc_type', [e['code'] for e in result['errors']])
        with self.assertRaises(VaultError) as raised:
            warc.parse_archive(b'WARC/1.0\r\nWARC-Type: response\r\n\r\n')
        self.assertEqual(raised.exception.code, 'warc_version')

    def test_metadata_record_is_stored_without_http(self):
        result = warc.parse_archive(samples()['forward.warc'])
        meta = next(r for r in result['records'] if r['type'] == 'metadata')
        self.assertNotIn('http_status', meta)
        self.assertEqual(meta['actual_payload_digest'], meta['actual_block_digest'])

    def test_revisit_requires_profile_and_reference(self):
        payload = b'x'
        sha = 'sha256:' + sha256(payload)
        no_profile = record(2, 'revisit', http_response('200 OK', b''),
                            {'WARC-Refers-To': identity(1), 'WARC-Payload-Digest': sha})
        result = warc.parse_archive(no_profile, partial=True)
        self.assertIn('warc_profile', [e['code'] for e in result['errors']])


if __name__ == '__main__':
    unittest.main()
