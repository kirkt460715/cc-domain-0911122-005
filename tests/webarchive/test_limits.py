import unittest
from tests.support import Case
from sealvault.codec import encode
from sealvault.custody import actors
from lab.archives import samples


class WarcLimitsAndRouting(Case):
    def setUp(self):
        super().setUp()
        self.bundles = samples()

    def test_lower_total_limit_marks_failed_without_partial_success(self):
        self.vault.cases.create('case-a', '限额案件', 'collector')
        result = self.vault.webarchives.ingest('ing-small', 'first.warc', self.bundles['first.warc'],
                                               'collector', max_total=32, max_record=16)
        self.assertEqual(result['state'], 'failed')
        self.assertEqual(result['reason']['code'], 'warc_limit')
        # 超限在解压/分帧前发生，没有任何记录或对象被暂存。
        self.assertEqual(len(result['records']), 0)
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM objects'), 0)

    def test_record_limit_marks_failed_but_ingest_never_mounts(self):
        self.vault.cases.create('case-a', '限额案件', 'collector')
        result = self.vault.webarchives.ingest('ing-record', 'first.warc', self.bundles['first.warc'],
                                               'collector', max_total=4096, max_record=32)
        self.assertEqual(result['state'], 'failed')
        self.assertEqual(result['reason']['code'], 'warc_record_limit')
        self.error('warc_state', self.vault.webarchives.resolve, 'ing-record', 'collector')

    def test_metadata_record_is_not_a_capture(self):
        self.vault.cases.create('case-a', '元数据案件', 'collector')
        result = self.vault.webarchives.ingest('ing-meta', 'forward.warc', self.bundles['forward.warc'], 'collector')
        types = {r['record_type'] for r in result['records']}
        self.assertEqual(types, {'revisit', 'response', 'metadata'})
        capture_types = {c['record_type'] for c in result['captures']}
        self.assertEqual(capture_types, {'revisit', 'response'})

    def test_base64_ingest_through_service_route(self):
        self.vault.cases.create('case-a', '路由案件', 'collector')
        request = {'operation': 'warc.ingest_base64',
                   'arguments': {'ingest_id': 'ing-b64', 'source_name': 'first.warc',
                                 'content': encode(self.bundles['first.warc']), 'owner': 'collector'}}
        result = self.vault.execute(request)
        self.assertEqual(result['state'], 'parsed')
        self.assertEqual(len(result['records']), 1)

    def test_commands_include_warc_operations(self):
        names = {item['operation'] for item in self.vault.commands()}
        self.assertIn('warc.ingest', names)
        self.assertIn('warc.resolve', names)
        self.assertIn('warc.mount', names)
        self.assertIn('warc.describe_capture', names)

    def test_non_actor_cannot_ingest(self):
        self.vault.cases.create('case-a', '权限案件', 'collector')
        actors.register(self.db, 'auditor', 'auditor')
        self.error('actor_permission', self.vault.webarchives.ingest,
                   'ing-x', 'first.warc', self.bundles['first.warc'], 'auditor')

    def test_tampered_source_digest_rejected(self):
        self.vault.cases.create('case-a', '摘要案件', 'collector')
        self.error('warc_source_digest', self.vault.webarchives.ingest,
                   'ing-x', 'first.warc', self.bundles['first.warc'], 'collector',
                   source_digest='0' * 64)


if __name__ == '__main__':
    unittest.main()
