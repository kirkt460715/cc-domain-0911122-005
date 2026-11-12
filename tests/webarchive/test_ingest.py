import tempfile
from pathlib import Path
from tests.support import Case
from sealvault.codec import sha256
from sealvault.custody import actors
from sealvault.service import Vault
from lab.archives import samples, conflict_sample, cross_package_samples, record, identity, http_response
from sealvault.inspect import checks, semantic


class WarcIngestWorkflow(Case):
    def setUp(self):
        super().setUp()
        self.vault.cases.create('case-a', '网页归档案件', 'collector')
        self.bundles = samples()
        self.conflict = conflict_sample()
        self.cross = cross_package_samples()

    def ingest(self, ingest_id, name, content):
        return self.vault.webarchives.ingest(ingest_id, name, content, 'collector')

    def test_forward_revisit_resolves_to_later_response_and_mounts(self):
        self.ingest('ing-fwd', 'forward.warc', self.bundles['forward.warc'])
        pending = self.vault.webarchives.get('ing-fwd')
        self.assertEqual(pending['state'], 'parsed')
        revisit = next(c for c in pending['captures'] if c['record_type'] == 'revisit')
        self.assertEqual(revisit['state'], 'pending')
        resolved = self.vault.webarchives.resolve('ing-fwd', 'collector')
        self.assertEqual(resolved['state'], 'ready')
        self.assertEqual({c['state'] for c in resolved['captures']}, {'resolved'})
        # revisit 的正文对象与 response 相同（内容去重）。
        payloads = {c['payload_digest'] for c in resolved['captures']}
        self.assertEqual(len(payloads), 1)
        mounted = self.vault.webarchives.mount('ing-fwd', 'case-a', 1, 'collector')
        self.assertEqual(mounted['state'], 'mounted')
        case = self.vault.cases.get('case-a')
        self.assertEqual(len(case['entries']), 2)
        # 访问证据：同一正文对应两条捕获记录，没有按 URL 合并。
        self.assertEqual(len(mounted['captures']), 2)
        self.assertTrue(semantic.verify_database(self.db)['valid'])

    def test_cross_package_reference_uses_existing_capture(self):
        self.ingest('ing-earlier', 'earlier.warc', self.cross['earlier.warc'])
        self.vault.webarchives.resolve('ing-earlier', 'collector')
        self.ingest('ing-later', 'later-ref.warc', self.cross['later-ref.warc'])
        result = self.vault.webarchives.resolve('ing-later', 'collector')
        self.assertEqual(result['state'], 'ready')
        revisit = result['captures'][0]
        self.assertEqual(revisit['state'], 'resolved')
        target = self.db.one("SELECT payload_digest FROM warc_captures WHERE ingest_id='ing-earlier'")
        self.assertEqual(revisit['payload_digest'], target['payload_digest'])

    def test_missing_reference_stays_unresolved_with_reason(self):
        # later.warc 的 revisit 指向不存在的记录 1。
        self.ingest('ing-orphan', 'later.warc', self.bundles['later.warc'])
        result = self.vault.webarchives.resolve('ing-orphan', 'collector')
        self.assertEqual(result['state'], 'review')
        self.assertEqual(result['unresolved'][0]['state'], 'unresolved')
        self.assertEqual(result['unresolved'][0]['reason']['code'], 'warc_unresolved_reference')
        self.error('warc_state', self.vault.webarchives.mount, 'ing-orphan', 'case-a', 1, 'collector')

    def test_reference_cycle_is_reported_and_blocks_mount(self):
        self.ingest('ing-cycle', 'cycle.warc', self.bundles['cycle.warc'])
        result = self.vault.webarchives.resolve('ing-cycle', 'collector')
        self.assertEqual(result['state'], 'review')
        self.assertEqual({c['state'] for c in result['unresolved']}, {'cycle'})
        self.error('warc_state', self.vault.webarchives.mount, 'ing-cycle', 'case-a', 1, 'collector')

    def test_digest_mismatch_between_revisit_and_target(self):
        payload = '共享正文。'.encode()
        other = '不同正文。'.encode()
        response = self._response(30, payload)
        bad_revisit = self._revisit(31, 30, other)
        self.ingest('ing-mix', 'mix.warc', response + bad_revisit)
        result = self.vault.webarchives.resolve('ing-mix', 'collector')
        states = {c['record_id'][-3:]: c['state'] for c in result['unresolved']}
        self.assertIn('digest_mismatch', states.values())

    def test_duplicate_record_id_same_content_is_reused_but_evidence_kept(self):
        self.ingest('ing-dup', 'repeated.warc', self.bundles['repeated.warc'])
        result = self.vault.webarchives.resolve('ing-dup', 'collector')
        self.assertEqual(result['state'], 'ready')
        self.assertEqual(len(result['captures']), 2)
        self.assertEqual({c['payload_digest'] for c in result['captures']},
                         {sha256('合成维护正文。'.encode())})
        before = self.db.scalar('SELECT COUNT(*) FROM objects')
        mounted = self.vault.webarchives.mount('ing-dup', 'case-a', 1, 'collector')
        # 两条访问都进案件，正文对象不重复存储。
        self.assertEqual(len(mounted['attachments']), 2)
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM objects'), before + 2)  # 仅新增两份证据 JSON

    def test_duplicate_record_id_different_content_conflicts(self):
        self.ingest('ing-conflict', 'conflict.warc', self.conflict['conflict.warc'])
        result = self.vault.webarchives.get('ing-conflict')
        states = [(c['state'], c['reason']['code'] if c['reason'] else None) for c in result['captures']]
        self.assertIn(('conflict', 'warc_record_id_conflict'), states)
        # 冲突记录不允许挂载。
        self.vault.webarchives.resolve('ing-conflict', 'collector')
        self.error('warc_open_references', self.vault.webarchives.mount, 'ing-conflict', 'case-a', 1, 'collector')

    def test_truncated_archive_keeps_prior_records_but_never_mounts(self):
        result = self.ingest('ing-trunc', 'truncated.warc', self.bundles['truncated.warc'])
        self.assertEqual(result['state'], 'failed')
        self.assertEqual(result['reason']['code'], 'warc_truncated')
        self.assertEqual(len(result['records']), 1)  # 前面已暂存的 response 保留
        # 已暂存记录的块对象确实入库。
        block = result['records'][0]['detail']
        self.assertIsNotNone(block)
        self.error('warc_state', self.vault.webarchives.resolve, 'ing-trunc', 'collector')
        self.error('warc_state', self.vault.webarchives.mount, 'ing-trunc', 'case-a', 1, 'collector')

    def test_joined_gzip_framing_matches_plain(self):
        result = self.ingest('ing-gz', 'joined.warc.gz', self.bundles['joined.warc.gz'])
        self.assertEqual(result['gzip_members'], 2)
        self.assertEqual(len(result['records']), 3)
        resolved = self.vault.webarchives.resolve('ing-gz', 'collector')
        self.assertEqual(resolved['state'], 'ready')

    def test_reingest_same_id_same_bytes_is_idempotent(self):
        self.ingest('ing-idem', 'first.warc', self.bundles['first.warc'])
        again = self.ingest('ing-idem', 'first.warc', self.bundles['first.warc'])
        self.assertEqual(again['source_digest'], sha256(self.bundles['first.warc']))
        self.assertEqual(len(again['records']), 1)

    def test_reingest_same_id_different_bytes_conflicts(self):
        self.ingest('ing-idem', 'first.warc', self.bundles['first.warc'])
        self.error('warc_ingest_conflict', self.ingest, 'ing-idem', 'other.warc',
                   self.bundles['forward.warc'])

    def test_mount_requires_current_case_revision_and_is_idempotent(self):
        self.ingest('ing-fwd', 'forward.warc', self.bundles['forward.warc'])
        self.vault.webarchives.resolve('ing-fwd', 'collector')
        self.error('case_revision', self.vault.webarchives.mount, 'ing-fwd', 'case-a', 99, 'collector')
        mounted = self.vault.webarchives.mount('ing-fwd', 'case-a', 1, 'collector')
        self.assertEqual(mounted['state'], 'mounted')
        attachments_after_first = len(mounted['attachments'])
        # 重复挂载是幂等的，不会产生第二份案件附件。
        again = self.vault.webarchives.mount('ing-fwd', 'case-a', self.vault.cases.get('case-a')['revision'], 'collector')
        self.assertEqual(len(again['attachments']), attachments_after_first)
        self.assertEqual(again['state'], 'mounted')

    def test_describe_links_object_capture_and_attachment(self):
        self.ingest('ing-fwd', 'forward.warc', self.bundles['forward.warc'])
        self.vault.webarchives.resolve('ing-fwd', 'collector')
        self.vault.webarchives.mount('ing-fwd', 'case-a', 1, 'collector')
        record_id = self.vault.webarchives.get('ing-fwd')['captures'][0]['record_id']
        description = self.vault.webarchives.describe_capture(record_id, 'ing-fwd')
        self.assertIsNotNone(description['payload_object'])
        self.assertEqual(description['block_object']['state'], 'available')
        self.assertEqual(len(description['case_attachments']), 1)
        # 同正文的另一条捕获也能被检索到（访问证据不丢）。
        self.assertEqual(len(description['same_payload_captures']), 2)

    def test_persistence_across_restart(self):
        with tempfile.TemporaryDirectory() as temporary:
            filename = Path(temporary) / 'vault.sqlite'
            with Vault(filename, clock=self.clock) as first:
                actors.register(first.db, 'collector', 'collector')
                first.cases.create('case-a', '网页归档案件', 'collector')
                first.webarchives.ingest('ing-fwd', 'forward.warc', self.bundles['forward.warc'], 'collector')
                first.webarchives.resolve('ing-fwd', 'collector')
            with Vault(filename, clock=self.clock) as second:
                restarted = second.webarchives.get('ing-fwd')
                self.assertEqual(restarted['state'], 'ready')
                mounted = second.webarchives.mount('ing-fwd', 'case-a', 1, 'collector')
                self.assertEqual(mounted['state'], 'mounted')
                self.assertTrue(checks.run(second.db)['ok'])

    def test_role_enforcement(self):
        actors.register(self.db, 'auditor', 'auditor')
        self.error('actor_permission', self.vault.webarchives.ingest,
                   'ing-x', 'first.warc', self.bundles['first.warc'], 'auditor')

    def _response(self, number, payload):
        return record(number, 'response', http_response('200 OK', payload),
                      {'WARC-Payload-Digest': 'sha256:' + sha256(payload)})

    def _revisit(self, number, target, payload):
        return record(number, 'revisit', http_response('200 OK', b''),
                      {'WARC-Refers-To': identity(target),
                       'WARC-Payload-Digest': 'sha256:' + sha256(payload),
                       'WARC-Profile': 'http://netpreserve.org/warc/1.1/revisit/identical-payload-digest'})
