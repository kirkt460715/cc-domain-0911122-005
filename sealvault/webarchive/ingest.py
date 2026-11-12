"""WARC 归档接收入库。

把每次捕获（response/revisit）的记录身份、网址、时间、HTTP 状态与正文对象
建立关联；revisit 引用可前向、跨包解析；解析结束仍找不到依赖、引用成环或
摘要不一致时保留待处理原因。正文按内容去重为对象，访问证据（捕获记录）不合并。
"""
from sealvault.codec import key, text, integer, canonical, loads, sha256, timestamp, fail, VaultError, checksum, decode
from sealvault.objects import Objects
from sealvault.custody import actors, chain
from sealvault.custody.cases import Cases
from sealvault.webarchive import warc

DDL = '''
CREATE TABLE IF NOT EXISTS warc_ingests(ingest_id TEXT PRIMARY KEY,source_name TEXT NOT NULL,source_digest TEXT NOT NULL,bytes INTEGER NOT NULL,compressed INTEGER NOT NULL,gzip_members INTEGER NOT NULL,decompressed_bytes INTEGER NOT NULL,owner TEXT NOT NULL,state TEXT NOT NULL,reason TEXT,cursor INTEGER NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS warc_records(ingest_id TEXT NOT NULL,ordinal INTEGER NOT NULL,record_id TEXT NOT NULL,record_type TEXT NOT NULL,warc_date TEXT NOT NULL,target_uri TEXT,http_status INTEGER,block_digest TEXT NOT NULL,payload_digest TEXT,refers_to TEXT,profile TEXT,record_state TEXT NOT NULL,detail TEXT NOT NULL,PRIMARY KEY(ingest_id,ordinal));
CREATE INDEX IF NOT EXISTS warc_record_identity ON warc_records(ingest_id,record_id);
CREATE INDEX IF NOT EXISTS warc_record_digest ON warc_records(payload_digest);
CREATE TABLE IF NOT EXISTS warc_captures(capture_key INTEGER PRIMARY KEY AUTOINCREMENT,ingest_id TEXT NOT NULL,ordinal INTEGER NOT NULL,record_id TEXT NOT NULL,target_uri TEXT NOT NULL,warc_date TEXT NOT NULL,http_status INTEGER NOT NULL,record_type TEXT NOT NULL,block_digest TEXT NOT NULL,declared_payload_digest TEXT,payload_digest TEXT,actual_payload_digest TEXT,refers_to TEXT,state TEXT NOT NULL,reason TEXT,resolved_chain TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS warc_capture_identity ON warc_captures(ingest_id,record_id);
CREATE INDEX IF NOT EXISTS warc_capture_global ON warc_captures(record_id);
CREATE INDEX IF NOT EXISTS warc_capture_payload ON warc_captures(payload_digest);
CREATE TABLE IF NOT EXISTS warc_case_attachments(ingest_id TEXT NOT NULL,ordinal INTEGER NOT NULL,case_id TEXT NOT NULL,capture_id TEXT NOT NULL,entry_path TEXT NOT NULL,case_revision INTEGER NOT NULL,attached_at TEXT NOT NULL,PRIMARY KEY(ingest_id,capture_id,ordinal));
CREATE INDEX IF NOT EXISTS warc_attachment_case ON warc_case_attachments(case_id);
'''

CAPTURE_TYPES = {'response', 'revisit'}
TERMINAL_STATES = {'mounted', 'failed', 'abandoned'}


class WebArchives:
    def __init__(self, database):
        self.db = database
        self.objects = Objects(database)
        self.cases = Cases(database)
        if database.depth:
            fail('warc_transaction', 'Initialize web archive desk outside transactions')
        database.connection.executescript(DDL)

    # ------------------------------------------------------------------ 接收
    def ingest(self, ingest_id, source_name, content, owner, source_digest=None,
               max_total=warc.DEFAULT_MAX_TOTAL, max_record=warc.DEFAULT_MAX_RECORD):
        key(ingest_id)
        text(source_name, 500)
        actors.require(self.db, owner, {'collector', 'custodian'})
        integer(max_total, 'max_total', 1, 10 ** 12)
        integer(max_record, 'max_record', 1, max_total)
        if not isinstance(content, (bytes, bytearray)) or not content:
            fail('warc_input', 'WARC source must be nonempty raw bytes')
        content = bytes(content)
        actual_digest = sha256(content)
        if source_digest is not None and checksum(source_digest) != actual_digest:
            fail('warc_source_digest', 'Source bytes differ from declared digest')
        with self.db.transaction():
            prior = self.db.one('SELECT * FROM warc_ingests WHERE ingest_id=?', (ingest_id,))
            if prior:
                if prior['source_digest'] != actual_digest or prior['owner'] != owner:
                    fail('warc_ingest_conflict', 'Ingest identifier binds another source or owner')
                return self.get(ingest_id)
            parsed = self._parse(content, max_total, max_record)
            reason = parsed.get('fatal')
            state = 'parsed' if reason is None else 'failed'
            at = self.db.clock()
            self.db.execute("INSERT INTO warc_ingests VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (ingest_id, source_name, actual_digest, len(content),
                             1 if parsed['compressed'] else 0, parsed['gzip_members'],
                             parsed['decompressed_bytes'], owner, state,
                             None if reason is None else canonical(reason), len(parsed['records']), at, at))
            self._persist_records(ingest_id, parsed, owner)
            chain.append(self.db, ingest_id, 'warc_ingested', owner,
                         {'source_name': source_name, 'source_digest': actual_digest,
                          'records': len(parsed['records']), 'fatal': reason})
            return self.get(ingest_id)

    def ingest_base64(self, ingest_id, source_name, content, owner, source_digest=None,
                      max_total=warc.DEFAULT_MAX_TOTAL, max_record=warc.DEFAULT_MAX_RECORD):
        integer(max_total, 'max_total', 1, 10 ** 12)
        data = decode(content, max_total)
        return self.ingest(ingest_id, source_name, data, owner, source_digest, max_total, max_record)

    def _parse(self, content, max_total, max_record):
        # 截断/分帧失败时仍返回此前已解析记录：损坏尾部不能抹掉前面的暂存内容。
        return warc.parse_archive(content, max_total, max_record, partial=True)

    def _persist_records(self, ingest_id, parsed, owner):
        seen_ids = {}
        for record in parsed['records']:
            detail = {'parse_errors': record['errors'], 'headers': record.get('headers', {})}
            record_state = 'accepted' if not record['errors'] else 'rejected'
            kind = record.get('type', 'unknown')
            self.db.execute('INSERT INTO warc_records VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                            (ingest_id, record['ordinal'], record.get('record_id', f'<missing:{record["ordinal"]}>'),
                             kind, record.get('date', ''), record.get('target_uri'),
                             record.get('http_status'), record.get('actual_block_digest', sha256(record.get('block', b''))),
                             record.get('actual_payload_digest'), record.get('refers_to'),
                             record.get('profile'), record_state, canonical(detail)))
            if kind not in CAPTURE_TYPES or record['errors']:
                continue
            # 重复 record-id：同内容可复用，换内容必须冲突，绝不按 URL 合并。
            duplicate = seen_ids.get(record['record_id'])
            if duplicate is not None:
                if duplicate['actual_block_digest'] != record['actual_block_digest'] or \
                        duplicate['actual_payload_digest'] != record['actual_payload_digest']:
                    self._capture_row(ingest_id, record, 'conflict',
                                      {'code': 'warc_record_id_conflict', 'message': 'Record identifier reappears with different content'},
                                      None)
                    continue
                self._capture_row(ingest_id, record, 'duplicate',
                                  {'code': 'warc_duplicate_record', 'message': 'Record identifier repeats identical content and is reused'},
                                  duplicate['record_id'])
                continue
            seen_ids[record['record_id']] = record
            self._store_capture(ingest_id, record, owner)

    def _store_capture(self, ingest_id, record, owner):
        reason = None
        payload_digest = None
        try:
            self.objects.put(record['block'], record['actual_block_digest'])
            if record['type'] == 'response':
                stored = self.objects.put(record['payload'], record['actual_payload_digest'])
                payload_digest = stored['digest']
                state = 'resolved'
            else:
                # revisit 自身没有正文对象；正文沿引用链在 resolve 阶段确定。
                state = 'pending'
        except VaultError as exc:
            state, reason = 'rejected', exc.payload()
        self._capture_row(ingest_id, record, state, reason, None, payload_digest)

    def _capture_row(self, ingest_id, record, state, reason, duplicate_of, payload_digest=None):
        chain_text = canonical([] if duplicate_of is None else [duplicate_of])
        self.db.execute('''INSERT INTO warc_captures(ingest_id,ordinal,record_id,target_uri,warc_date,http_status,
            record_type,block_digest,declared_payload_digest,payload_digest,actual_payload_digest,refers_to,state,reason,resolved_chain)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                        (ingest_id, record['ordinal'], record['record_id'], record['target_uri'],
                         timestamp(record['date']), record['http_status'], record['type'],
                         record['actual_block_digest'], record['declared_payload_digest'],
                         payload_digest, record.get('actual_payload_digest'), record['refers_to'], state,
                         None if reason is None else canonical(reason), chain_text))

    # ------------------------------------------------------------------ 解析
    def resolve(self, ingest_id, owner):
        actors.require(self.db, owner)
        with self.db.transaction():
            ingest = self._require_ingest(ingest_id)
            if ingest['owner'] != owner:
                fail('warc_owner', 'Ingest owner differs')
            if ingest['state'] in TERMINAL_STATES:
                fail('warc_state', 'Ingest is terminal and cannot resolve', state=ingest['state'])
            if ingest['state'] != 'parsed':
                fail('warc_state', 'Only parsed ingests can resolve references')
            rows = self.db.all('SELECT * FROM warc_captures WHERE ingest_id=? ORDER BY ordinal', (ingest_id,))
            # 同 record-id 同内容的重复访问：复用原记录解析结果，但访问证据各自保留。
            for row in rows:
                if row['state'] != 'duplicate':
                    continue
                if row['record_type'] == 'response':
                    self._promote_duplicate(ingest_id, row)
            for row in rows:
                if row['record_type'] != 'revisit' or row['state'] == 'resolved':
                    continue
                if row['state'] == 'duplicate':
                    self._resolve_duplicate(ingest_id, row)
                else:
                    self._resolve_revisit(ingest_id, row)
            # 第二轮：前向引用在首轮可能尚未就绪（含重复记录的引用）。
            for row in rows:
                if row['record_type'] != 'revisit' or row['state'] == 'resolved':
                    continue
                if row['state'] == 'duplicate':
                    self._resolve_duplicate(ingest_id, row)
                elif row['state'] == 'pending':
                    self._resolve_revisit(ingest_id, row)
            pending = self.db.all("SELECT record_id,state,reason FROM warc_captures WHERE ingest_id=? AND state IN ('pending','cycle','unresolved','digest_mismatch')", (ingest_id,))
            state = 'ready' if not pending else 'review'
            self.db.execute('UPDATE warc_ingests SET state=?,updated_at=? WHERE ingest_id=?', (state, self.db.clock(), ingest_id))
            chain.append(self.db, ingest_id, 'warc_resolved', owner,
                         {'captures': len(rows), 'open': len(pending)})
            return self.get(ingest_id)

    def _promote_duplicate(self, ingest_id, row):
        chain_values = loads(row['resolved_chain'])
        original_id = chain_values[0] if chain_values else None
        original = self.db.one('SELECT * FROM warc_captures WHERE record_id=? AND ingest_id=?', (original_id, ingest_id))
        if original is None or original['state'] != 'resolved':
            return
        self.db.execute("UPDATE warc_captures SET state='resolved',payload_digest=?,resolved_chain=? WHERE capture_key=?",
                        (original['payload_digest'],
                         canonical([row['record_id'], *loads(original['resolved_chain'])]), row['capture_key']))

    def _resolve_duplicate(self, ingest_id, row):
        chain_values = loads(row['resolved_chain'])
        original_id = chain_values[0] if chain_values else None
        original = self.db.one('SELECT * FROM warc_captures WHERE record_id=? AND ingest_id=?', (original_id, ingest_id))
        if original is None or original['state'] != 'resolved':
            return  # 原记录尚未解析或不可用，重复记录保持待处理
        self.db.execute("UPDATE warc_captures SET state='resolved',reason=NULL,payload_digest=?,resolved_chain=? WHERE capture_key=?",
                        (original['payload_digest'], canonical([row['record_id'], *loads(original['resolved_chain'])]), row['capture_key']))

    def _resolve_revisit(self, ingest_id, row):
        path = []
        current = row
        while True:
            if current['record_id'] in path:
                self._mark(current, 'cycle', {'code': 'warc_reference_cycle', 'message': 'Revisit reference chain contains a cycle', 'chain': path + [current['record_id']]})
                return
            path.append(current['record_id'])
            target = self._find_target(current['refers_to'], ingest_id)
            if target is None:
                self._mark(current, 'unresolved', {'code': 'warc_unresolved_reference', 'message': 'Referenced capture is absent from this ingest and the case vault', 'refers_to': current['refers_to']})
                return
            if target['state'] == 'conflict' or target['state'] == 'rejected':
                self._mark(current, 'unresolved', {'code': 'warc_reference_invalid', 'message': 'Referenced record itself is not usable', 'refers_to': current['record_id']})
                return
            if target['record_type'] == 'revisit' and target['state'] not in {'resolved', 'duplicate'}:
                current = target
                if len(path) > 1000:
                    self._mark(current, 'cycle', {'code': 'warc_reference_depth', 'message': 'Revisit chain exceeds supported depth'})
                    return
                continue
            payload_digest = target['payload_digest']
            if payload_digest is None:
                self._mark(current, 'unresolved', {'code': 'warc_unresolved_reference', 'message': 'Target capture has no resolved payload'})
                return
            if current['declared_payload_digest'] != payload_digest:
                self._mark(current, 'digest_mismatch', {'code': 'warc_payload_digest', 'message': 'Revisit declared payload digest does not match the referenced capture body',
                                                        'declared': current['declared_payload_digest'], 'actual': payload_digest})
                return
            self.db.execute("UPDATE warc_captures SET state='resolved',reason=NULL,payload_digest=?,resolved_chain=? WHERE capture_key=?",
                            (payload_digest, canonical(path), current['capture_key']))
            return

    def _find_target(self, record_id, ingest_id):
        row = self.db.one('SELECT * FROM warc_captures WHERE record_id=? AND ingest_id=?', (record_id, ingest_id))
        if row is not None:
            return row
        # 引用可以指向同案件/同库已经收录的捕获（跨包引用）。
        return self.db.one("SELECT * FROM warc_captures WHERE record_id=? AND state='resolved' ORDER BY ingest_id,ordinal LIMIT 1", (record_id,))

    def _mark(self, row, state, reason):
        self.db.execute('UPDATE warc_captures SET state=?,reason=? WHERE capture_key=?',
                        (state, canonical(reason), row['capture_key']))

    # ------------------------------------------------------------------ 挂载
    def mount(self, ingest_id, case_id, expected_revision, owner):
        actors.require(self.db, owner, {'collector', 'custodian'})
        with self.db.transaction():
            ingest = self._require_ingest(ingest_id)
            if ingest['owner'] != owner:
                fail('warc_owner', 'Ingest owner differs')
            if ingest['state'] not in {'ready', 'mounted'}:
                fail('warc_state', 'Only fully resolved ingests may be mounted', state=ingest['state'])
            if ingest['state'] == 'mounted':
                return self.get(ingest_id)
            captures = self.db.all("SELECT * FROM warc_captures WHERE ingest_id=? AND state='resolved' ORDER BY ordinal", (ingest_id,))
            open_items = self.db.all("SELECT record_id,state,reason FROM warc_captures WHERE ingest_id=? AND state NOT IN ('resolved','duplicate')", (ingest_id,))
            if open_items:
                fail('warc_open_references', 'Capture list still has unresolved evidence', open=open_items)
            if not captures:
                fail('warc_empty_mount', 'Ingest has no resolved capture to mount')
            case = self.cases.editable(case_id, expected_revision, owner)
            if case['state'] != 'draft':
                fail('case_state', 'Only draft cases may receive captures')
            revision = expected_revision
            attached = []
            for capture in captures:
                # 块对象与正文对象都必须可按内容地址读取，确认核验在挂载时仍成立。
                self.objects.read(capture['block_digest'])
                self.objects.read(capture['payload_digest'])
                entry_path = f'warc/{ingest_id}/{capture["ordinal"]:06d}-{capture["record_id"].strip("<>").rsplit(":", 1)[-1]}.json'
                entry = {'path': entry_path, 'digest': self._evidence_object(capture)['digest'],
                         'size': len(self._evidence_bytes(capture)), 'media_type': 'application/json',
                         'metadata': {'warc_record_id': capture['record_id'], 'warc_type': capture['record_type'],
                                      'warc_date': capture['warc_date'], 'target_uri': capture['target_uri'],
                                      'http_status': capture['http_status'], 'payload_digest': capture['payload_digest'],
                                      'block_digest': capture['block_digest']}}
                case = self.cases.attach(case_id, revision, owner, entry)
                revision = case['revision']
                self.db.execute('INSERT INTO warc_case_attachments VALUES(?,?,?,?,?,?,?)',
                                (ingest_id, capture['ordinal'], case_id, capture['record_id'], entry_path, revision, self.db.clock()))
                attached.append({'record_id': capture['record_id'], 'entry_path': entry_path, 'payload_digest': capture['payload_digest']})
            self.db.execute("UPDATE warc_ingests SET state='mounted',updated_at=? WHERE ingest_id=?", (self.db.clock(), ingest_id))
            chain.append(self.db, case_id, 'warc_mounted', owner,
                         {'ingest_id': ingest_id, 'case_revision': revision, 'captures': len(attached)})
            return self.get(ingest_id)

    def _evidence_bytes(self, capture):
        record = canonical({'record_id': capture['record_id'], 'target_uri': capture['target_uri'],
                            'warc_date': capture['warc_date'], 'http_status': capture['http_status'],
                            'record_type': capture['record_type'], 'block_digest': capture['block_digest'],
                            'payload_digest': capture['payload_digest'], 'refers_to': capture['refers_to'],
                            'resolved_chain': loads(capture['resolved_chain'])}).encode('utf-8')
        return record

    def _evidence_object(self, capture):
        return self.objects.put(self._evidence_bytes(capture))

    def abandon(self, ingest_id, owner, reason):
        actors.require(self.db, owner)
        reason = text(reason)
        with self.db.transaction():
            ingest = self._require_ingest(ingest_id)
            if ingest['owner'] != owner:
                fail('warc_owner', 'Ingest owner differs')
            if ingest['state'] == 'mounted':
                fail('warc_state', 'Mounted ingests are part of a case and cannot be abandoned')
            self.db.execute("UPDATE warc_ingests SET state='abandoned',reason=?,updated_at=? WHERE ingest_id=?",
                            (canonical({'reason': reason}), self.db.clock(), ingest_id))
            chain.append(self.db, ingest_id, 'warc_abandoned', owner, {'reason': reason})
            return self.get(ingest_id)

    # ------------------------------------------------------------------ 查询
    def _require_ingest(self, ingest_id):
        row = self.db.one('SELECT * FROM warc_ingests WHERE ingest_id=?', (ingest_id,))
        if row is None:
            fail('warc_ingest_missing', 'WARC ingest does not exist')
        return row

    def get(self, ingest_id):
        row = dict(self._require_ingest(ingest_id))
        if row['reason']:
            row['reason'] = loads(row['reason'])
        row['records'] = self.db.all('SELECT ordinal,record_id,record_type,warc_date,target_uri,http_status,block_digest,payload_digest,refers_to,record_state,detail FROM warc_records WHERE ingest_id=? ORDER BY ordinal', (ingest_id,))
        for item in row['records']:
            item['detail'] = loads(item['detail'])
        row['captures'] = self.db.all('SELECT ordinal,record_id,target_uri,warc_date,http_status,record_type,block_digest,declared_payload_digest,payload_digest,refers_to,state,reason,resolved_chain FROM warc_captures WHERE ingest_id=? ORDER BY ordinal', (ingest_id,))
        for item in row['captures']:
            item['reason'] = loads(item['reason']) if item['reason'] else None
            item['resolved_chain'] = loads(item['resolved_chain'])
        row['unresolved'] = [item for item in row['captures'] if item['state'] not in {'resolved', 'duplicate'}]
        row['attachments'] = self.db.all('SELECT ordinal,case_id,capture_id,entry_path,case_revision FROM warc_case_attachments WHERE ingest_id=? ORDER BY case_id,ordinal', (ingest_id,))
        row['unique_payloads'] = self.db.all('SELECT DISTINCT payload_digest FROM warc_captures WHERE ingest_id=? AND payload_digest IS NOT NULL ORDER BY payload_digest', (ingest_id,))
        return row

    def list(self, state=None):
        if state is not None and state not in {'running', 'parsed', 'review', 'ready', 'mounted', 'failed', 'abandoned'}:
            fail('warc_state', 'Unknown ingest state')
        sql = 'SELECT ingest_id FROM warc_ingests'
        args = ()
        if state:
            sql += ' WHERE state=?'
            args = (state,)
        return [self.get(row['ingest_id']) for row in self.db.all(sql + ' ORDER BY ingest_id', args)]

    def describe_capture(self, record_id, ingest_id=None):
        """说明对象、捕获和案件附件之间的关系。"""
        if ingest_id:
            capture = self.db.one('SELECT * FROM warc_captures WHERE record_id=? AND ingest_id=?', (record_id, ingest_id))
        else:
            capture = self.db.one('SELECT * FROM warc_captures WHERE record_id=? ORDER BY ingest_id,ordinal LIMIT 1', (record_id,))
        if capture is None:
            fail('warc_capture_missing', 'Capture record does not exist')
        result = dict(capture)
        result['reason'] = loads(result['reason']) if result['reason'] else None
        result['resolved_chain'] = loads(result['resolved_chain'])
        result['payload_object'] = self.objects.info(capture['payload_digest']) if capture['payload_digest'] else None
        result['block_object'] = self.objects.info(capture['block_digest'])
        result['case_attachments'] = self.db.all('SELECT ingest_id,ordinal,case_id,entry_path,case_revision FROM warc_case_attachments WHERE capture_id=? ORDER BY case_id,ordinal', (record_id,))
        result['same_payload_captures'] = self.db.all('SELECT ingest_id,record_id,target_uri,warc_date,http_status FROM warc_captures WHERE payload_digest=? ORDER BY ingest_id,ordinal', (capture['payload_digest'],))
        return result
