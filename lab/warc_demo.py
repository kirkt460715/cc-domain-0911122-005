"""本地 WARC 归档演示（无网络、无页面执行）。

依次展示：先重访后原文、跨包引用、重复记录（同内容复用 / 换内容冲突）、
截断尾部，并用文件数据库演示重启后继续处理，最后说明对象、捕获与案件附件关系。
"""
import shutil
import tempfile
from pathlib import Path

from lab import archives
from sealvault.custody import actors
from sealvault.service import Vault
from sealvault.inspect import checks, semantic


def line(title):
    print('\n=== ' + title + ' ===')


def show_captures(ingest):
    for capture in ingest['captures']:
        reason = capture['reason']['code'] if capture['reason'] else '-'
        payload = (capture['payload_digest'] or '')[:12]
        print(f"  #{capture['ordinal']} {capture['record_type']:8s} {capture['record_id'][-13:]} "
              f"HTTP {capture['http_status'] or '-':>3} 状态={capture['state']:14s} 正文={payload} 原因={reason}")


def main():
    bundles = {**archives.samples(), **archives.conflict_sample(), **archives.cross_package_samples()}
    workdir = Path(tempfile.mkdtemp(prefix='sealvault-warc-'))
    database = workdir / 'vault.sqlite'
    print('工作目录（含重启用数据库与合成 WARC）:', workdir)
    source_dir = workdir / 'sources'
    archives.build(source_dir)

    with Vault(database) as vault:
        actors.register(vault.db, 'collector', 'collector')
        actors.register(vault.db, 'custodian', 'custodian')
        vault.cases.create('case-web', '网页归档封存演示', 'collector', 'restricted')

        line('1. 先重访后原文（forward.warc：revisit 出现在 response 之前）')
        vault.webarchives.ingest('ing-forward', 'forward.warc', bundles['forward.warc'], 'collector')
        show_captures(vault.webarchives.get('ing-forward'))
        vault.webarchives.resolve('ing-forward', 'collector')
        print('  解析后：')
        show_captures(vault.webarchives.get('ing-forward'))

        line('2. 跨包引用（earlier.warc 收录原文，later-ref.warc 的 revisit 指向它）')
        vault.webarchives.ingest('ing-earlier', 'earlier.warc', bundles['earlier.warc'], 'collector')
        vault.webarchives.resolve('ing-earlier', 'collector')
        vault.webarchives.ingest('ing-later', 'later-ref.warc', bundles['later-ref.warc'], 'collector')
        show_captures(vault.webarchives.resolve('ing-later', 'collector'))

        line('3a. 重复 record-id 且内容相同（repeated.warc：复用对象，保留两次访问证据）')
        vault.webarchives.ingest('ing-repeat', 'repeated.warc', bundles['repeated.warc'], 'collector')
        show_captures(vault.webarchives.resolve('ing-repeat', 'collector'))

        line('3b. 重复 record-id 但内容不同（conflict.warc：必须冲突，不按 URL 合并）')
        vault.webarchives.ingest('ing-conflict', 'conflict.warc', bundles['conflict.warc'], 'collector')
        show_captures(vault.webarchives.get('ing-conflict'))

        line('4. 截断尾部（truncated.warc：前面记录暂存，整包判失败，绝不挂载）')
        failed = vault.webarchives.ingest('ing-trunc', 'truncated.warc', bundles['truncated.warc'], 'collector')
        print(f"  入库状态={failed['state']} 待处理原因={failed['reason']['code']} 已暂存记录={len(failed['records'])}")

        line('5. 拼接 gzip（joined.warc.gz：两个成员，按记录切分）')
        gz = vault.webarchives.ingest('ing-gz', 'joined.warc.gz', bundles['joined.warc.gz'], 'collector')
        print(f"  gzip 成员数={gz['gzip_members']} 解压字节={gz['decompressed_bytes']} 记录数={len(gz['records'])}")
        vault.webarchives.resolve('ing-gz', 'collector')

        line('6. 引用成环（cycle.warc：保留 cycle 待处理原因，阻止挂载）')
        vault.webarchives.ingest('ing-cycle', 'cycle.warc', bundles['cycle.warc'], 'collector')
        review = vault.webarchives.resolve('ing-cycle', 'collector')
        show_captures(review)

        line('7. 确认前展示捕获清单与未解决引用')
        forward = vault.webarchives.get('ing-forward')
        print('  待挂载捕获：', [(c['record_id'][-13:], c['target_uri'], c['warc_date'], c['http_status']) for c in forward['captures']])
        print('  未解决引用：', [(c['record_id'][-13:], c['reason']['code']) for c in forward['unresolved']])

        line('8. 整包挂载到案件（全部核验通过、案件版本有效）')
        mounted = vault.webarchives.mount('ing-forward', 'case-web', 1, 'collector')
        case = vault.cases.get('case-web')
        print(f"  挂载状态={mounted['state']} 案件版本={case['revision']} 附件条目={len(case['entries'])}")
        for entry in case['entries']:
            print('   ', entry['path'], '->', entry['metadata']['warc_record_id'][-13:],
                  entry['metadata']['http_status'], entry['metadata']['payload_digest'][:12])

    line('9. 重启后继续处理（重新打开同一文件数据库）')
    with Vault(database) as reopened:
        forward = reopened.webarchives.get('ing-forward')
        print('  重启后 ingest 状态：', forward['state'])
        record_id = forward['captures'][0]['record_id']
        relation = reopened.webarchives.describe_capture(record_id, 'ing-forward')
        print('  对象—捕获—案件附件关系：')
        print('   捕获 record-id ：', relation['record_id'])
        print('   网址/时间/状态 ：', relation['target_uri'], relation['warc_date'], relation['http_status'])
        print('   块对象（WARC块）：', relation['block_object']['digest'][:16], relation['block_object']['size'], '字节')
        print('   正文对象（实体）：', relation['payload_object']['digest'][:16], relation['payload_object']['size'], '字节')
        print('   案件附件       ：', [(a['case_id'], a['entry_path']) for a in relation['case_attachments']])
        print('   同正文的全部访问：', len(relation['same_payload_captures']), '条（访问证据不丢）')
        integrity = checks.run(reopened.db)
        semantics = semantic.verify_database(reopened.db)
        print('  完整性检查 ok =', integrity['ok'], '；语义检查 valid =', semantics['valid'])

    line('10. 内容去重统计')
    with Vault(database) as vault:
        total_objects = vault.db.scalar('SELECT COUNT(*) FROM objects')
        total_captures = vault.db.scalar('SELECT COUNT(*) FROM warc_captures')
        unique_payloads = vault.db.scalar('SELECT COUNT(DISTINCT payload_digest) FROM warc_captures WHERE payload_digest IS NOT NULL')
        print(f'  内容对象={total_objects}（含块对象与正文对象，按字节去重） 捕获记录={total_captures} 不同正文={unique_payloads}')
    print('\n演示完成。合成数据仅作字节保存，未执行任何页面或网络访问。')
    shutil.rmtree(workdir, ignore_errors=True)


if __name__ == '__main__':
    main()
