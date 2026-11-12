import argparse
import sys
from pathlib import Path
from sealvault.codec import loads, canonical, VaultError, fail
from sealvault.service import Vault
from sealvault.transfer import archive
from sealvault.inspect import checks, semantic


def read_json(filename):
    source = Path(filename)
    if not source.is_file() or source.stat().st_size > 33554432:
        fail('input_file', 'Input must be a local regular JSON file under 32 MiB')
    return loads(source.read_text(encoding='utf-8'))


def read_warc(filename):
    source = Path(filename)
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 1073741824:
        fail('warc_source', 'WARC input must be a bounded local regular file')
    return source.read_bytes()


def replay(vault, fixture):
    if not isinstance(fixture, dict) or set(fixture) != {'synthetic', 'steps'} or fixture['synthetic'] is not True:
        fail('fixture', 'Replay requires explicitly synthetic local fixture')
    if not isinstance(fixture['steps'], list) or not 1 <= len(fixture['steps']) <= 1000:
        fail('fixture_steps', 'Fixture requires bounded operation sequence')
    results = []
    for index, step in enumerate(fixture['steps']):
        if not isinstance(step, dict) or 'request' not in step or set(step) - {'request', 'expect'}:
            fail('fixture_step', 'Fixture step requires request and optional assertions')
        result = vault.execute(step['request'])
        for path, expected in step.get('expect', {}).items():
            actual = result
            try:
                for component in path.split('.'):
                    actual = actual[int(component)] if isinstance(actual, list) else actual[component]
            except (ValueError, KeyError, IndexError, TypeError):
                fail('fixture_path', 'Fixture assertion path does not exist', step=index, path=path)
            if actual != expected:
                fail('fixture_assertion', 'Business result differs from expected', step=index, path=path, expected=expected, actual=actual)
        results.append({'step': index, 'operation': step['request']['operation'], 'assertions': len(step.get('expect', {}))})
    integrity = checks.run(vault.db)
    semantics = semantic.verify_database(vault.db)
    if not integrity['ok'] or not semantics['valid']:
        fail('fixture_integrity', 'Fixture ended with invalid vault state', integrity=integrity, semantics=semantics)
    return {'ok': True, 'steps': results, 'integrity': integrity, 'semantic_cases': len(semantics['cases'])}


def parser():
    result = argparse.ArgumentParser(prog='sealvault', description='Offline content-addressed evidence custody vault')
    result.add_argument('--database', default=':memory:')
    commands = result.add_subparsers(dest='command', required=True)
    commands.add_parser('commands')
    commands.add_parser('check')
    execute = commands.add_parser('execute')
    execute.add_argument('request')
    demo = commands.add_parser('replay')
    demo.add_argument('fixture')
    export = commands.add_parser('archive-export')
    export.add_argument('manifest_id')
    export.add_argument('destination')
    verify = commands.add_parser('archive-verify')
    verify.add_argument('source')
    imports = commands.add_parser('archive-import-objects')
    imports.add_argument('source')
    imports.add_argument('actor')
    warc_ingest = commands.add_parser('warc-ingest')
    warc_ingest.add_argument('ingest_id')
    warc_ingest.add_argument('source')
    warc_ingest.add_argument('actor')
    warc_ingest.add_argument('--max-total', type=int, default=67108864)
    warc_ingest.add_argument('--max-record', type=int, default=16777216)
    warc_resolve = commands.add_parser('warc-resolve')
    warc_resolve.add_argument('ingest_id')
    warc_resolve.add_argument('actor')
    warc_mount = commands.add_parser('warc-mount')
    warc_mount.add_argument('ingest_id')
    warc_mount.add_argument('case_id')
    warc_mount.add_argument('expected_revision', type=int)
    warc_mount.add_argument('actor')
    warc_get = commands.add_parser('warc-get')
    warc_get.add_argument('ingest_id')
    warc_describe = commands.add_parser('warc-describe')
    warc_describe.add_argument('record_id')
    return result


def main(argv=None):
    options = parser().parse_args(argv)
    try:
        with Vault(options.database) as vault:
            if options.command == 'commands':
                result = vault.commands()
            elif options.command == 'execute':
                result = vault.execute(read_json(options.request))
            elif options.command == 'check':
                result = {'integrity': checks.run(vault.db), 'semantics': semantic.verify_database(vault.db)}
                print(canonical(result))
                return 0 if result['integrity']['ok'] and result['semantics']['valid'] else 1
            elif options.command == 'archive-export':
                result = archive.export_file(vault.db, options.manifest_id, options.destination)
            elif options.command == 'archive-verify':
                result = archive.verify(archive.read_file(options.source))
            elif options.command == 'archive-import-objects':
                result = archive.import_objects(vault.db, archive.read_file(options.source), options.actor)
            elif options.command == 'warc-ingest':
                result = vault.webarchives.ingest(options.ingest_id, Path(options.source).name,
                                                  read_warc(options.source), options.actor,
                                                  max_total=options.max_total, max_record=options.max_record)
            elif options.command == 'warc-resolve':
                result = vault.webarchives.resolve(options.ingest_id, options.actor)
            elif options.command == 'warc-mount':
                result = vault.webarchives.mount(options.ingest_id, options.case_id, options.expected_revision, options.actor)
            elif options.command == 'warc-get':
                result = vault.webarchives.get(options.ingest_id)
            elif options.command == 'warc-describe':
                result = vault.webarchives.describe_capture(options.record_id)
            else:
                result = replay(vault, read_json(options.fixture))
            print(canonical(result))
            return 0
    except VaultError as exc:
        print(canonical({'ok': False, 'error': exc.payload()}), file=sys.stderr)
        return 2
    except (OSError, UnicodeError) as exc:
        print(canonical({'ok': False, 'error': {'code': 'io', 'message': str(exc)}}), file=sys.stderr)
        return 2
