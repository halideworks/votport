#!/usr/bin/env python3
"""Exercise delivery import/export against an isolated S3 service.

Requires a running S3 endpoint, curl with --aws-sigv4, and a test server binary.
All local state lives beneath --root. Never point this at production storage.
"""
import argparse
import hashlib
import http.client
import http.cookiejar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', required=True, type=Path)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--web-root', required=True, type=Path)
    parser.add_argument('--s3', default='http://127.0.0.1:19000')
    credentials = parser.add_mutually_exclusive_group()
    credentials.add_argument('--ambient-credentials', action='store_true')
    credentials.add_argument('--saved-credentials', action='store_true')
    args = parser.parse_args()
    args.root.mkdir(parents=True, exist_ok=True)
    access = os.environ['S3_TEST_ACCESS_KEY']
    secret = os.environ['S3_TEST_SECRET_KEY']
    bucket = 'workflow-' + str(time.time_ns())

    def s3(method, key='', content=None):
        command = ['curl', '--silent', '--show-error', '--fail-with-body', '--aws-sigv4',
                   'aws:amz:us-east-1:s3', '--user', access + ':' + secret, '-X', method,
                   args.s3 + '/' + bucket + '/' + urllib.parse.quote(key, safe='/')]
        if content is not None:
            command += ['--data-binary', '@-']
        result = subprocess.run(command, input=content, capture_output=True, timeout=60)
        if result.returncode:
            raise RuntimeError(result.stderr.decode() + result.stdout.decode(errors='replace'))
        return result.stdout

    s3('PUT')
    files = {'zero.bin': b'', 'literal%23#[1].bin': b'literal keys survive\n',
             'nested/large.bin': os.urandom(9 * 1024 * 1024)}
    for name, content in files.items():
        s3('PUT', 'source/' + name, content)
    s3('PUT', 'source-sibling/skip.bin', b'not part of this prefix')
    trace, faults = [], {'mutate': None, 'reject_completion': False}
    backend = urllib.parse.urlsplit(args.s3)

    class Proxy(BaseHTTPRequestHandler):
        def do_request(self):
            path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
            trace.append((self.command, path, self.headers.get('If-Match')))
            body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            if self.command == 'GET' and path == faults['mutate']:
                faults['mutate'] = None
                s3('PUT', path.removeprefix('/' + bucket + '/'), b'mutated after listing')
            if self.command == 'PUT' and path.endswith('/complete.json') and faults['reject_completion']:
                self.send_response(403); self.send_header('Content-Length', '0'); self.end_headers(); return
            connection = http.client.HTTPConnection(backend.hostname, backend.port, timeout=60)
            try:
                connection.request(self.command, self.path, body=body, headers=dict(self.headers))
                response = connection.getresponse()
                payload = response.read()
                self.send_response(response.status)
                for key, value in response.getheaders():
                    if key.lower() not in ('transfer-encoding', 'connection', 'content-length'):
                        self.send_header(key, value)
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                if self.command != 'HEAD': self.wfile.write(payload)
            finally:
                connection.close()
        do_GET = do_PUT = do_POST = do_DELETE = do_HEAD = do_request
        def log_message(self, *_args): pass

    proxy = ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    base = f'http://127.0.0.1:{free_port()}'
    env = os.environ | {'VOTPORT_BIND': urllib.parse.urlsplit(base).netloc,
        'VOTPORT_PUBLIC_URL': base, 'VOTPORT_DATA_DIR': str(args.root / 'data'),
        'VOTPORT_RECEIVE_DIR': str(args.root / 'received'), 'VOTPORT_OUTBOUND_DIR': str(args.root / 'library'),
        'VOTPORT_WEB_ROOT': str(args.web_root), 'VOTPORT_ADMIN_PASSWORD': 'workflow-fixture-only',
        'VOTPORT_SERVE_BIND': '', 'VOTPORT_PUSH_BIND': '',
        'VOTPORT_STORAGE_FIXTURE_ACCESS_KEY_ID': access, 'VOTPORT_STORAGE_FIXTURE_SECRET_ACCESS_KEY': secret}
    if args.saved_credentials:
        env['VOTPORT_STORAGE_FIXTURE_ACCESS_KEY_ID'] = 'wrong-key'
        env['VOTPORT_STORAGE_FIXTURE_SECRET_ACCESS_KEY'] = 'wrong-secret'
    if args.ambient_credentials:
        del env['VOTPORT_STORAGE_FIXTURE_ACCESS_KEY_ID'], env['VOTPORT_STORAGE_FIXTURE_SECRET_ACCESS_KEY']
        env.update(AWS_ACCESS_KEY_ID=access, AWS_SECRET_ACCESS_KEY=secret,
                   AWS_ENDPOINT='http://127.0.0.1:1', AWS_ENDPOINT_URL_S3='http://127.0.0.1:1',
                   AWS_BUCKET='wrong-bucket')
        env.pop('AWS_SESSION_TOKEN', None)
    else:
        env.update(AWS_ACCESS_KEY_ID='wrong-key', AWS_SECRET_ACCESS_KEY='wrong-secret',
                   AWS_SESSION_TOKEN='wrong-token')
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def api(path, body=None, method=None):
        request = urllib.request.Request(base + '/api/' + path, method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={'Content-Type': 'application/json', 'X-Votport': '1'})
        with opener.open(request, timeout=60) as response:
            return json.load(response)

    def wait_job(job_id, expected):
        for _ in range(1200):
            value = api('workflows/jobs/' + job_id)
            if value['job']['state'] in ('ready', 'failed', 'awaiting_approval'):
                assert value['job']['state'] == expected, value
                return value
            time.sleep(.05)
        raise AssertionError('job did not settle')

    log = (args.root / 'server.log').open('wb')
    server = subprocess.Popen([str(args.server)], env=env, stdout=log, stderr=log)
    try:
        for _ in range(200):
            try:
                urllib.request.urlopen(base + '/healthz', timeout=1).close(); break
            except OSError:
                assert server.poll() is None, (args.root / 'server.log').read_text()
                time.sleep(.05)
        api('admin/login', {'password': 'workflow-fixture-only'})
        config = api('workflows/storage', {'storage': {'id': 'fixture', 'revision': 0, 'label': 'Fixture',
            'endpoint': f'http://127.0.0.1:{proxy.server_port}', 'bucket': bucket, 'region': 'us-east-1',
            'prefix': '', 'path_style': True, 'kms_key_id': None, 'tenants': [''], 'enabled': True},
            'credentials': {'mode': 'access_key', 'access_key_id': access, 'secret_access_key': secret} if args.saved_credentials else None}, 'PUT')
        assert api('workflows/storage/fixture/test', {'revision': config['revision']})['ok']
        api('workflows/projects', {'id': 'storage', 'label': 'Storage checks', 'directory': 'storage',
            'required_metadata': ['client'], 'export_storage': 'fixture'}, 'PUT')
        request = {'operation_id': 's3-import-export', 'project_id': 'storage', 'label': 'S3 delivery',
            'metadata': {'client': 'Fixture'}, 'expires_days': 1, 'import': {'storage_id': 'fixture', 'prefix': 'source'}}
        faults['mutate'] = '/' + bucket + '/source/literal%23#[1].bin'
        first = api('workflows/jobs', request)
        job_id = first['job']['id']
        failed = wait_job(job_id, 'failed')
        assert 'conditional read failed' in failed['job']['error'], failed
        assert not failed.get('url')
        assert api('workflows/jobs', request)['job']['id'] == job_id
        assert any(entry[2] for entry in trace if entry[0] == 'GET'), trace
        s3('PUT', 'source/literal%23#[1].bin', files['literal%23#[1].bin'])
        faults['reject_completion'] = True
        api('workflows/jobs/' + job_id, {'action': 'retry'})
        failed = wait_job(job_id, 'failed')
        assert 'completion manifest' in failed['job']['error'], failed
        assert not failed.get('url')
        faults['reject_completion'] = False
        api('workflows/jobs/' + job_id, {'action': 'retry'})
        ready = wait_job(job_id, 'ready')
        manifest = ready['job']['manifest']
        prefix = f'deliveries/{job_id}/{manifest}'
        completion = json.loads(s3('GET', prefix + '/complete.json'))
        assert completion['signature'] and completion['document']['manifest'] == manifest
        exported = completion['document']['files']
        assert {entry['name'] for entry in exported} == set(files)
        for entry in exported:
            actual = s3('GET', entry['key'])
            assert hashlib.sha256(actual).digest() == hashlib.sha256(files[entry['name']]).digest()
        # Retry after a lost completion response must accept the identical commit object.
        import sqlite3
        with sqlite3.connect(args.root / 'data/votport.db') as database:
            database.execute("UPDATE delivery_jobs SET state='exporting',owner='',document=json_remove(json_set(document,'$.state','exporting'),'$.checks.export_manifest_key') WHERE id=?", (job_id,))
        assert wait_job(job_id, 'ready')['job']['manifest'] == manifest
        assert json.loads(s3('GET', prefix + '/complete.json')) == completion
        puts = [path for method, path, _ in trace if method == 'PUT']
        assert puts[-1].endswith('/complete.json')
        assert config['revision'] == 1
        print(json.dumps({'import_export': 'passed', 'conditional_mutation': 'rejected',
            'credentials': 'saved' if args.saved_credentials else 'ambient' if args.ambient_credentials else 'configured',
            'completion_failure': 'withheld URL', 'retry': 'same operation and manifest',
            'literal_keys': 'preserved', 'files': len(files), 'bytes': sum(map(len, files.values()))}), flush=True)
    finally:
        server.terminate()
        try: server.wait(timeout=15)
        except subprocess.TimeoutExpired: server.kill(); server.wait()
        log.close(); proxy.shutdown(); proxy.server_close()


if __name__ == '__main__':
    main()
