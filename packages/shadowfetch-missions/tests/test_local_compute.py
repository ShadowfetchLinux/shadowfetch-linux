import http.server
import hashlib
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'data/usr/lib/shadowfetch/missions'))
import sf_local_compute as compute

class NativeComputeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.proc = Path(self.temp.name) / '123'
        (self.proc / 'fd').mkdir(parents=True)
        (self.proc / 'net').mkdir()
        (self.proc / 'exe').symlink_to('/opt/buzz/runtime/llama-server')
        (self.proc / 'stat').write_text('123 (native server) ' + ' '.join(['S'] + ['0'] * 18 + ['999']))
        (self.proc / 'fd/5').symlink_to('socket:[456]')
        (self.proc / 'net/tcp').write_text('header\n0: 0100007F:A02A 00000000:0000 0A 0 0 0 0 0 456\n')
        self.record = {'name':'model', 'backend':'llama', 'status':'ready', 'pid':123, 'port':41002}
    def tearDown(self):
        self.temp.cleanup()
    def test_native_process_requires_owned_local_socket_and_backend(self):
        proof = compute.process_proof(self.record, self.proc.parent)
        self.assertTrue(proof['local_only_verified'])
        self.assertEqual(proof['endpoint'],'http://127.0.0.1:41002')
        (self.proc / 'fd/5').unlink()
        with self.assertRaisesRegex(compute.ComputeError,'does not own'):
            compute.process_proof(self.record, self.proc.parent)
    def test_router_port_and_unknown_backends_never_qualify(self):
        for field, value in [('port',9337),('port',3131),('backend','openai-endpoint'),('status','starting'),('pid',0)]:
            with self.subTest(field=field,value=value), self.assertRaises(compute.ComputeError):
                compute.process_proof(dict(self.record, **{field:value}), self.proc.parent)
    def test_mismatched_executable_is_refused(self):
        (self.proc / 'exe').unlink()
        (self.proc / 'exe').symlink_to('/usr/bin/python3')
        with self.assertRaisesRegex(compute.ComputeError,'executable'):
            compute.process_proof(self.record, self.proc.parent)
    def test_embedded_buzz_still_requires_owned_native_socket(self):
        (self.proc / 'exe').unlink()
        (self.proc / 'exe').symlink_to('/usr/bin/buzz-desktop')
        record = dict(self.record, backend='skippy')
        with patch.object(compute, 'buzz_binary_proof', return_value={'package':'buzz','version':'0.5.17'}) as identity:
            proof = compute.process_proof(record, self.proc.parent)
            self.assertEqual(proof['package_identity']['package'], 'buzz')
            identity.assert_called_once_with(Path('/usr/bin/buzz-desktop'))
            (self.proc / 'fd/5').unlink()
            with self.assertRaisesRegex(compute.ComputeError, 'does not own'):
                compute.process_proof(record, self.proc.parent)
        (self.proc / 'exe').unlink()
        (self.proc / 'exe').symlink_to('/home/person/buzz-desktop')
        with self.assertRaisesRegex(compute.ComputeError, 'executable'):
            compute.process_proof(record, self.proc.parent)
    def test_embedded_binary_requires_pinned_package_and_content_integrity(self):
        binary = Path(self.temp.name) / 'buzz-desktop'
        binary.write_bytes(b'official package fixture')
        manifest = Path(self.temp.name) / 'buzz.md5sums'
        manifest.write_text(hashlib.md5(binary.read_bytes()).hexdigest() + '  usr/bin/buzz-desktop\n')
        query = subprocess.CompletedProcess([], 0, stdout='0.5.17 ii ', stderr='')
        with patch.object(compute, 'BUZZ_EXECUTABLE', binary), patch.object(compute, 'BUZZ_MANIFEST', manifest), patch.object(compute, 'protected_file', return_value=True), patch.object(compute.subprocess, 'run', return_value=query):
            self.assertEqual(compute.buzz_binary_proof(binary)['sha256'], hashlib.sha256(binary.read_bytes()).hexdigest())
            query.stdout = '0.5.18 ii '
            with self.assertRaisesRegex(compute.ComputeError, 'verified Buzz'):
                compute.buzz_binary_proof(binary)
            query.stdout = '0.5.17 ii '
            binary.write_bytes(b'modified executable')
            with self.assertRaisesRegex(compute.ComputeError, 'does not match'):
                compute.buzz_binary_proof(binary)
        with patch.object(compute, 'BUZZ_EXECUTABLE', binary), patch.object(compute, 'protected_file', return_value=False):
            with self.assertRaisesRegex(compute.ComputeError, 'protected'):
                compute.buzz_binary_proof(binary)
    def test_no_native_model_fails_closed_before_shared_inference(self):
        with patch.object(compute,'local_models',return_value=[]), patch.object(compute,'shared_models',return_value=[{'name':'remote'}]) as shared:
            with self.assertRaisesRegex(compute.ComputeError,'Offline missions never'):
                compute.target('remote',False)
            shared.assert_not_called()
            target = compute.target('remote',True)
            self.assertFalse(target['local_only_verified'])
            self.assertEqual(target['endpoint'],compute.ROUTER)
    def test_native_discovery_refuses_distributed_or_unknown_stage_state(self):
        for stages in ({'stages':[{'stage_id':'remote'}],'topologies':[]}, {'stages':[], 'topologies':[{'run_id':'split'}]}, {}):
            def reply(url):
                return {'processes':[self.record]} if url.endswith('/processes') else stages
            with self.subTest(stages=stages), patch.object(compute, 'request', side_effect=reply), patch.object(compute, 'process_proof', side_effect=AssertionError('must refuse before native selection')):
                self.assertEqual(compute.local_models(), [])
    def test_native_route_wins_over_mesh_when_both_allowed(self):
        native = compute.process_proof(self.record, self.proc.parent)
        with patch.object(compute,'local_models',return_value=[native]), patch.object(compute,'shared_models',side_effect=AssertionError('do not route mesh')):
            self.assertEqual(compute.target('model',True),native)
    def test_native_requests_disable_all_peer_consultation_hooks(self):
        native = compute.process_proof(self.record, self.proc.parent)
        payload = {'model':'model','mesh_hooks':True,'messages':[{'role':'user','content':'private text'}]}
        with patch.object(compute, 'target', return_value=native), patch.object(compute, 'request', return_value={'choices':[{'message':{'content':'done'}}]}) as call, patch.object(compute, 'process_proof', return_value=native), patch.object(compute, 'no_distributed_stages', return_value=True):
            result = compute.complete(payload)
        self.assertIs(call.call_args.args[1]['mesh_hooks'], False)
        self.assertIs(payload['mesh_hooks'], True)
        self.assertIs(result['shadowfetch_compute']['mesh_hooks_enabled'], False)
    def test_skippy_requests_produce_direct_output_with_bounded_token_budget(self):
        native = dict(compute.process_proof(self.record, self.proc.parent), backend='skippy')
        payload = {'model':'model','reasoning_effort':'high','chat_template_kwargs':{'enable_thinking':True},'messages':[{'role':'user','content':'READY'}]}
        with patch.object(compute, 'target', return_value=native), patch.object(compute, 'request', return_value={'choices':[{'message':{'content':'READY'}}]}) as call, patch.object(compute, 'process_proof', return_value=native), patch.object(compute, 'no_distributed_stages', return_value=True):
            result = compute.complete(payload)
        self.assertEqual(call.call_args.args[1]['reasoning_effort'], 'none')
        self.assertIs(call.call_args.args[1]['chat_template_kwargs']['enable_thinking'], False)
        self.assertIs(payload['chat_template_kwargs']['enable_thinking'], True)
        self.assertIn('bounded', result['shadowfetch_compute']['reasoning_mode'])
    def test_only_literal_loopback_urls_accepted(self):
        for url in ['https://example.com/v1/models','http://localhost:3131/api/status','http://127.0.0.1:3131@evil.test/api/status','file:///etc/passwd']:
            with self.subTest(url=url), self.assertRaises(compute.ComputeError):
                compute.request(url)
    def test_redirect_is_refused_and_external_proxy_ignored(self):
        hits=[]
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                if self.path=='/redirect':
                    self.send_response(302)
                    self.send_header('Location','http://127.0.0.1:' + str(self.server.server_port) + '/leaked')
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'{"data":[]}')
            def log_message(self,*args): pass
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            with patch.dict(os.environ,{'http_proxy':'http://127.0.0.1:1','HTTP_PROXY':'http://127.0.0.1:1','no_proxy':'','NO_PROXY':''}):
                base='http://127.0.0.1:' + str(server.server_port)
                self.assertEqual(compute.request(base+'/models'),{'data':[]})
                with self.assertRaises(compute.ComputeError):
                    compute.request(base+'/redirect')
            self.assertNotIn('/leaked',hits)
        finally:
            server.shutdown()
            thread.join()
            server.server_close()

if __name__=='__main__': unittest.main(verbosity=2)
