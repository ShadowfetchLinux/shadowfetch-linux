import http.server
import json
import os
from pathlib import Path
import sys
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
    def test_no_native_model_fails_closed_before_shared_inference(self):
        with patch.object(compute,'local_models',return_value=[]), patch.object(compute,'shared_models',return_value=[{'name':'remote'}]) as shared:
            with self.assertRaisesRegex(compute.ComputeError,'Offline missions never'):
                compute.target('remote',False)
            shared.assert_not_called()
            target = compute.target('remote',True)
            self.assertFalse(target['local_only_verified'])
            self.assertEqual(target['endpoint'],compute.ROUTER)
    def test_native_route_wins_over_mesh_when_both_allowed(self):
        native = compute.process_proof(self.record, self.proc.parent)
        with patch.object(compute,'local_models',return_value=[native]), patch.object(compute,'shared_models',side_effect=AssertionError('do not route mesh')):
            self.assertEqual(compute.target('model',True),native)
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
