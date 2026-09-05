import importlib.machinery
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

PATH = Path(__file__).resolve().parents[1] / 'data/usr/bin/shadowfetch-model-check'
SPEC = importlib.util.spec_from_loader('model_check', importlib.machinery.SourceFileLoader('model_check', str(PATH)))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

class LocalModelChecks(unittest.TestCase):
    def module(self, models=None, response=None):
        native = Mock()
        native.local_models.return_value = models if models is not None else [{'name':'small','local_only_verified':True}]
        native.complete.return_value = response if response is not None else {'model':'small','choices':[{'message':{'content':'READY'}}], 'shadowfetch_compute':{'local_only_verified':True}}
        return native
    def test_unavailable_model_service_is_not_reported_ready(self):
        native=self.module(models=[])
        with patch.object(MODULE,'compute_module',return_value=native):
            result=MODULE.inspect()
        self.assertFalse(result['ready'])
        self.assertFalse(result['local_only'])
        self.assertFalse(result['upload_performed'])
    def test_verify_refuses_unknown_model_before_invocation(self):
        native=self.module()
        with patch.object(MODULE,'compute_module',return_value=native), self.assertRaises(ValueError):
            MODULE.verify('not-installed')
        native.complete.assert_not_called()
    def test_empty_response_does_not_create_success_receipt(self):
        native=self.module(response={'choices':[]})
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ,{'XDG_STATE_HOME':temporary}), patch.object(MODULE,'compute_module',return_value=native):
            with self.assertRaises(ValueError): MODULE.verify('small')
            self.assertFalse((Path(temporary)/'shadowfetch/model-check/last-verification.json').exists())
    def test_unverified_compute_cannot_claim_offline_success(self):
        native=self.module(response={'choices':[{'message':{'content':'READY'}}], 'shadowfetch_compute':{'local_only_verified':False}})
        with patch.object(MODULE,'compute_module',return_value=native), self.assertRaisesRegex(ValueError,'locality'):
            MODULE.verify('small')
    def test_verified_response_has_private_receipt_and_hardware(self):
        native=self.module()
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ,{'XDG_STATE_HOME':temporary}), patch.object(MODULE,'compute_module',return_value=native):
            result=MODULE.verify('small')
            self.assertEqual(result['status'],'pass')
            self.assertEqual(result['response'],'READY')
            self.assertEqual(Path(result['receipt']).stat().st_mode & 0o777,0o600)
            self.assertIn('ram_available_bytes',result['hardware_before'])
            self.assertFalse(native.complete.call_args.kwargs['allow_network'])
