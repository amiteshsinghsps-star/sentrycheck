#!/usr/bin/env python3
"""Offline collector trust-boundary regressions; does not execute a guest."""
from copy import deepcopy
import json
from pathlib import Path
import struct
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import capture_kata as collector

DIGEST = "sha256:" + "a" * 64
IMAGE = "registry.invalid/workload@" + DIGEST
ID = "b" * 64
TYPE = "/trusted/containerd-shim-kata-v2"


def native():
    profile = dict(name="test", description="", command=["/test"], env=[], timeout_seconds=5, repetitions=1, expected_exit_code=0, compare_stdout=False, compare_stderr=False, timing_ratio=2.0, timing_min_native_ms=100, coverage="smoke")
    return {"schema_version": "1.0", "image_digest": DIGEST, "target_runtime": {"architecture": "amd64"}, "dynamic": {"profile": profile, "profile_sha256": DIGEST, "native": [{"runtime": "runc", "trace_kind": "strace-guest", "infrastructure_error": None, "timed_out": False, "exit_code": 0, "trace_summary": {"truncated": False, "discarded_guest_records": 0, "unfinished_count": 0}}]}}


class CollectorTests(unittest.TestCase):
    def test_native_binding_and_incomplete_rejection(self):
        self.assertEqual(collector.validate_native(native(), IMAGE)[2], "amd64")
        for image in ("repo:latest", "-option@" + DIGEST, IMAGE + "a", "repo@@" + DIGEST):
            with self.subTest(image=image), self.assertRaises(collector.CaptureError):
                collector.validate_native(native(), image)
        for key, value in (("timed_out", True), ("exit_code", 42), ("infrastructure_error", "lost")):
            report = native(); report["dynamic"]["native"][0][key] = value
            with self.subTest(key=key), self.assertRaises(collector.CaptureError):
                collector.validate_native(report, IMAGE)
        for field in ("truncated", "discarded_guest_records", "unfinished_count"):
            report = native(); report["dynamic"]["native"][0]["trace_summary"][field] = 1
            with self.subTest(field=field), self.assertRaises(collector.CaptureError):
                collector.validate_native(report, IMAGE)

    def test_sandbox_requires_exact_id_uid_state_type(self):
        good = {"status": {"id": ID, "state": "SANDBOX_READY", "metadata": {"uid": "token"}}, "info": {"runtimeType": TYPE}}
        collector.sandbox_identity(good, ID, TYPE, "token")
        for path, value in ((('status', 'id'), 'c' * 64), (('status', 'state'), False), (('status', 'state'), 'SANDBOX_NOTREADY'), (('info', 'runtimeType'), 'io.containerd.runc.v2')):
            data = deepcopy(good); data[path[0]][path[1]] = value
            with self.subTest(path=path, value=value), self.assertRaises(collector.CaptureError):
                collector.sandbox_identity(data, ID, TYPE, "token")
        with self.assertRaises(collector.CaptureError):
            collector.sandbox_identity(good, ID, TYPE, "other-token")

    def test_image_requires_repo_digest_and_config_identity(self):
        good = {"status": {"id": DIGEST, "repoDigests": [IMAGE]}, "info": {"imageSpec": {"architecture": "amd64", "os": "linux", "config": {"Cmd": ["/test"], "WorkingDir": "/work"}}}}
        self.assertEqual(collector.image_configuration(good, IMAGE, "amd64")[1], DIGEST)
        for mutate in (lambda x: x['status'].pop('id'), lambda x: x['status'].update(repoDigests=[]), lambda x: x['info']['imageSpec'].update(architecture='arm64'), lambda x: x['info']['imageSpec']['config'].update(WorkingDir='relative'), lambda x: x['info']['imageSpec']['config'].update(Cmd=['a\0b'])):
            value = deepcopy(good); mutate(value)
            with self.assertRaises(collector.CaptureError): collector.image_configuration(value, IMAGE, 'amd64')

    def test_container_requires_requested_image_and_private_label(self):
        good = {"status": {"id": ID, "labels": {"sentrycheck.io/collector-id": "nonce"}, "image": {"image": IMAGE}, "imageRef": DIGEST}}
        collector.container_identity(good, ID, IMAGE, DIGEST, "nonce")
        for key, value in (("id", 'c' * 64), ("labels", {}), ("imageRef", None), ("image", {"image": "repo:latest"})):
            changed = deepcopy(good); changed['status'][key] = value
            with self.subTest(key=key), self.assertRaises(collector.CaptureError): collector.container_identity(changed, ID, IMAGE, DIGEST, "nonce")

    def test_enum_boolean_and_noncanonical_ids_rejected(self):
        self.assertFalse(collector.enum_state(False, "SANDBOX_READY", 0))
        self.assertFalse(collector.enum_state(True, "CONTAINER_RUNNING", 1))
        for identifier in (b"", b"--all", b"abc", (ID + "\n" + ID).encode()):
            with self.assertRaises(collector.CaptureError): collector.owned_id(identifier)
        self.assertEqual(collector.owned_id((ID + "\n").encode()), ID)

    def test_artifact_containment_limits_and_duplicate_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); file = root / 'output'; file.write_bytes(b'hello')
            self.assertEqual(collector.safe_source(root, 'output'), file)
            self.assertEqual(collector.read_regular(file, 5), b'hello')
            with self.assertRaises(collector.CaptureError): collector.read_regular(file, 4)
            with self.assertRaises(collector.CaptureError): collector.safe_source(root, '../outside')
            file.write_text('{"x":1,"x":2}')
            with self.assertRaises(collector.CaptureError): collector.load_json(file)

    def test_static_tools_reject_interpreter_and_wrong_architecture(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'tool'; raw = bytearray(120)
            raw[:6] = b'\x7fELF\x02\x01'; struct.pack_into('<H', raw, 18, 62); struct.pack_into('<Q', raw, 32, 64); struct.pack_into('<HH', raw, 54, 56, 1); struct.pack_into('<I', raw, 64, 1); path.write_bytes(raw)
            collector.static_elf(path, 'amd64')
            with self.assertRaises(collector.CaptureError): collector.static_elf(path, 'arm64')
            struct.pack_into('<I', raw, 64, 3); path.write_bytes(raw)
            with self.assertRaises(collector.CaptureError): collector.static_elf(path, 'amd64')

    def test_environment_overrides_match_native_order(self):
        actual = collector.env_values({'Env': ['A=image','B=image']}, {'env': ['A=profile']})
        actual = {x['key']:x['value'] for x in actual}
        self.assertEqual(actual['A'], 'profile'); self.assertEqual(actual['B'], 'image'); self.assertIn('PATH', actual)

    def test_cleanup_removes_only_returned_ids(self):
        class Fake:
            def __init__(self): self.calls = []
            def call(self, *args, **kwargs): self.calls.append(args); return b''
        fake = Fake(); collector.cleanup(fake, ID, 'c' * 64)
        self.assertEqual(fake.calls, [('stop','--timeout','5',ID), ('rm','--force',ID), ('stopp','c'*64), ('rmp','--force','c'*64)])

    def test_cleanup_failure_requires_exact_absence(self):
        class Fake:
            def __init__(self, absent): self.absent = absent
            def call(self, *args, **kwargs): raise collector.CaptureError('cleanup failed')
            def json(self, *args, **kwargs):
                self_args = args
                self_id = self_args[self_args.index('--id') + 1]
                return {'containers' if args[0] == 'ps' else 'items': [] if self.absent else [{'id': self_id}]}
        collector.cleanup(Fake(True), ID, 'c' * 64)
        with self.assertRaises(collector.CaptureError): collector.cleanup(Fake(False), ID, 'c' * 64)

    def lifecycle(self, directory, *, fail_cleanup=False, bad_state=False):
        root = Path(directory)
        args = SimpleNamespace(image=IMAGE, handler='kata', startup_timeout=5, kata_version='4.2.0')
        profile = native()['dynamic']['profile']
        class Fake:
            started = False
            def call(self, *args, **kwargs):
                if args[0] == 'runp':
                    self.pod = json.loads(Path(args[-1]).read_text())
                    return ('c' * 64).encode()
                if args[0] == 'create': return ID.encode()
                if args[0] == 'start':
                    self.started = True
                    for kind, data in [('stdout',b'ok\n'),('stderr',b''),('trace',b'write(1, "ok\\n", 3) = 3\n')]:
                        (root/'kata-0'/'guest-output'/kind).write_bytes(data)
                if args[0] == 'rmp' and fail_cleanup: raise collector.CaptureError('still alive')
                return b''
            def json(self, *args, **kwargs):
                if args[0] == 'inspectp': return {'status':{'id':'c'*64,'state':'SANDBOX_READY','metadata':{'uid':self.pod['metadata']['uid']}},'info':{'runtimeType':TYPE}}
                if args[0] == 'pods': return {'items':[{'id':'c'*64}]}
                return {'status':{'id':ID,'image':{'image':IMAGE},'imageRef':DIGEST,'labels':{'sentrycheck.io/collector-id':self.pod['metadata']['uid']},'state':False if bad_state and self.started else ('CONTAINER_EXITED' if self.started else 'CONTAINER_CREATED'),'exitCode':0}}
        return args, Fake(), root, profile

    def test_lifecycle_captures_only_after_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            args, cri, root, profile = self.lifecycle(directory)
            with patch.object(collector, 'command', return_value=b'') as commands, patch.object(collector.os, 'statvfs', return_value=SimpleNamespace(f_bavail=1), create=True):
                record = collector.run_once(args,cri,root,0,profile,{'Cmd':['/test']},DIGEST,TYPE)
            self.assertEqual(record['runtime'],'kata'); self.assertEqual(record['exit_code'],0)
            self.assertEqual((root/record['stdout']).read_bytes(),b'ok\n')
            self.assertEqual(record['trace_sha256'],collector.digest_bytes((root/record['trace']).read_bytes()))
            self.assertTrue(any(call.args[0][0]=='umount' for call in commands.call_args_list))

    def test_lifecycle_failed_cleanup_never_reads_guest_output(self):
        with tempfile.TemporaryDirectory() as directory:
            args, cri, root, profile = self.lifecycle(directory,fail_cleanup=True)
            with patch.object(collector, 'command', return_value=b'') as commands, patch.object(collector.os, 'statvfs', return_value=SimpleNamespace(f_bavail=1), create=True), patch.object(collector, 'read_regular') as read:
                with self.assertRaisesRegex(collector.CaptureError,'Cleanup failed'):
                    collector.run_once(args,cri,root,0,profile,{'Cmd':['/test']},DIGEST,TYPE)
                read.assert_not_called()
            self.assertFalse(any(call.args[0][0]=='umount' for call in commands.call_args_list))
            self.assertTrue((root/'kata-0'/'owned-resources.json').exists())

    def test_lifecycle_invalid_running_state_cleans_and_unmounts(self):
        with tempfile.TemporaryDirectory() as directory:
            args, cri, root, profile = self.lifecycle(directory,bad_state=True)
            with patch.object(collector, 'command', return_value=b'') as commands, patch.object(collector.os, 'statvfs', return_value=SimpleNamespace(f_bavail=1), create=True), patch.object(collector, 'read_regular') as read:
                with self.assertRaisesRegex(collector.CaptureError,'left running state'):
                    collector.run_once(args,cri,root,0,profile,{'Cmd':['/test']},DIGEST,TYPE)
                read.assert_not_called()
            self.assertTrue(any(call.args[0][0]=='umount' for call in commands.call_args_list))

    def test_ledger_write_failure_cannot_skip_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            args, cri, root, profile = self.lifecycle(directory)
            original = collector.write_json
            def writes(path, value):
                if path.name == 'owned-resources.json': raise OSError('disk full')
                return original(path, value)
            with patch.object(collector, 'command', return_value=b'') as commands, patch.object(collector.os, 'statvfs', return_value=SimpleNamespace(f_bavail=1), create=True), patch.object(collector, 'write_json', side_effect=writes), patch.object(collector, 'cleanup', wraps=collector.cleanup) as clean:
                with self.assertRaisesRegex(OSError,'disk full'):
                    collector.run_once(args,cri,root,0,profile,{'Cmd':['/test']},DIGEST,TYPE)
                clean.assert_called_once_with(cri,ID,'c'*64)
            self.assertTrue(any(call.args[0][0]=='umount' for call in commands.call_args_list))

    @unittest.skipUnless(sys.platform == 'linux', 'Collector subprocess pipe implementation targets Linux')
    def test_subprocess_output_and_time_bounds(self):
        with self.assertRaisesRegex(collector.CaptureError,'output exceeded'):
            collector.command([sys.executable,'-c','print("x"*65536)'], output_limit=1024)
        started=time.monotonic()
        with self.assertRaisesRegex(collector.CaptureError,'timed out'):
            collector.command([sys.executable,'-c','import time; time.sleep(10)'],timeout=.2)
        self.assertLess(time.monotonic()-started,3)


if __name__ == '__main__':
    unittest.main(verbosity=2)
