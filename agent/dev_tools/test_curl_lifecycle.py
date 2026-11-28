"""Managed admission, maintenance fencing and cleanup records with no host state changes."""

from contextlib import nullcontext
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import curl_lifecycle as lifecycle
from curl_windows import LogonScope


SCOPE = LogonScope(b"user-a", 1234, 5, 8192)
OPERATION = "c" * 32
CLEAN = dict(worker_cleanup_confirmed=True, pending_resumes=0, report_drained=True, runtime_failed=False)


class ManagedInstanceTests(unittest.TestCase):
    def setUp(self):
        self.store = Mock()
        self.store.maintenance.return_value = ""
        self.registry = patch.object(lifecycle, "_Registry", return_value=self.store).start()
        self.mutex = patch.object(lifecycle, "_singleton", return_value=nullcontext(True)).start()
        self.addCleanup(patch.stopall)

    def test_singleton_distinguishes_sid_logon_and_session(self):
        scopes = [SCOPE, SCOPE._replace(user_sid=b"user-b"), SCOPE._replace(authentication_id=1235),
                  SCOPE._replace(session_id=6)]
        self.assertEqual(len({lifecycle.ManagedInstance(scope).name for scope in scopes}), 4)
        self.assertEqual(lifecycle.ManagedInstance(SCOPE).name, lifecycle.ManagedInstance(SCOPE).name)

    def test_duplicate_never_registers(self):
        self.mutex.return_value = nullcontext(False)
        with lifecycle.ManagedInstance(SCOPE) as instance:
            self.assertFalse(instance.admitted)
        self.registry.assert_not_called()

    def test_maintenance_prevents_admission(self):
        self.store.maintenance.return_value = OPERATION
        with lifecycle.ManagedInstance(SCOPE) as instance:
            self.assertFalse(instance.admitted)
        self.store.register.assert_not_called()

    def test_retired_generation_never_scans(self):
        self.store.current_generation.return_value = False
        with lifecycle.ManagedInstance(SCOPE) as instance:
            self.assertFalse(instance.admitted)
        self.store.register.assert_not_called()

    def test_maintenance_arriving_during_registration_closes_without_polling(self):
        self.store.maintenance.side_effect = ["", OPERATION, OPERATION]
        with lifecycle.ManagedInstance(SCOPE) as instance:
            self.assertFalse(instance.admitted)
            self.assertTrue(instance.stop.is_set())
        receipt = self.store.write.call_args.args[0]
        self.assertEqual((receipt["operation"], receipt["state"]), (OPERATION, "complete"))

    def test_receipt_binds_instance_and_current_operation(self):
        with lifecycle.ManagedInstance(SCOPE) as instance:
            self.assertTrue(instance.admitted)
            start = self.store.register.call_args.args[1]
            self.assertEqual(start["state"], "running")
            self.assertEqual(start["operation"], "")
            self.store.maintenance.return_value = OPERATION
            self.assertTrue(instance.stop.wait(2))
            self.assertEqual(instance.finish(CLEAN), "complete")
        end = self.store.write.call_args.args[0]
        self.assertEqual((end["instance"], end["local_stop"]), (start["instance"], start["local_stop"]))
        self.assertEqual(end["operation"], OPERATION)

    def test_each_ordinary_exit_uses_fresh_instance_and_local_stop(self):
        ids = set()
        for _ in range(2):
            with lifecycle.ManagedInstance(SCOPE) as instance:
                self.assertEqual(instance.finish(CLEAN), "complete")
            receipt = self.store.write.call_args.args[0]
            self.assertEqual(receipt["operation"], receipt["local_stop"])
            ids.update([receipt["instance"], receipt["local_stop"]])
        self.assertEqual(len(ids), 4)

    def test_natural_logoff_observes_challenge_published_during_receipt_write(self):
        with lifecycle.ManagedInstance(SCOPE) as instance:
            self.store.write.side_effect = lambda *_: setattr(self.store.maintenance, "return_value", OPERATION)
            self.assertEqual(instance.finish(CLEAN), "complete")
        first, second = (call.args[0] for call in self.store.write.call_args_list)
        self.assertEqual(first["operation"], first["local_stop"])
        self.assertEqual(second, dict(first, operation=OPERATION))

    def test_incomplete_cleanup_keeps_logon_marker(self):
        for outcome in (dict(CLEAN, pending_resumes=1), dict(CLEAN, worker_cleanup_confirmed=False)):
            with self.subTest(outcome=outcome), lifecycle.ManagedInstance(SCOPE) as instance:
                self.assertEqual(instance.finish(outcome), "incomplete")
                self.store.clear_logon.assert_not_called()

    def test_report_timeout_is_distinct_from_process_cleanup(self):
        with lifecycle.ManagedInstance(SCOPE) as instance:
            self.assertEqual(instance.finish(dict(CLEAN, report_drained=False)), "complete")
        receipt = self.store.write.call_args.args[0]
        self.assertFalse(receipt["report_drained"])

    def test_exit_without_cleanup_leaves_running_record(self):
        with self.assertRaises(ArithmeticError), lifecycle.ManagedInstance(SCOPE) as instance:
            self.assertTrue(instance.admitted)
            raise ArithmeticError()
        self.store.write.assert_not_called()
        self.store.clear_logon.assert_not_called()

    def test_changed_operation_never_certifies_cleanup(self):
        with lifecycle.ManagedInstance(SCOPE) as instance:
            self.store.maintenance.return_value = OPERATION
            self.assertTrue(instance.stop.wait(2))
            self.store.maintenance.return_value = "d" * 32
            with self.assertRaisesRegex(RuntimeError, "lost its maintenance"):
                instance.finish(CLEAN)
        self.store.write.assert_not_called()

    def test_registry_failure_interrupts_and_leaves_unconfirmed_record(self):
        with lifecycle.ManagedInstance(SCOPE) as instance:
            self.store.maintenance.side_effect = PermissionError()
            self.assertTrue(instance.stop.wait(2))
            with self.assertRaises(PermissionError):
                instance.finish(CLEAN)
        self.store.write.assert_not_called()

    def test_malformed_or_missing_cleanup_facts_never_certify_success(self):
        for outcome in ({}, dict(CLEAN, pending_resumes=False), dict(CLEAN, worker_cleanup_confirmed=1)):
            with self.subTest(outcome=outcome), lifecycle.ManagedInstance(SCOPE) as instance:
                with self.assertRaisesRegex(ValueError, "Invalid"):
                    instance.finish(outcome)
        self.store.write.assert_not_called()

    def test_failed_receipt_write_preserves_dirty_marker(self):
        self.store.write.side_effect = PermissionError()
        with lifecycle.ManagedInstance(SCOPE) as instance, self.assertRaises(PermissionError):
            instance.finish(CLEAN)
        self.store.clear_logon.assert_not_called()


class RegistryTests(unittest.TestCase):
    def setUp(self):
        reg = MagicMock()
        reg.KEY_WOW64_64KEY = 0x100
        reg.KEY_QUERY_VALUE = 1
        reg.KEY_SET_VALUE = 2
        reg.KEY_CREATE_SUB_KEY = 4
        reg.REG_SZ = 1
        stack = lifecycle.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.dict(sys.modules, winreg=reg))
        self.store = lifecycle._Registry(stack)
        self.reg = reg

    def test_control_values_read_from_fixed_64_bit_key_and_validated(self):
        self.reg.OpenKey.assert_called_once_with(self.reg.HKEY_LOCAL_MACHINE, lifecycle.CONTROL_KEY, 0, 0x101)
        for value, kind in (("", 1), (OPERATION, 1), ("bad", 1), (OPERATION, 2)):
            self.reg.QueryValueEx.return_value = value, kind
            if kind == 1 and value in ("", OPERATION):
                self.assertEqual(self.store.maintenance(), value)
            else:
                with self.assertRaises(ValueError):
                    self.store.maintenance()

    def test_existing_dirty_logon_blocks_registration(self):
        self.reg.QueryValueEx.return_value = "prior-instance", 1
        with self.assertRaisesRegex(RuntimeError, "Previous Curl cleanup"):
            self.store.register("scope", {"instance": "different"})
        self.reg.SetValueEx.assert_not_called()

    def test_reconciles_only_certified_prior_instance_after_crash_clearing_marker(self):
        previous = "e" * 32
        record = dict(CLEAN, instance=previous, version=1, operation=OPERATION, local_stop="d" * 32, state="complete")
        for overrides, allow in (({}, True), ({"instance": "f" * 32}, False), ({"state": "running"}, False),
                                 ({"worker_cleanup_confirmed": False}, False), ({"pending_resumes": 1}, False)):
            with self.subTest(overrides=overrides):
                self.reg.QueryValueEx.side_effect = [
                    (previous, 1), (json.dumps(dict(record, **overrides)), 1), FileNotFoundError()]
                if allow:
                    self.store.register("scope", {"instance": "a" * 32})
                else:
                    with self.assertRaisesRegex(RuntimeError, "Previous Curl cleanup"):
                        self.store.register("scope", {"instance": "a" * 32})

    def test_instances_parent_opened_with_create_only_and_flushed_before_polling(self):
        self.reg.QueryValueEx.side_effect = FileNotFoundError()
        self.store.register("scope", {"instance": "a" * 32})
        self.reg.OpenKey.assert_called_with(self.store.control, "Instances", 0, 0x104)
        self.assertEqual(self.reg.FlushKey.call_count, 2)

    def test_reused_logon_requires_disposition_for_exact_previous_running_record(self):
        previous = "e" * 32
        original = json.dumps(dict(version=1, instance=previous, local_stop="d" * 32,
                                   state="running", operation="", **dict.fromkeys(CLEAN)))
        disposition = dict(reason="abandoned_after_full_restart", record=original,
                           operation=OPERATION, witness="b" * 32)
        for delta, allowed in (({}, True), ({"record": original + " "}, False),
                               ({"reason": "complete"}, False), ({"witness": ""}, False)):
            with self.subTest(delta=delta):
                self.reg.QueryValueEx.side_effect = [
                    (original, 1), (json.dumps(dict(disposition, **delta)), 1)]
                self.assertEqual(self.store._previous_resolved(previous), allowed)
                self.reg.OpenKey.assert_called_with(
                    self.store.control, "RestartEvidence\\" + previous, 0, 0x101)
        self.reg.QueryValueEx.side_effect = [
            (previous, 1), (original, 1), (json.dumps(disposition), 1), FileNotFoundError()]
        self.store.register("scope", {"instance": "a" * 32})
        self.assertEqual(self.reg.SetValueEx.call_count, 2)
        self.reg.SetValueEx.assert_called_with(self.store.logon, "scope", 0, 1, "a" * 32)

    def test_foreign_dirty_marker_never_removed(self):
        self.store.logon = object()
        self.reg.QueryValueEx.return_value = "b" * 32, 1
        with self.assertRaisesRegex(RuntimeError, "ownership"):
            self.store.clear_logon("scope", "a" * 32)
        self.reg.DeleteValue.assert_not_called()


class StandaloneAdmissionTests(unittest.TestCase):
    def test_uses_managed_singleton_on_unmanaged_machine(self):
        with patch.object(lifecycle, "_managed_installed", return_value=False):
            with patch.object(lifecycle, "_singleton", return_value=nullcontext(False)) as singleton:
                with lifecycle.standalone_admission(SCOPE) as admitted:
                    self.assertFalse(admitted)
                singleton.assert_called_once_with(lifecycle.ManagedInstance(SCOPE).name)

    def test_deployment_between_lookup_and_mutex_blocks_standalone(self):
        with patch.object(lifecycle, "_managed_installed", side_effect=[False, True]):
            with patch.object(lifecycle, "_singleton", return_value=nullcontext(True)):
                with lifecycle.standalone_admission(SCOPE) as admitted:
                    self.assertFalse(admitted)

    def test_installation_blocks_even_elevated_or_unsupported_standalone(self):
        with patch.object(lifecycle, "_managed_installed", return_value=True):
            with patch("curl_windows.watcher_scope") as lookup, lifecycle.standalone_admission() as admitted:
                self.assertFalse(admitted)
            lookup.assert_not_called()

    def test_unmanaged_elevated_lab_can_run_v1(self):
        from curl_windows import OriginUnavailable
        with patch.object(lifecycle, "_managed_installed", return_value=False):
            with patch("curl_windows.watcher_scope", side_effect=OriginUnavailable("unsupported")):
                with lifecycle.standalone_admission() as admitted:
                    self.assertTrue(admitted)

    def test_missing_or_explicitly_uninstalled_root_allows_standalone(self):
        reg = MagicMock()
        reg.KEY_QUERY_VALUE = 1
        reg.KEY_WOW64_64KEY = 0x100
        reg.REG_SZ = 1
        with patch.dict(sys.modules, winreg=reg):
            reg.OpenKey.side_effect = FileNotFoundError()
            self.assertFalse(lifecycle._managed_installed())
            reg.OpenKey.side_effect = PermissionError()
            with self.assertRaises(PermissionError):
                lifecycle._managed_installed()
            reg.OpenKey.side_effect = None
            reg.QueryValueEx.side_effect = [("", 1), ("", 1)]
            self.assertFalse(lifecycle._managed_installed())
            reg.QueryValueEx.side_effect = [("", 1), (OPERATION, 1)]
            self.assertTrue(lifecycle._managed_installed())
            reg.QueryValueEx.side_effect = [(OPERATION, 1)]
            self.assertTrue(lifecycle._managed_installed())
            reg.QueryValueEx.side_effect = FileNotFoundError()
            with self.assertRaises(FileNotFoundError):
                lifecycle._managed_installed()


if __name__ == "__main__":
    unittest.main()
