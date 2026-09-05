"""Journal regression fixtures only; no system service or workload is executed."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "qa_4_0_0/classify_service_journal.py"
spec = importlib.util.spec_from_file_location("service_journal", SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
FIXTURE = Path(__file__).resolve().parent / "fixtures/service-journal-regressions.jsonl"


class ServiceJournalTests(unittest.TestCase):
    def records(self):
        return [json.loads(line) for line in FIXTURE.read_text().splitlines()]

    def test_observed_mq_503_admission_and_aof_faults_are_not_a_smoke_pass(self):
        result = m.classify_lines(FIXTURE.read_text().splitlines())
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["fault_count"], 4)
        self.assertEqual(result["qa_command_echo_count"], 1)
        self.assertEqual(result["parse_error_count"], 0)
        self.assertIn("http-5xx", result["fault_records"][3]["categories"])
        self.assertEqual(result["latency_event_count"], 1)
        self.assertIn("redis-aof-fsync-delay", result["latency_events"][0]["categories"])
        self.assertEqual(result["latency_events"][0]["record"], self.records()[4])
        self.assertEqual(result["qa_command_records"][0]["record"], self.records()[-1])

    def test_actual_503_cli_returns_failure_and_preserves_raw_input(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            raw = FIXTURE.read_bytes()
            journal = d / "journal.jsonl"; journal.write_bytes(raw)
            command = [sys.executable, str(SOURCE), "--journal", str(journal),
                       "--output", str(d / "result.json"), "--faults-text", str(d / "faults.txt")]
            result = subprocess.run(command, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(json.loads((d / "result.json").read_text())["status"], "FAIL")
            self.assertEqual(len((d / "faults.txt").read_text().splitlines()), 4)
            self.assertEqual(journal.read_bytes(), raw)
            before = (d / "result.json").read_bytes()
            again = subprocess.run(command, capture_output=True, text=True, timeout=5)
            self.assertEqual(again.returncode, 2)
            self.assertEqual((d / "result.json").read_bytes(), before)

    def test_echo_only_is_retained_without_inventing_a_service_failure(self):
        echo = self.records()[-1]
        result = m.classify_lines([json.dumps(echo)])
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["fault_count"], 0)
        self.assertEqual(result["qa_command_records"][0]["record"], echo)

    def test_guest_agent_failure_is_not_suppressed_by_its_unit(self):
        record = dict(self.records()[-1], MESSAGE="Main process exited, code=exited, status=1/FAILURE")
        categories, _, echo = m.classify_record(record)
        self.assertFalse(echo)
        self.assertIn("generic-service-failure", categories)

    def test_misleading_logger_alone_cannot_turn_failure_into_command_echo(self):
        record = dict(self.records()[-1], _SYSTEMD_UNIT="other.service")
        categories, _, echo = m.classify_record(record)
        self.assertFalse(echo)
        self.assertTrue(categories)

    def test_health_failure_forms_and_generic_service_failures(self):
        for message in ("healthcheck command exceeded timeout 3s", "Health check failed with exit status125",
                        "container abc is unhealthy", "Failed to start worker.service",
                        "worker.service: Failed with result 'timeout'", "worker.service: Failed with result 'core-dump'"):
            with self.subTest(message=message):
                self.assertTrue(m.classify_record({"MESSAGE": message})[0])

    def test_http_schema_variants_and_plain_status_messages(self):
        for event in ({"status": 503}, {"fields": {"status": "503"}},
                      {"http.response.status_code": 502}, {"status_code": 500}):
            self.assertIn("http-5xx", m.classify_record({"MESSAGE": json.dumps(event)})[0])
        for message in ("HTTP/1.1 503 Service Unavailable", "HTTP 502 Bad Gateway"):
            self.assertIn("http-5xx", m.classify_record({"MESSAGE": message})[0])

    def test_aof_delay_is_retained_latency_not_a_failed_request(self):
        record = self.records()[4]
        result = m.classify_lines([json.dumps(record)])
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["fault_count"], 0)
        self.assertEqual(result["latency_event_count"], 1)
        self.assertEqual(result["latency_events"][0]["record"], record)

    def test_configured_healthcheck_timeout_is_not_a_failed_healthcheck(self):
        self.assertEqual(m.classify_record({"MESSAGE": "healthcheck interval=30s timeout=3s"})[0], [])

    def test_successful_vendor_records_are_preserved_as_other(self):
        records = [{"SYSLOG_IDENTIFIER": "shadowfetch-buzz_relay_1", "MESSAGE": json.dumps(event)} for event in (
            {"level": "INFO", "message": "HTTP bridge request", "status": 200},
            {"level": "INFO", "message": "Redis pool initialized"})]
        result = m.classify_lines(map(json.dumps, records))
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["other_record_count"], 2)

    def test_vendor_error_is_not_lost_without_an_old_grep_phrase(self):
        record = {"_SYSTEMD_USER_UNIT": "shadowfetch-buzz.service", "MESSAGE": '{"level":"ERROR","message":"backend stopped"}'}
        self.assertIn("vendor-error", m.classify_record(record)[0])

    def test_malformed_or_missing_message_fails_closed_with_line_provenance(self):
        result = m.classify_lines(['{"MESSAGE": "ok"}', '{"MESSAGE":', '{}'])
        self.assertEqual(result["status"], "ERROR")
        self.assertEqual([r["line"] for r in result["parse_errors"]], [2, 3])
        self.assertEqual(result["other_record_count"], 1)

    def test_empty_journal_cannot_pass_as_available_telemetry(self):
        result = m.classify_lines([])
        self.assertEqual(result["status"], "ERROR")
        self.assertEqual(result["record_count"], 0)
        self.assertIn("telemetry unavailable", result["parse_errors"][0]["error"])

    def test_journalctl_null_message_cannot_be_excused_as_a_qa_echo(self):
        # Retained development JSON had two long qemu-ga MESSAGE fields emitted
        # as null without journalctl --all. Provenance cannot recover the body.
        record = {"MESSAGE": None, "_SYSTEMD_UNIT": "qemu-guest-agent.service",
                  "SYSLOG_IDENTIFIER": "qemu-ga", "_COMM": "qemu-ga"}
        result = m.classify_lines([json.dumps(record)])
        self.assertEqual(result["status"], "ERROR")
        self.assertEqual(result["parse_error_count"], 1)
        self.assertEqual(result["qa_command_echo_count"], 0)
        self.assertEqual(result["parse_errors"][0]["line"], 1)

    def test_empty_journal_cli_fails_even_when_capture_command_succeeded(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            journal = d / "empty.jsonl"; journal.write_text("")
            result = subprocess.run([sys.executable, str(SOURCE), "--journal", str(journal),
                "--output", str(d / "result.json"), "--faults-text", str(d / "faults.txt")],
                capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(json.loads((d / "result.json").read_text())["status"], "ERROR")
            self.assertEqual(journal.read_text(), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
