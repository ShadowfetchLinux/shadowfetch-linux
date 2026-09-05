#!/usr/bin/env python3
"""Classify retained journalctl JSON records; never changes runtime or raw logs."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

SCHEMA = 1
GENERIC_FAILURE = re.compile(r"Failed to start |Failed with result|Main process exited, code=|core-dump", re.I)
HEALTH_FAILURE = re.compile(r"health[- ]?check.{0,160}(?:\bfail(?:ed|ure)?\b|\bunhealthy\b|\btimed out\b|\bexceeded\b)|container.{0,100}\bunhealthy\b", re.I)
AOF_DELAY = re.compile(r"Asynchronous AOF fsync is taking too long", re.I)
REDIS_FAILURE = re.compile(r"\bRedis\b.{0,240}(?:timed out|timeout|failed|error|unavailable)", re.I)
ADMISSION_FAILURE = re.compile(r"\badmission\b.{0,100}(?:unavailable|failed|timed out)", re.I)
HTTP_FAILURE = re.compile(r"\bHTTP(?:/\d(?:\.\d)?)?\s+5\d\d\b|\b5\d\d\s+(?:Service Unavailable|Internal Server Error|Bad Gateway|Gateway Timeout)\b", re.I)
COMMAND_ECHO = re.compile(r"^(?:info:\s*)?guest-exec(?:-status)? called:\s*", re.I)


def classify_record(record):
    """Return fault/latency categories plus echo status; never drops a record."""
    if not isinstance(record, dict) or not isinstance(record.get("MESSAGE"), str):
        raise ValueError("Journal record must contain a string MESSAGE")
    message = record["MESSAGE"]
    # Only the guest agent's actual command-log prefix is an observer echo.
    # A failure emitted by this same unit remains a real generic service fault.
    is_agent = record.get("_SYSTEMD_UNIT") == "qemu-guest-agent.service" and (
        record.get("SYSLOG_IDENTIFIER") == "qemu-ga" or record.get("_COMM") == "qemu-ga")
    if is_agent and COMMAND_ECHO.match(message):
        return [], [], True
    categories, latency = [], []
    if GENERIC_FAILURE.search(message):
        categories.append("generic-service-failure")
    if HEALTH_FAILURE.search(message):
        categories.append("healthcheck-failure")
    if AOF_DELAY.search(message):
        latency.append("redis-aof-fsync-delay")
    if HTTP_FAILURE.search(message):
        categories.append("http-5xx")
    vendor = record.get("_SYSTEMD_USER_UNIT") == "shadowfetch-buzz.service" or bool(
        re.fullmatch(r"shadowfetch-buzz(?:[-_].*)?", str(record.get("SYSLOG_IDENTIFIER", ""))))
    if vendor:
        if REDIS_FAILURE.search(message):
            categories.append("redis-failure")
        if ADMISSION_FAILURE.search(message):
            categories.append("admission-failure")
    try:
        event = json.loads(message)
    except ValueError:
        event = None
    if isinstance(event, dict):
        fields = dict(event)
        if isinstance(event.get("fields"), dict):
            fields.update(event["fields"])
        for key in ("status", "status_code", "http.status_code", "http.response.status_code"):
            value = fields.get(key)
            if (isinstance(value, int) and not isinstance(value, bool) and 500 <= value <= 599) or (
                    isinstance(value, str) and re.fullmatch(r"5\d\d", value)):
                categories.append("http-5xx")
        if vendor and str(event.get("level", "")).upper() in ("ERROR", "FATAL"):
            categories.append("vendor-error")
    return sorted(set(categories)), latency, False


def classify_lines(lines):
    faults, latency_events, echoes, errors = [], [], [], []
    count = other = 0
    for number, line in enumerate(lines, 1):
        count += 1
        try:
            record = json.loads(line)
            categories, latency, echo = classify_record(record)
        except (ValueError, TypeError) as exc:
            errors.append({"line": number, "error": str(exc), "raw_line_sha256": hashlib.sha256(line.encode()).hexdigest()})
            continue
        retained = {"line": number, "record": record}
        if echo:
            echoes.append(retained)
        else:
            if categories:
                faults.append(dict(retained, categories=categories))
            if latency:
                latency_events.append(dict(retained, categories=latency))
            if not categories and not latency:
                other += 1
    if not count:
        errors.append({"line": 0, "error": "No journal records captured; telemetry unavailable"})
    return {"schema": SCHEMA, "status": "ERROR" if errors else "FAIL" if faults else "PASS",
            "record_count": count, "fault_count": len(faults), "qa_command_echo_count": len(echoes),
            "latency_event_count": len(latency_events), "latency_events": latency_events,
            "other_record_count": other, "parse_error_count": len(errors),
            "fault_records": faults, "qa_command_records": echoes, "parse_errors": errors,
            "scope": "Service journal classification only; raw input remains authoritative and kernel/package/unit-list checks remain separate"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--journal", required=True, type=Path, help="Unmodified journalctl --output=json JSONL")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--faults-text", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.journal.is_symlink() or not args.journal.is_file() or args.journal.stat().st_size > 128 * 1024**2:
        parser.error("A regular retained journal up to 128 MiB is required")
    if args.output.exists() or args.output.is_symlink() or args.faults_text.exists() or args.faults_text.is_symlink():
        parser.error("Refusing to overwrite earlier classification")
    raw = args.journal.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        parser.error("journalctl JSON output is not valid UTF-8; raw bytes preserved")
    result = classify_lines(text.splitlines())
    result["source"] = {"path": str(args.journal), "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    with args.faults_text.open("x") as stream:
        for item in result["fault_records"]:
            stream.write(json.dumps(item, sort_keys=True) + "\n")
    print(json.dumps({key: result[key] for key in ("status", "record_count", "fault_count", "latency_event_count", "qa_command_echo_count", "parse_error_count")}))
    return 2 if result["parse_errors"] else 1 if result["fault_records"] else 0


if __name__ == "__main__":
    sys.exit(main())
