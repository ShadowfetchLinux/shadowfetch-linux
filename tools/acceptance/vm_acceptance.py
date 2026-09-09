#!/usr/bin/env python3
"""Shadowfetch VM acceptance harness.

ONE WORKFLOW. Executing a case, capturing its evidence, binding that evidence
to the artifact digest and recording the result are a single command. There is
no subcommand that marks a case passed, and no way to hand this tool a verdict:
a verdict exists only as the return value of a case that this process just ran
against a running machine.

That is the whole point of the design. The release this harness serves was
published with thirteen of eighteen required cases unproven, because "run the
test" and "write PASS in the manifest" were two separate acts with a human in
between. Here the second act is unreachable except through the first.

  vm_acceptance.py list
  vm_acceptance.py run --case recovery --artifact ISO --base-image DISK
  vm_acceptance.py run --case live-boot --artifact ISO --record
  vm_acceptance.py verify --all
  vm_acceptance.py status

Exit status: 0 only when the case PASSED. BLOCKED is 3, FAIL is 1, a harness
error is 2. A blocked case is not a pass and does not exit 0.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import socket
import sys
import time
import traceback

# Executed directly as tools/acceptance/vm_acceptance.py, so put tools/ on the
# path and adopt the package name the relative imports inside the modules need.
# tools/ deliberately has no __init__.py of its own: adding one would change how
# every other tool in that directory is imported.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    __package__ = "acceptance"

from acceptance import release_link, trusted  # noqa: E402
from acceptance.cases import CASES, Blocked, Context  # noqa: E402
from acceptance.evidence import (  # noqa: E402
    EvidenceSet,
    harness_fingerprint,
    sha256_file,
    utc_now,
)
from acceptance.ledger import Ledger, receipt_problems, write_receipt  # noqa: E402

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_ERROR = 2
EXIT_BLOCKED = 3


def repo_root() -> Path:
    root = Path(__file__).resolve().parents[2]
    if not (root / "Makefile").is_file() or not (root / "packages").is_dir():
        raise SystemExit(f"ERROR: {root} does not look like the repository root")
    return root


def work_root(root: Path, version: str) -> Path:
    return root / "work" / f"qa-{version}"


def ledger_for(root: Path, version: str) -> Ledger:
    return Ledger(work_root(root, version) / "vm-acceptance" / "ledger.jsonl")


def artifact_facts(root: Path, path: Path) -> dict:
    """Identify the artifact under test and cross-check its published digest."""
    path = path.resolve()
    if not path.is_file():
        raise SystemExit(f"ERROR: artifact does not exist: {path}")
    digest = sha256_file(path)
    facts = {
        "path": str(path),
        "name": path.name,
        "sha256": digest,
        "size_bytes": path.stat().st_size,
        "mtime_utc": time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(path.stat().st_mtime)
        ),
        "sidecar_sha256": None,
        "sidecar_agrees": None,
        "signature_path": None,
    }
    sidecar = path.with_suffix(path.suffix + ".sha256")
    if sidecar.is_file():
        published = sidecar.read_text(encoding="utf-8").split()[0].strip().lower()
        facts["sidecar_sha256"] = published
        facts["sidecar_agrees"] = published == digest
    signature = path.with_suffix(path.suffix + ".asc")
    if signature.is_file():
        facts["signature_path"] = str(signature)
        facts["signature_sha256"] = sha256_file(signature)
    return facts


def verdict_for(ctx: Context) -> tuple[str, str]:
    if not ctx.checks:
        return (
            "BLOCKED",
            "no check was evaluated, so nothing was proven either way",
        )
    failed = [check for check in ctx.checks if check["state"] == "FAILED"]
    if failed:
        return "FAIL", "; ".join(check["name"] for check in failed)
    return "PASS", f"{len(ctx.checks)} checks evaluated against the running system"


def command_run(args: argparse.Namespace) -> int:
    root = repo_root()
    case = CASES.get(args.case)
    if case is None:
        print(
            f"ERROR: unknown case {args.case!r}. Known: {', '.join(sorted(CASES))}",
            file=sys.stderr,
        )
        return EXIT_ERROR

    release = release_link.load_release(args.version)
    version = release.version
    artifact = artifact_facts(root, args.artifact)
    if artifact["sidecar_agrees"] is False:
        print(
            "ERROR: the artifact does not match its published .sha256 sidecar; "
            "refusing to produce acceptance evidence for an unidentified image",
            file=sys.stderr,
        )
        return EXIT_ERROR

    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    run_id = f"{case.name}-{stamp}-{artifact['sha256'][:12]}"
    run_dir = work_root(root, version) / "vm-acceptance" / run_id
    evidence_dir = work_root(root, version) / "evidence" / "vm-acceptance" / run_id
    run_dir.mkdir(parents=True, exist_ok=False)

    options = {
        "version": version,
        "firmware": args.firmware,
        "disk_gib": args.disk_gib,
        "boot_timeout": args.boot_timeout,
        "desktop_settle": args.desktop_settle,
        "base_image": args.base_image,
        "upgrade_base_image": args.upgrade_base_image,
        "upgrade_repo": args.upgrade_repo,
        "upgrade_from_version": args.upgrade_from_version,
        "interrupt_deadline": args.interrupt_deadline,
    }
    evidence = EvidenceSet(root, evidence_dir)
    ctx = Context(
        name=case.name,
        repo_root=root,
        run_dir=run_dir,
        evidence=evidence,
        artifact=artifact,
        options=options,
    )

    started = utc_now()
    started_monotonic = time.monotonic()
    ctx.log(f"run {run_id}")
    ctx.log(f"case {case.name}: {case.summary}")
    ctx.log(f"release {version} ({release.edition}, {release.display_codename})")
    ctx.log(f"artifact {artifact['name']} sha256={artifact['sha256']}")
    if artifact["name"] != release.iso_name and case.consumes_artifact:
        ctx.log(
            f"NOTE artifact is named {artifact['name']}, the release data names "
            f"{release.iso_name}"
        )

    verdict, reason, failure = "ERROR", "", None
    try:
        case.run(ctx)
        verdict, reason = verdict_for(ctx)
    except Blocked as blocked:
        verdict, reason = "BLOCKED", str(blocked)
        ctx.log(f"BLOCKED {reason}")
    except BaseException as error:  # noqa: BLE001 - a crash must not become a pass
        verdict = "ERROR"
        reason = f"{type(error).__name__}: {error}"
        failure = traceback.format_exc()
        ctx.log(f"ERROR {reason}")
    finally:
        for machine in ctx.guests:
            if machine.is_running():
                try:
                    machine.shutdown(timeout=60)
                except Exception:  # noqa: BLE001 - cleanup must not mask a result
                    try:
                        machine.kill_hard()
                    except Exception:  # noqa: BLE001
                        pass

    # A failed check anywhere outranks a clean finish: a case that evaluated a
    # failing check and then hit a harness error is still a failing case.
    if verdict in ("BLOCKED", "ERROR") and any(
        check["state"] == "FAILED" for check in ctx.checks
    ):
        reason = (
            f"{verdict.lower()} after a failing check; reported as FAIL: {reason}"
        )
        verdict = "FAIL"

    transcript = "\n".join(ctx.transcript) + "\n"
    if failure:
        transcript += "\n" + failure
    evidence.write_text(f"{case.name}-transcript.log", transcript)

    receipt = {
        "schema": "shadowfetch.vm-acceptance.receipt/1",
        "run_id": run_id,
        "case": case.name,
        "case_summary": case.summary,
        "manifest_case": case.manifest_case,
        "verdict": verdict,
        "verdict_reason": reason,
        "started_utc": started,
        "finished_utc": utc_now(),
        "duration_seconds": round(time.monotonic() - started_monotonic, 1),
        "release": {
            "version": version,
            "edition": release.edition,
            "codename": release.display_codename,
            "data_file": str(release.path.relative_to(root)),
            "historical": release.historical,
        },
        "artifact": artifact,
        "artifact_consumed_by_case": case.consumes_artifact,
        "host": {
            "hostname": socket.gethostname(),
            "kernel": platform.release(),
            "python": platform.python_version(),
            "uid": os.getuid(),
        },
        "harness": harness_fingerprint(Path(__file__).resolve().parent),
        "trust_base": trusted.describe(),
        "options": options,
        "checks": ctx.checks,
        "observations": ctx.observations,
        "evidence": evidence.items,
        "evidence_root": str(evidence_dir.relative_to(root)),
        "boots": [boot for machine in ctx.guests for boot in machine.boots],
        "traceback": failure,
    }
    receipt_path = run_dir / "receipt.json"
    receipt_digest = write_receipt(receipt_path, receipt)

    ledger = ledger_for(root, version)
    entry = ledger.append(
        {
            "run_id": run_id,
            "case": case.name,
            "manifest_case": case.manifest_case,
            "verdict": verdict,
            "artifact_sha256": artifact["sha256"],
            "harness_digest": receipt["harness"]["digest"],
            "receipt_sha256": receipt_digest,
            "receipt_path": str(receipt_path.relative_to(root)),
            "evidence_count": len(evidence.items),
        }
    )

    print()
    print(f"VERDICT {verdict} case={case.name} run={run_id}")
    print(f"  reason        {reason}")
    print(f"  checks        {len(ctx.checks)} evaluated")
    print(f"  evidence      {len(evidence.items)} files in {evidence_dir}")
    print(f"  receipt       {receipt_path} ({receipt_digest[:16]}...)")
    print(f"  ledger        entry {entry['seq']} ({entry['entry_sha256'][:16]}...)")

    if args.record:
        code = _record(root, release, case, receipt, receipt_path, ledger)
        if code:
            return code

    return {
        "PASS": EXIT_PASS,
        "FAIL": EXIT_FAIL,
        "BLOCKED": EXIT_BLOCKED,
    }.get(verdict, EXIT_ERROR)


def _record(
    root: Path,
    release,
    case,
    receipt: dict,
    receipt_path: Path,
    ledger: Ledger,
) -> int:
    """Record this run's result into the release acceptance manifest.

    Reachable only from the end of a run that just happened, and only for a
    PASS. Every guard here refuses; none of them can promote anything.
    """
    if receipt["verdict"] != "PASS":
        print(
            f"NOT RECORDED: verdict is {receipt['verdict']}, and only a PASS is "
            "ever recorded. Nothing was written to the manifest.",
            file=sys.stderr,
        )
        return 0
    if not case.manifest_case:
        print(
            f"NOT RECORDED: case {case.name!r} has no release manifest case; its "
            "result lives in the run ledger only."
        )
        return 0
    if case.manifest_gap:
        print(
            f"NOT RECORDED: this case does not prove all of {case.manifest_case}. "
            f"{case.manifest_gap} The run PASSED and its receipt and ledger entry "
            "stand; the release manifest is unchanged."
        )
        return 0
    for companion in case.companions:
        passes = [
            row
            for row in ledger.find(
                case=companion,
                verdict="PASS",
                artifact_sha256=receipt["artifact"]["sha256"],
            )
        ]
        if not passes:
            print(
                f"NOT RECORDED: {case.manifest_case} also requires case "
                f"{companion!r} to have passed against this same artifact, and the "
                "ledger has no such run. Run it first.",
                file=sys.stderr,
            )
            return EXIT_BLOCKED
    problems = ledger.verify()
    if problems:
        print(
            "NOT RECORDED: the run ledger does not verify, so no run in it can be "
            "trusted to have happened:\n  " + "\n  ".join(problems),
            file=sys.stderr,
        )
        return EXIT_ERROR

    manifest = release.acceptance_manifest()
    recorder = release_link.recorder_path()
    evidence_root = (work_root(root, release.version) / "evidence").resolve()
    files = [
        str((root / item["relative_path"]).resolve()) for item in receipt["evidence"]
    ]
    if not files:
        print(
            "NOT RECORDED: the run produced no evidence files. A passing case "
            "without evidence is not recordable.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    notes = (
        f"Recorded by tools/acceptance/vm_acceptance.py run --case {case.name} "
        f"(run {receipt['run_id']}, receipt {receipt['receipt_sha256'][:16]}, "
        f"harness {receipt['harness']['digest'][:16]}) against "
        f"{receipt['artifact']['name']} sha256 {receipt['artifact']['sha256']}. "
        f"{len(receipt['checks'])} checks evaluated against the running machine."
    )
    argv = [
        str(recorder),
        "--version",
        release.version,
        "--manifest",
        str(manifest),
        "record",
        case.manifest_case,
        "--status",
        "pass",
        "--notes",
        notes,
    ]
    for path in files:
        argv += ["--evidence", path]
    result = trusted.run("python3", argv, timeout=600, check=False)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if result.returncode != 0:
        print(
            f"NOT RECORDED: the release recorder refused (exit {result.returncode}). "
            "The run receipt and ledger entry stand; the manifest is unchanged.",
            file=sys.stderr,
        )
        return EXIT_ERROR
    print(
        f"RECORDED {case.manifest_case} = pass from run {receipt['run_id']} "
        f"({len(files)} evidence files under {evidence_root})"
    )
    return 0


def command_list(args: argparse.Namespace) -> int:
    print(f"{'case':<22} {'manifest':<12} {'~min':>5}  summary")
    for name in sorted(CASES):
        case = CASES[name]
        print(
            f"{case.name:<22} {case.manifest_case or '-':<12} {case.minutes:>5}  "
            f"{case.summary}"
        )
    return 0


def command_status(args: argparse.Namespace) -> int:
    root = repo_root()
    ledger = ledger_for(root, release_link.load_release(args.version).version)
    rows = ledger.entries()
    problems = ledger.verify()
    if not rows:
        print("No runs recorded yet.")
        return 0
    print(f"{'seq':>4} {'verdict':<8} {'case':<22} {'artifact':<14} run")
    for row in rows:
        print(
            f"{row['seq']:>4} {row['verdict']:<8} {row['case']:<22} "
            f"{row['artifact_sha256'][:12]:<14} {row['run_id']}"
        )
    if problems:
        print("\nLEDGER PROBLEMS:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return EXIT_ERROR
    print(f"\nLedger intact: {len(rows)} entries, head {ledger.head()[:16]}...")
    return 0


def command_verify(args: argparse.Namespace) -> int:
    """Re-verify recorded runs: chain, receipts, and every evidence byte."""
    root = repo_root()
    ledger = ledger_for(root, release_link.load_release(args.version).version)
    problems = ledger.verify()
    rows = ledger.entries()
    if args.run_id:
        rows = [row for row in rows if row["run_id"] == args.run_id]
        if not rows:
            print(f"ERROR: no run {args.run_id!r} in the ledger", file=sys.stderr)
            return EXIT_ERROR
    checked = 0
    for row in rows:
        receipt_path = root / row["receipt_path"]
        if not receipt_path.is_file():
            problems.append(f"{row['run_id']}: receipt is missing ({receipt_path})")
            continue
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        problems.extend(
            f"{row['run_id']}: {problem}" for problem in receipt_problems(receipt)
        )
        if receipt.get("receipt_sha256") != row["receipt_sha256"]:
            problems.append(
                f"{row['run_id']}: receipt digest differs from the ledger entry"
            )
        if receipt.get("artifact", {}).get("sha256") != row["artifact_sha256"]:
            problems.append(
                f"{row['run_id']}: receipt names a different artifact than the ledger"
            )
        for item in receipt.get("evidence", []):
            path = root / item["relative_path"]
            if not path.is_file():
                problems.append(f"{row['run_id']}: missing evidence {path}")
                continue
            if sha256_file(path) != item["sha256"]:
                problems.append(
                    f"{row['run_id']}: evidence changed since the run: {path}"
                )
        checked += 1
    if problems:
        for problem in problems:
            print(f"PROBLEM: {problem}", file=sys.stderr)
        print(f"VERIFY_FAILED runs={checked} problems={len(problems)}", file=sys.stderr)
        return EXIT_ERROR
    print(f"VERIFY_OK runs={checked} ledger_head={ledger.head()[:16]}...")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--version",
        help="release under test; defaults to the sole non-historical data file "
        "in tools/release/versions/",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="execute one case end to end")
    run_parser.add_argument("--case", required=True)
    run_parser.add_argument("--artifact", type=Path, required=True)
    run_parser.add_argument("--firmware", choices=("bios", "uefi"), default="bios")
    run_parser.add_argument("--disk-gib", type=int, default=40)
    run_parser.add_argument("--boot-timeout", type=float, default=900.0)
    run_parser.add_argument("--desktop-settle", type=float, default=90.0)
    run_parser.add_argument(
        "--base-image", help="installed image of the release under test (recovery)"
    )
    run_parser.add_argument("--upgrade-base-image", help="installed previous release")
    run_parser.add_argument(
        "--upgrade-repo", help="package specification apt-get should install"
    )
    run_parser.add_argument("--upgrade-from-version", default="3.5.0")
    run_parser.add_argument(
        "--interrupt-deadline",
        type=float,
        default=90.0,
        help="how long to wait for a restore to be observably in flight before "
        "giving up; the power cut is aimed at that window, never timed",
    )
    run_parser.add_argument(
        "--record",
        action="store_true",
        help="on PASS, record the result into the release acceptance manifest",
    )
    run_parser.set_defaults(func=command_run)

    list_parser = sub.add_parser("list", help="list the cases this harness runs")
    list_parser.set_defaults(func=command_list)

    status_parser = sub.add_parser("status", help="show the run ledger")
    status_parser.set_defaults(func=command_status)

    verify_parser = sub.add_parser(
        "verify", help="re-verify receipts, evidence bytes and the ledger chain"
    )
    verify_parser.add_argument("--run-id")
    verify_parser.add_argument("--all", action="store_true")
    verify_parser.set_defaults(func=command_verify)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
