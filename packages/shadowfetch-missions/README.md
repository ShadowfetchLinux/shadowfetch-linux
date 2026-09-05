# Shadowfetch Mission Control 4.0

Mission Control runs user-scoped, durable tasks and keeps results awaiting review.
It uses Python's standard library, SQLite/WAL and the installed Firebreak boundary.
It neither publishes code nor sends email. It has no network listener or telemetry.

## Three executable workflows

- **Code:** the user's selected Buzz native model proposes structured file edits,
  then the controller validates every path and runs the exact user-selected test
  command in Firebreak. Failed tests feed at most three repair iterations. Existing
  test files and selected validation scripts cannot be modified to make a run pass.
  The optional Codex adapter uses documented `codex exec --sandbox workspace-write
  --json --skip-git-repo-check`; only its designated `CODEX_API_KEY` is granted,
  with child command credential exclusion. User home authentication/configuration
  folders are never copied. Codex requires explicit network access.
- **Report:** read selected UTF-8 documents, ask the selected Buzz model for a report,
  validate every returned `[S1:L2-L5]` source range, then publish Markdown and a
  source register with SHA-256 hashes. Citation range checks cannot establish that
  the prose accurately represents a source: that remains part of human review.
- **Media:** export selected video as H.264/AAC MP4 or audio as 48 kHz PCM WAV using
  FFmpeg; strip metadata; decode the complete export to verify it; publish hashes,
  byte sizes and an export manifest. This workflow requires no model or network.

## Genuine native compute

The Buzz mesh router at `127.0.0.1:9337` can route to other community computers.
A loopback URL does **not** prove that inference stays on the current computer.
`sf_local_compute.py` therefore reads the pinned vendor's local management API,
`127.0.0.1:3131/api/runtime/processes`, and accepts only ready native model servers.
It validates the native executable identity, same-user PID, process start time,
and ownership of the advertised loopback listening socket through Linux `/proc`.
It sends prompts directly to that native server's port and revalidates the process
before reporting success. No model process is started or downloaded by this code.
Buzz 0.5.17 embeds native Skippy inside its desktop executable. This route requires
the exact root-owned `/usr/bin/buzz-desktop`, pinned installed package version,
and executable contents matching its protected dpkg manifest; the receipt records
the binary SHA-256. Copied executables with the same name do not qualify. Any
distributed stage/topology deployment, or unavailable stage inventory, refuses
offline selection; stage inventory is checked again after inference.
Every direct native request also sets the vendor's `mesh_hooks: false` switch,
disabling Skippy's automatic peer-consultation hooks even when the desktop has
community peers connected.
Pinned Skippy requests use `reasoning_effort: "none"` and
`chat_template_kwargs: {"enable_thinking": false}` so bounded missions receive
final output instead of exhausting their budget on hidden intermediate reasoning.
The receipt records this generation mode.

With `--network none`, absence of a verified native model fails closed before any
prompt is sent. With `--network allow`, native compute is still preferred, but a
selected model available only through the Buzz community router may be used. The
receipt records the selected native proof or community routing. HTTP redirects and
proxy environment variables cannot change these destinations.

Source contract: Buzz `desktop-v0.5.17` pins MeshLLM `v0.75.1`, commit
`3295c902d4c4f859aaadf9240042ffdaf06dd07e`. Its public runtime process payload is
specified in `crates/mesh-llm-host-runtime/src/api/state.rs` and verified by
`api/tests/runtime_data.rs`; `api/status.rs` constructs it from local processes.
The separate `shadowfetch-model-check` desktop helper uses this same module.

## Queue and recovery

The systemd user service starts with the desktop session. The CLI can also run
`shadowfetch-missions worker --once` or `shadowfetch-missions run ID` explicitly.
An exclusive execution lock serializes heavy missions. SQLite controllers, logs,
diffs and receipts live under `~/.local/state/shadowfetch/missions`, outside every
writable workspace. Queue mutation is transactional and supports concurrent UI
clients. Each mission has a bounded wall time (default 900 seconds, maximum 7200)
and a maximum of three explicit attempts.

State progression is `queued → running → waiting-review → completed`. Errors use
`failed`; cancellation uses `cancelled`; successful restoration uses `undone`.
A restarted worker marks interrupted executions failed and asks for inspection.
It never automatically replays an interrupted code edit or external network action.
An explicit Retry retains the original checkpoint. Previously published reports
and individual media exports are resumed only when their recorded input and output
hashes match. Changed report sources or edited output refuse retry before inference;
start a new mission to preserve those edits as a fresh recovery baseline.
Report retries retain the original inference time, attempt, model, usage, response
hash and process proof. Receipts explicitly mark that evidence as historical and
reused; resuming a published report performs no new inference or process check.
If original provenance is unavailable, retry fails with a new-mission instruction.

Accept marks successful work reviewed. Undo restores the original workspace using
its checkpoint, after proving no newer mission or manual file change intervened.
Review waits up to 10 seconds to acquire the execution lock, then rechecks the
mission state. If the lock remains busy, it reports that no review was applied;
the user can submit a new request. This limit covers lock acquisition only, not
an in-progress restoration. Execution publishes its final state and event in one
SQLite transaction after persisting the receipt, so readiness includes that event.
The checkpoint engine takes a safety snapshot before restoring. If an interrupted
run has no final file index, use the separately documented checkpoint CLI after
inspecting the workspace. Recovery affects workspace files; network effects are
outside this boundary.

Firebreak uses a private home and mount namespace; only the chosen direct folder
under `~/Workspaces` is writable. Standalone Firebreak uses a dedicated systemd
user scope with a task count, memory and CPU quota; each process also has CPU-time,
address-space and file limits. The mission worker has its own 4 GiB/128-task systemd
budget. A desktop without a working user manager fails closed on code/media work.
The native model server is owned by Buzz; its memory is reported separately and
is not included in the mission sandbox's 3 GiB address-space limit.

## CLI integration

All commands accept the global `--json` flag before their subcommand. Success
returns a JSON object (or an array for list/events); errors return `{"error":"..."}`
and a nonzero exit status.

```sh
shadowfetch-missions --json capabilities
shadowfetch-missions --json list
shadowfetch-missions --json create --kind report --workspace research \
  --title 'Project brief' --prompt 'Summarize the evidence and open questions' \
  --runtime local --model 'served-native-model' --network none --input notes.md
shadowfetch-missions --json create --kind code --workspace app \
  --title 'Fix addition' --prompt 'Fix add without changing the tests' \
  --runtime local --model 'served-native-model' --network none \
  --input app.py --test-json '["python3","-m","unittest","discover"]'
shadowfetch-missions --json show ID
shadowfetch-missions --json events ID
shadowfetch-missions --json diff ID
shadowfetch-missions --json run ID
shadowfetch-missions --json cancel ID
shadowfetch-missions --json retry ID
shadowfetch-missions --json review ID --decision accept
shadowfetch-missions --json review ID --decision undo
```

The workspace must already exist as a direct, non-hidden folder in Workbench.
Inputs are relative paths within that workspace. No symlink input or edit, path
traversal, secret/config folder or executable shell text from a model is accepted.
The only shell commands are explicit user-selected tests or the fixed FFmpeg /
Codex adapter commands. Shared compute receives the selected file context only.

## Verification

`tests/test_missions.py` covers concurrent queue creation, real process cancellation,
checkpoint/diff/undo, retry bounds, interrupted execution, scoped edits, and real
Python validation/repair with explicitly mocked model responses.
`tests/test_local_compute.py` covers local process/socket proof, native preference,
mesh refusal, redirect refusal and proxy isolation. `tests/test_review_lock.py`
uses real process locks and SQLite transactions to cover review contention,
bounded refusal, state revalidation, final publication and rollback. These unit fixtures do not
constitute a live model verification. Release QA additionally runs real Linux
Firebreak probes, real native model work, actual media missions and sustained load.
