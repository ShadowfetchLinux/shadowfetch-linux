# Mission Control 4.0

Mission Control keeps a durable user queue, workspace checkpoints, receipts and
results awaiting review. Code and reports use the existing Codex cloud CLI.
Media runs offline with FFmpeg. Local AI and shared inference are deferred;
Grok Bot launches separately and has no supported Mission Control adapter.

## Providers and permission

- Code and report: `--runtime codex --network allow`. The selected workspace is
  the boundary; cloud access requires explicit permission. Codex runs through
  Firebreak with a private home and no copied user login/configuration folders.
  Code uses the existing workspace-write adapter and runs the exact supplied test
  command afterward. Changing pre-existing tests or their runner refuses success,
  and so does adding a new test or validation-configuration file. Retries compare
  against the guard baseline recorded with the first attempt's checkpoint, never
  against the workspace an earlier attempt left behind.
  Report uses the same CLI in read-only mode, receives selected UTF-8 documents
  through stdin, validates every returned source-line citation, and publishes
  Markdown plus a source register containing SHA-256 hashes. Citation validation
  does not prove that prose accurately represents a source; review is required.
- Media: `--runtime offline --network none`. Selected video exports as H.264/AAC
  MP4; audio exports as 48 kHz PCM WAV. FFmpeg strips metadata and fully decodes the
  output before hashes, byte sizes and the export manifest are published.

Runtime defaults derive from kind. Model selection is unavailable. Unsupported
old-provider queued tasks fail clearly without migrating their prompts to cloud.
Existing historical receipts and outputs remain available for review and Undo.

## Configure the existing Codex adapter

Install Codex using the supported Coding Agents setup first. Mission workers use
a dedicated account login or API authentication. Run
`shadowfetch-mission-account login` and complete the device sign-in, or use the
Sign in button in the new-mission dialog. Check it with
`shadowfetch-mission-account status`; sign out with `shadowfetch-mission-account logout`.
This profile lives in private `~/.local/state/shadowfetch/mission-account` storage.
Only approved cloud missions receive it, and refreshed credentials persist. Your
normal Codex profile is not imported. Account operations wait for an idle account;
a busy operation fails clearly. `CODEX_API_KEY` takes precedence when configured,
with `OPENAI_API_KEY` as an existing environment fallback.

The systemd user service loads this optional per-user file:
`~/.config/shadowfetch/missions/codex.env`. Create its directory with mode 0700 and
its file with mode 0600, owned by the logged-in user. Use a text editor to enter
one assignment, `CODEX_API_KEY=your-key`; do not put a real key into shell history,
screenshots, logs or workspace files. The actual file is never shipped.

After saving, wait until the queue is idle, then run:

```sh
systemctl --user daemon-reload
systemctl --user restart shadowfetch-missions.service
```

A restart interrupts active work, so do this before submitting a task. The CLI
capability response separately reports current-process key presence and private
worker-file presence. Neither proves that a running worker reloaded the file or
that the credential is valid. A completed real task is the authentication check.
Only the designated key is granted to Codex; its child shell environment excludes
both API-key names. No host authentication directory is exposed to the sandbox.

## Durable execution and recovery

SQLite/WAL state, logs, the execution lock and receipts live outside writable
workspaces under `~/.local/state/shadowfetch/missions`. Execution is serialized.
Default task time is 900 seconds (maximum 7200), with at most three explicit attempts.
The worker has a 4 GiB/128-task systemd budget; Firebreak constrains each task's
CPU time, address space and process count. These limits do not isolate tasks from
all external disk pressure or prove full desktop responsiveness under saturation.

State progresses `queued → running → waiting-review → completed`. Errors become
`failed`; cancellation becomes `cancelled`; successful restoration becomes
`undone`. A restarted worker records interrupted work as failed and never replays
it automatically. Explicit retries preserve checkpoints; previously published
reports/media resume only when their source/output hashes still match. Report
retries mark original CLI provenance as historical and perform no new cloud turn.

Accept marks reviewed work complete. Undo checks for newer edits before restoring
the workspace. Review waits at most 10 seconds to acquire the execution lock and
revalidates state afterward. Busy refusal applies no review mutation. Publication
commits final state and event together after persisting the receipt. Recovery
covers workspace files; external network effects cannot be undone.

`list` prints a JSON array of at most 1,000 records per page. A short page is
announced on stderr with the offset to continue from; `--limit 0` returns the
complete queue. Every attempt writes `changes.diff` beside a structured
`changes.json` of typed change rows with escaped paths, and a rendering cut at
its byte budget ends with an explicit truncation trailer instead of stopping.

```sh
shadowfetch-missions --json capabilities
shadowfetch-missions --json create --kind report --workspace research \
  --title 'Project brief' --prompt 'Summarize the selected evidence' \
  --runtime codex --network allow --input notes.md
shadowfetch-missions --json create --kind code --workspace app \
  --title 'Fix addition' --prompt 'Fix add without changing tests' \
  --runtime codex --network allow --test-json '["python3","-m","unittest","discover"]'
shadowfetch-missions --json create --kind media --workspace studio \
  --title 'Audio export' --prompt 'Export the selected audio' \
  --runtime offline --network none --input source.wav
shadowfetch-missions --json list
shadowfetch-missions --json list --limit 200 --offset 200
shadowfetch-missions --json show ID
shadowfetch-missions --json review ID --decision accept
shadowfetch-missions --json review ID --decision undo
```

Workspaces must be direct non-hidden folders inside `~/Workspaces`. Selected
inputs cannot traverse paths, symlinks, or private configuration folders. Tests
cover real queue/lock/recovery/cancellation behavior and clearly labeled Codex
response fixtures. Fixture results are not live cloud-integration evidence.
