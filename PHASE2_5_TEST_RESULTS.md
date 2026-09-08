# Phase 2.5 Test Results

*Literal output. Every number here was produced by a command, not by counting
in prose.*

## Totals

| suite | baseline (`fb9b32a`) | now | delta |
|---|---|---|---|
| `packages/shadowfetch-missions` | 252 | **404** | +152 |
| `tools/tests` (release gate) | 143 | **162** | +19 |
| `packages/shadowfetch-fireline` | 11 | **13** | +2 |
| conformance assertions **per provider** | 23 | **33** | +10 |
| providers the conformance suite runs against | 3 | **4** | +1 |

```
$ make test
Ran 404 tests in 23.820s   OK (skipped=4)      # missions
Ran  50 tests in  1.269s   OK
Ran  98 tests in  1.115s   OK
Ran  26 tests in  0.443s   OK
Ran  36 tests in  1.316s   OK
Ran  49 tests in  0.238s   OK
Ran  26 tests in  2.717s   OK
Ran  13 tests in  0.036s   OK                  # fireline
Ran 162 tests in  0.526s   OK                  # release gate

$ make source-gate
PASS: provider manifests validated: codex, offline-media
SOURCE_GATE_PASSED
```

### The four skips, each with its reason

| test | reason |
|---|---|
| `Conformance_offline_media.test_readiness_reports_missing_authentication` | provider has no account to authenticate against |
| `Conformance_localmodel.test_readiness_reports_missing_authentication` | same |
| `Conformance_conformance_echo.test_a_program_the_manifest_does_not_declare_is_refused` | this provider genuinely declares the substitute (`/usr/bin/true`) |
| `Conformance_localmodel.test_a_program_the_manifest_does_not_declare_is_refused` | same |

No skip hides a failure, and none is a capability this host lacks.

## Fresh-checkout health — the measurement that mattered

`.gitignore` carried `*.log`, and two conformance fixtures are `.log` files, so
`test_provider_conformance.py` died at import in **any clone**. The suite passed
only in a working tree containing untracked files. Measured across three
commits in fresh `git worktree` checkouts:

```
fb9b32a: Ran 132 tests  FAILED (errors=1)   Phase 2 final
4351129: Ran 184 tests  FAILED (errors=1)   mid-Phase-2.5, same cause
5c16039: Ran 358 tests  OK (skipped=3)      after the .gitignore exception
```

This is why the mid-phase commit `4351129` is red in isolation. It is the same
pre-existing defect, not something that commit introduced, and `5c16039` fixes
it.

## Adversarial pass — 15 attacks, 15 refused

Executed against the shipped code. Nothing reasoned about.

```
ATTACK 01  a schema-valid manifest is dropped into the discovery directory
  EXPECTED  not a provider; the error names the policy
  OBSERVED  ids=['codex', 'offline-media']
            provider 'helpful-agent' is not in the approved-provider policy
            (…/policy/approved.json). A schema-valid manifest is not sufficient
            to become a provider.
  VERDICT   PASS

ATTACK 02  an approved manifest is edited after approval
  OBSERVED  codex active=False
            provider 'codex': manifest digest 07852ccdc2ab1e42... does not match
            the approved 9508a119bea46a32.... The manifest changed after it was
            approved; re-review it and re-seal the policy.
  VERDICT   PASS

ATTACK 03  a capability is added beyond the ceiling, WITH a matching digest
  OBSERVED  provider 'codex' requests capabilities it was not approved for:
            media_export
  VERDICT   PASS   (refused outright, not silently narrowed)

ATTACK 04  a credential identity is added beyond the ceiling
  OBSERVED  provider 'codex' requests credential_ids it was not approved for:
            ANTHROPIC_API_KEY
  VERDICT   PASS

ATTACK 05  an offline provider re-declares itself networked
  OBSERVED  provider 'offline-media' requests egress_allowlist it was not
            approved for: evil.example
  VERDICT   PASS

ATTACK 06  the approved-provider policy is deleted
  OBSERVED  ids=[]
            approved-provider policy is unavailable at …: [Errno 2] No such file
            or directory. Mission Control will not activate any provider
            without one.
  VERDICT   PASS   (zero providers, not all providers)

ATTACK 07  the policy file is corrupted
  OBSERVED  ids=[]
            approved-provider policy is not valid JSON: …: Expecting property
            name enclosed in double quotes: line 1 column 3 (char 2)
  VERDICT   PASS

ATTACK 08  a policy declares a schema version this build does not know
  OBSERVED  ids=[]
            …/approved.json: unsupported policy schema_version 99
  VERDICT   PASS

ATTACK 09  a second file claims an already-approved provider id
  OBSERVED  ids=['codex', 'offline-media']
            aaa-codex.json: manifest filename must match its id 'codex', so a
            provider cannot be shadowed by a second file claiming the same id
  VERDICT   PASS

ATTACK 10  SHADOWFETCH_PROVIDER_MANIFESTS points discovery at an attacker's dir
  OBSERVED  root = …/data/usr/share/shadowfetch/providers
            ignoring SHADOWFETCH_PROVIDER_MANIFESTS: the provider discovery root
            is not environment-selectable in production; pass root= to
            ProviderRegistry for tests
  VERDICT   PASS

ATTACK 11  the program sits in a world-writable, non-sticky directory
  OBSERVED  tier=untrusted
            reason=…/worldwritable is world-writable, so the program can be
            substituted by someone other than root or the invoking user
            Provider executable classifies as untrusted: … Its manifest declares
            executable trust 'user-runtime', which accepts distro-managed,
            user-managed. Refusing to execute it.
  VERDICT   PASS

ATTACK 12  the program is owned by a uid other than the one running the mission
  OBSERVED  as uid 2000: tier=untrusted
            reason=…/otheruid/agent is owned by uid 1000, so the program can be
            substituted by someone other than root or the invoking user
  VERDICT   PASS
  NOTE      Executed by asking the classifier the question a DIFFERENT user
            would ask, rather than by creating a root-owned file. No privilege
            was acquired to run this phase.

ATTACK 13  a manifest declares developer executable trust, approved only system
  OBSERVED  provider 'offline-media' declares executable trust 'developer',
            approved only for 'system'
  VERDICT   PASS

ATTACK 14  an adapter hands back a sandbox wider than its manifest declared
  OBSERVED  verify_invocation: offline-media: requested network 'allowlist' but
                               declares none
            narrow():          An adapter may not add network access it did not
                               declare
  VERDICT   PASS

ATTACK 15  an adapter returns a program outside its manifest's declaration
  OBSERVED  offline-media: …/smuggled/ffmpeg is not a program this manifest
            declares. Declared: /usr/bin/ffmpeg
  VERDICT   PASS

ADVERSARIAL PASS: 15 of 15 attacks refused
```

### Attack 15 found a real defect, and nearly hid it

Its first form used a program in `/tmp`, which was refused — **on its trust
tier**, because `/tmp` is `user-managed` and `offline-media` declares `system`.
That looked like a pass. Retrying with a program of the *right* tier showed what
the check actually did:

```
declared executable: {'kind': 'absolute', 'path': '/usr/bin/ffmpeg', ...}
RESULT: NOT REFUSED -- /usr/bin/true accepted for a provider declaring
                       /usr/bin/ffmpeg
CODEX : NOT REFUSED -- /usr/bin/true accepted for a candidates declaration
```

Fixed in `43372e4`, with a per-provider conformance regression test.

## Sandbox enforcement — measured against the real Firebreak

Real sandboxed processes in throwaway `/tmp` workspaces.

```
net none      -> "NETWORK BLOCKED: OSError [Errno 101] Network is unreachable"
net allow     -> "NETWORK REACHABLE"
read grant    -> granted readable: True | ungranted exists: False
                 grant write refused: OSError Read-only file system
processes 8   -> "REFUSED after 5 threads: RuntimeError can't start new thread"
cpu_seconds 2 -> exit 152 (128+SIGXCPU), wall 2.07s
credentials   -> OPENAI_API_KEY PRESENT / ANTHROPIC_API_KEY absent /
                 GITHUB_TOKEN absent
                 undeclared name -> "Credential grant must name a supported
                 provider environment variable", exit 1

workspace_mode read-only
  BEFORE  "WORKSPACE WRITABLE: True"; the file appeared on the host
  AFTER   "WORKSPACE WRITE REFUSED OSError Read-only file system";
          the file did not appear on the host
  and the default posture still writes (asserted separately, because
  enforcing read-only must not make every workspace read-only)

memory_mb 256, allocate+touch 4096 MiB
  BEFORE  "ALLOCATED AND TOUCHED 4096 MiB UNDER A 256 MiB CAP", exit 0
          MemoryMax=268435456  MemorySwapMax=infinity
  AFTER   stopped; the probe never printed its allocation
```

## Transport defects — measured before and after

```
1. redactor never flushed on an abnormal exit
   records=    10  emitted~     380B  log=       0B  lost=    380B
   records=   200  emitted~    7600B  log=       0B  lost=   7600B
   records=  2000  emitted~   76000B  log=   57392B  lost=  18608B
   deadline path: log 0 bytes of ~7600 emitted
   AFTER: every record survives, and the log ends at a record boundary

2. output cap kept the head; a terminal event is last
   child exit code               : 0
   bytes the provider emitted    : 4560074
   bytes retained in the log     : 2000000
   'generation.done' in the log  : False
   turn_succeeded(events)        : False        <- exit-0 success reported failed
   AFTER: marked tail retained; generation.done present; turn_succeeded True

3. per-block utf-8 decode
   euro sign written by the child : 1
   euro signs in the retained log : 0
   U+FFFD in the retained log     : 3
   turn_succeeded                 : True        <- silently wrong text
   AFTER: 0 U+FFFD, the euro present in the log
```

## Interface generality — what the streaming provider proved

| characteristic | verdict |
|---|---|
| incremental token chunks | expressible; the adapter accumulates deltas into one MESSAGE |
| no explicit terminal event | expressible; the adapter synthesises, as offline-media does |
| explicit session start / reuse | expressible; a session is a native event the adapter remembers |
| cancellation mid-generation | expressible; the process group is the mechanism |
| server crash / truncated stream | expressible; exactly one invocation, no retry |
| provider heartbeat | vocabulary yes, **timing no** — `parse_stream` runs once after exit |
| stalled stream | coped with, bounded only by the mission deadline (no idle timeout) |
| provider reconnect | not expressible, correctly — it belongs inside a bridge process |

**No new `AgentEvent` type was needed.** Fourteen distinct native event names
reduce to the existing six with nothing dropped and nothing mislabelled.

## LIVE_CODEX_INTEGRATION = NOT VERIFIED

**REASON = provider authentication unavailable to Mission Control on this host.**

The Codex CLI is installed
(`~/.nvm/versions/node/v22.22.3/bin/codex`, a `user-managed` program that its
manifest's `user-runtime` declaration accepts). Mission Control readiness
reports:

```
codex available=False | Run shadowfetch-mission-account login for a dedicated
account, or save a user-owned 0600 CODEX_API_KEY environment file and restart
the idle worker. Credential presence does not verify authentication.
```

A personal `~/.codex/auth.json` exists; it is the user's own and is deliberately
**not** the dedicated Mission Control account the mission path requires. This
phase does not alter credentials, so no live cloud turn was executed and none is
claimed. Every Codex path is covered by unit tests and recorded fixture streams
only.

`account_mount` enforcement is likewise **source-read only** — demonstrating it
needs a signed-in account this phase must not touch.
