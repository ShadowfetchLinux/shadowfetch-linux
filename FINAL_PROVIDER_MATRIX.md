# FINAL_PROVIDER_MATRIX

Four providers ship in 4.0.0. Each is a manifest, an adapter, a sealed policy
entry and a conformance case; none of them is a branch in the engine. That is
the property Phase 2 bought, and this document is the check on it: if adding a
provider had cost an edit to `sf_missions.py`, `sf_policy.py` or Firebreak, it
would say so here.

## The four

| id | what it is | capabilities | network | credentials | executable trust |
| --- | --- | --- | --- | --- | --- |
| `codex` | OpenAI Codex CLI, cloud | code_change, sourced_report | `allowlist` — api.openai.com, chatgpt.com, auth.openai.com | `CODEX_API_KEY` | user-runtime |
| `claude` | Claude Code CLI, cloud | code_change, sourced_report | `allowlist` — api.anthropic.com | `ANTHROPIC_API_KEY` | user-runtime |
| `localmodel` | on-device inference over one unix socket | code_change, sourced_report | `none`, and it stays none | *none* | system |
| `offline-media` | deterministic media export | media_export | `none` | *none* | system |

A fifth, `conformance-echo`, exists only under `tests/fixtures/` and is the
proof that a third-party provider needs no gate edit. It does not ship.

## What each is APPROVED for, and what approval means

`packages/shadowfetch-missions/data/usr/share/shadowfetch/provider-policy/approved.json`
pins each provider by manifest digest. A schema-valid manifest is not sufficient
to become a provider: `ApprovedPolicy.approve()` refuses an id that is not in
the policy, a digest that does not match, a package or interface version that
disagrees, any capability / credential id / egress host the entry does not
permit, and any executable trust tier above the approved one. Effective
privilege is the INTERSECTION of what the manifest requests and what the policy
permits, never the union, and an excess request is refused outright rather than
clamped — a provider asking for more than it may have is either mis-packaged or
hostile, and silently narrowing it would hide both.

Re-sealing is `tools/providers/seal_policy.py`, which prints the privilege diff
and requires `--yes`. It is deliberately not called by make, by a gate or by CI.

**A defect found while sealing these two:** the tool could not seal a NEW
provider at all. `entry_for()` emitted the pinned privileges but never
`executable_trust`, which it could only carry over from a previous entry —
and `approve()` refuses outright any entry that lacks it. A brand-new provider
was therefore sealed into a policy that would refuse it at runtime, with a
message blaming the policy author rather than the tool. `executable_trust` is
now one of the PINNED fields, read from `executable.trust`, and it appears in
the printed diff like every other privilege.

## Conformance

Every registered provider runs the SAME assertions, generated from one profile
type (`provider_conformance.ProviderCase` / `conformance_class`): capability
acceptance and refusal, stream parsing across success / failure / interleaved /
cancelled transcripts, readiness with the binary present and absent, readiness
with authentication present and absent, executable tier classification against
the manifest's declared trust, and the interface-generality checks (an adapter
must not name another provider; the engine must not compare against a provider
id).

`codex`, `offline-media` and `conformance-echo` are cased in
`tests/test_provider_conformance.py`. `claude` and `localmodel` are cased in
their own modules, because each needs fixtures the shared file has no business
carrying — a stream transcript per provider, a unix socket, a candidate list.
That is not an exemption: `PROFILES_ELSEWHERE` maps each to an importable
profile, and the shared suite IMPORTS it and checks `profile.provider_id`.
Grepping for a name would have let a profile that was deleted, renamed or built
for a different provider pass.

| provider | conformance case | result |
| --- | --- | --- |
| `codex` | test_provider_conformance.py | pass |
| `offline-media` | test_provider_conformance.py | pass |
| `conformance-echo` | test_provider_conformance.py | pass |
| `claude` | test_provider_claude.py + claude_conformance.CLAUDE_PROFILE | pass |
| `localmodel` | test_provider_localmodel_shipped.py + LOCALMODEL_PROFILE | pass |

## What is NOT proven, per provider

**`claude` — LIVE INTEGRATION NOT VERIFIED.** No Anthropic credential exists on
the build host (`claude auth status` reports `loggedIn: false`), so no real
authenticated turn was run. Its CLI interface was verified against the real
binary (2.1.178): `--print --output-format stream-json` is refused without
`--verbose`; `result.subtype` was observed as `"success"` on a run whose
`is_error` was true, so the parser trusts `is_error` and never `subtype`;
`--bare` takes authentication strictly from the declared identity and reads no
host config, hooks, plugins or keychain. Four of its five stream fixtures are
SYNTHETIC, written to the schema of real captures; only
`claude_unauthenticated.jsonl` is a recording. Not verified: that a real turn
edits files, that tool events appear in a real authenticated stream in the
shape the fixtures assume, or that usage figures from a real turn parse.

Two facts about it came only from running its invocation inside the real
sandbox and could not have come from a fixture. The payload is uid 0 in bwrap's
unshared user namespace and the CLI refuses its permission-bypass mode under
root, exiting before writing one stream record — every mission would have failed
with an unparseable log. And `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`
measurably cuts egress: without it every run contacted api.anthropic.com AND
one Google-hosted endpoint (2/2 runs); with it, only api.anthropic.com (3/3).
That measurement is why `egress_allowlist` declares exactly one host.

**`localmodel` — runs only where a service answers.** Its bridge now ships from
`data/usr/libexec/shadowfetch/local-model-bridge` (it was written under
`tests/fixtures/` by a stage that was not permitted to add a packaged file, and
was MOVED rather than copied, so the file the tests execute and the file a
person gets are the same file). It reaches the model over ONE unix socket
inside the single directory named in `read_grants`, which Firebreak bind-mounts
read-only. That works from a namespace with no interfaces because AF_UNIX is
addressed by filesystem path rather than by network namespace — measured on
this kernel: with the directory bound, connect() succeeds and bytes flow; with
nothing bound, `FileNotFoundError`; TCP to the host's 127.0.0.1 is refused
whether or not the directory is bound, so the grant buys the socket and nothing
else. Where no service answers, readiness reports unavailable with a reason and
`capabilities()["local_ai"]` reads `installed-unavailable`.

**Both cloud providers — the credential reaches the sandbox.** Firebreak
resolves the declared identities from the worker's environment and passes the
VALUES with `bwrap --setenv`. An agent that runs a shell inside the sandbox can
read its own environment. There is no credential broker. This is stated in the
`claude` manifest's own notes and in the approved policy's `approved_note`,
because a provider whose approval record omitted it would be approved on a
false description.

## Choosing between providers

Three providers now serve `code_change`. The engine REFUSES to choose: a
mission that names none gets *"More than one provider can do this; name one
with --provider"*. That is deliberate and it is tested — silently picking one
would be a policy invented in code. Model selection is likewise the provider's
decision: the engine bounds only the STRING (at most 100 characters of
`[A-Za-z0-9._:@/-]`, and never a leading dash, because a model name becomes an
argv element and `--dangerous` is a flag), and which names exist is answered by
`accepts()` in each adapter — `claude` against an alias list and a
`claude-<name>` pattern, `codex` by refusing model selection in its own words,
`offline-media` by saying it runs no model at all.

## Not shipped, and why

**Grok Bot — UNSUPPORTED, permanently and architecturally.** It is a desktop
cloud teammate with no supported mission CLI adapter. It is OFFERED DURING
INSTALLATION as a desktop application and `capabilities()["grok_bot"]` says
exactly that: *"Launch the official desktop cloud teammate separately; it has
no supported mission CLI adapter."* Nothing named `grok` ships as a provider.

**Grok Build CLI — DEFERRED.** A real headless interface is documented, but no
evidence exists on this machine from which to write an honest adapter, and one
unresolved security question blocks approval.

**Cursor — DEFERRED, not unsupported.** Cursor Agent ships a real
non-interactive CLI artifact. It is not installed here, there is no account
here, and two required grants live in files outside the stage's territory —
so nothing about it could be verified. Deferred is the honest word: there is no
evidence the product is unsuitable, only that nothing about it can be checked
from this machine.
