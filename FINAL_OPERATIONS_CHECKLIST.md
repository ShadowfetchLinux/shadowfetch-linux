# FINAL_OPERATIONS_CHECKLIST

Everything an operator has to do, and the specific ways each step has gone
wrong before. The traps are here because each one cost real time or real damage;
none of them is hypothetical.

## Before anything: where the work lives

Branch `release/4.0.0` in `~/projects/shadowfetch-4.0.0` on the Linux publisher.
There is one authorized publishing tree and `publish_release_4_0_0.py` refuses
to run anywhere else (`sys.platform != "linux" or ROOT != PUBLISHER or
getpass.getuser() != "rtx5060ti"`).

## Running the tests

```sh
make test            # every package suite, then `make attacks`
make attacks         # the six adversarial suites on their own
```

`make test` takes about ten minutes and RUNS THE ATTACKS. The attacks are not a
separate quality tier: they assert what the system REFUSES, which a test written
against an implementation structurally cannot notice.

**Trap: do not edit the tree while a verification runs.** This was done twice in
this program and both results were garbage — `TEST=2` with attack failures that
did not reproduce on the settled tree. If you started a run and then changed a
file, throw the result away. There is no partial credit.

**Trap: background a long run with `setsid`.** A plain `&` over ssh dies with
the session:

```sh
setsid nohup make test </dev/null >/tmp/test.log 2>&1 &
```

**Trap: `pkill -f "make test"` from an ssh command line matches the ssh command
itself** and kills your own session (exit 255). Match on something narrower.

## The gates

```sh
python3 tools/release/source_gate.py     # runs make test, plus source checks
python3 tools/release/package_gate.py    # builds and inspects the debs
python3 tools/release/iso_gate.py        # builds and boots the image
python3 tools/drift_gate.py              # one authority per fact
python3 tools/release/acceptance.py --version 4.0.0 verify
```

`drift_gate` exits non-zero on DRIFT (a copy disagrees with its source) and
prints BLOCKED separately (a real duplication whose remedy is outside one
stage's territory). **A BLOCKED finding is an OBSERVATION with a named remedy,
not an enforced control** — read the printed report, never the exit code alone.

**Trap: `package_gate` fails on files git still tracks that the tree deleted.**
It reads payload from the index, so a rename or deletion that is unstaged reads
as "a payload file no package ships". Stage the deletion.

## Provider policy

Adding or changing a provider manifest requires re-sealing the pin:

```sh
python3 tools/providers/seal_policy.py          # dry run: prints the privilege diff
python3 tools/providers/seal_policy.py --yes    # writes it
```

It is deliberately NOT called by make, by a gate or by CI. A tool that silently
re-digests whatever manifests happen to be present turns the pin into
decoration. Read the printed diff: each line is a privilege a provider will be
permitted to request.

**Trap: the `approved_note` is not decoration either.** Write what was actually
reviewed and what was accepted as a known cost. The two notes added this phase
name the credential that reaches the sandbox and the single egress destination a
real run was observed to contact.

## Credentials

Per-provider environment files live in `~/.config/shadowfetch/missions/*.env`,
mode 0600. The worker reads the DIRECTORY and takes only the identities the
provider registry declares, so a stray file cannot inject `PATH` or
`LD_PRELOAD`; a value already exported wins over a file.

**Trap, now fixed, worth knowing:** the systemd unit used to name ONE file
(`codex.env`), so a second provider's key reached nothing at all while its
readiness reported it present. If you add a provider, you do not edit the unit.

## Publishing

```sh
python3 tools/publish_release_4_0_0.py            # plan only
python3 tools/publish_release_4_0_0.py --apply    # uploads
```

Order is a control: the signed APT `InRelease` is the last of the objects, the
ISO's bytes are then streamed back and compared, and only after that is
`releases/CURRENT.json` written. Nothing that DIRECTS a reader is written before
the thing it directs them to is present and proven. `--published` defaults to
the ISO's mtime so re-running rewrites nothing.

## The compliance trap, which is not this project's but shares a machine

`shadowfetch-ios-apps.pages.dev` hosts the App Store privacy and support URLs
for ~530 live apps. **Cloudflare Pages deploys REPLACE the whole project
directory.** Deploying one app's `Website/` folder there deletes every other
app's compliance page; it has happened twice, and the second time all 530 URLs
were 404 at origin for about 42 hours behind edge cache. Never run
`wrangler pages deploy … --project-name shadowfetch-ios-apps` from anything but
the repair job:

```sh
cd ~/shadowfetchcrew/compliance-watch && ./repair.sh
```

That verifies all managed URLs and redeploys the COMPLETE set. A LaunchAgent
runs it every six hours; `compliance-watch/last-run.json` is the last result.
The Mac's `wrangler`/`npx` are intercepted and refuse a partial Pages deploy
from any other directory.

## When something refuses

The vocabulary is deliberate and each word means a different thing. A refusal
that says `not_enforced` is telling you a control does not exist, not that it
failed. A `partial` is a control with a stated residual. `observed` means a fact
was recorded, not verified. `not_representable` means the system has no way to
express the thing at all. If a message uses one of these words, the answer is in
`docs/SECURITY_CLAIMS_MATRIX.md` under the matching row.
