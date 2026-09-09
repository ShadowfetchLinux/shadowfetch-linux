"""Stage L determination: is there a Grok provider Shadowfetch can honestly ship?

VERDICT
-------
  Grok Bot (native desktop, 0.43.0)     UNSUPPORTED -- no programmatic interface
  Grok Build CLI (`grok`, pinned 1.0.5) DEFERRED    -- interface exists, evidence does not

This file adds NO product code and NO provider. It records the determination as
executable assertions, so that the day someone disagrees they have to change a
test that says why, rather than quietly adding a manifest.

WHY GROK BOT IS UNSUPPORTED (permanent, architectural -- not a missing flag)
---------------------------------------------------------------------------
Observed, on this repository and in the 4.0.0 QA evidence captured from an
actually installed copy (work/qa-4.0.0/.../fire/native-grok-integrity-process.json,
ISO e9859800..., boot aafbc627..., installed_version 0.43.0):

  * Its whole process surface is Chromium. The recorded process table is one
    `main`, three `zygote`, a `gpu-process`, a `broker`, a `utility` and a
    `renderer`, all `/opt/Grok Bot/grok-bot`. That is an Electron GUI, and the
    evidence file says so itself: "Vendor process titles present a single
    NUL-terminated command line with space-separated Chromium switches."
  * Its only non-GUI entry point is a URI handler (`grok-bot.desktop`, scheme
    `grokbot`) whose purpose is receiving the vendor's browser sign-in callback.
    A URI handler is not an invocation contract: it has no stdin, no exit code,
    no stream, and no way to say "this turn is finished".
  * Authentication is a browser sign-in inside the app against a Cursor account
    (`authentication: "sign-in-in-native-app"`, `authenticated: null`, and
    release.json `api_keys_supported_by_installer: false`). There is no
    credential a headless invocation could be given, so even a hypothetical CLI
    could not be driven by the orchestrator.
  * The work does not run here. Grok Bot drives a vendor cloud computer, so
    `workspace_mode`, `read_grants` and the Firebreak mount boundary -- the only
    parts of SandboxSpec that are actually ENFORCED -- would constrain nothing
    that matters. A manifest for it would be a receipt describing a sandbox the
    agent is not in.
  * The vendor's own getting-started documentation (docs.x.ai/grok-bot/get-started,
    read 2026-09-09) documents a GUI and nothing else: no CLI, no local API, no
    headless flag.

The only honest way to reach Grok Bot from a mission would be to drive its
window. That is GUI scraping, it is forbidden by the engineering program, and
it would be forbidden anyway: nothing in AgentProvider could be satisfied by it.

WHY GROK BUILD CLI IS DEFERRED, NOT UNSUPPORTED
-----------------------------------------------
Grok Build is a DIFFERENT product from Grok Bot -- Shadowfetch already ships it
as an optional coding agent (`shadowfetch-code-agent grok`, pinned 1.0.5,
SHA-256 9ba87444...). Its published interface is the right shape for
AgentProvider: `-p/--single <PROMPT>` runs one non-interactive turn,
`--output-format streaming-json` emits newline-delimited events, `--always-approve`,
`--allow`/`--deny`/`--tools`/`--disallowed-tools`, `--sandbox`, `--max-turns`,
`--cwd`, and `XAI_API_KEY` for non-browser environments (docs.x.ai/build/overview
and docs.x.ai/build/cli/{reference,headless-scripting}, read 2026-09-09).

That is DOCUMENTED, not OBSERVED, and the difference is the whole point:

  1. No stream has been captured. The conformance suite requires a real native
     stream fixture and the normalisation it must produce. The pinned binary is
     not installed on the build host (no `grok` under any user's
     ~/.local/share/shadowfetch/code-agents, /usr/bin or /usr/local/bin) and no
     xAI credential exists here, so nobody has seen one byte of its output.
     Writing fixtures/providers/streams/grok_*.jsonl from a documentation page
     would be fabricating evidence, and `parse_stream` written against an
     invented schema would pass conformance while failing in front of a user.
  2. The docs are unversioned; the pin is 1.0.5. An argv asserted for a version
     nobody ran is a guess with a receipt.
  3. Config isolation is unresolved. `grok inspect` discovers "configuration,
     instructions, skills, plugins, hooks, and MCP servers", and no documented
     flag is the equivalent of Codex's `--ignore-user-config --ignore-rules
     --ephemeral`. Without a VERIFIED flag that disables all of it, a mission
     would silently execute the user's own hooks, plugins and MCP servers inside
     the mission sandbox with the mission's credentials and network grant. That
     is a real finding, not paperwork.
  4. `XAI_API_KEY` would still reach the sandbox as an environment VALUE. The
     credential broker (Stage D) does not exist, so no provider credential stays
     outside the sandbox today; a Grok manifest must not imply otherwise.

Completing Stage L therefore needs, in order: install the pinned 1.0.5 binary and
record `--help`; identify and verify a config-isolation flag; run one real turn
with a real key and capture plain/json/streaming-json plus a failure and a
cancellation; only then write sf_provider_grok.py, grok.json, the stream fixtures
and grok.approved-entry.json. Until step 3 exists there is nothing to review.

WHAT IS ACTUALLY ENFORCED HERE
------------------------------
Be precise, because it is less than it looks:

  ENFORCED  A manifest for Grok Bot dropped into the provider directory does not
            become a provider: the approved-provider policy refuses it, and with
            a forged policy it still fails closed for want of an adapter. Both
            are asserted below against the real registry.
  ENFORCED  The Grok Bot helper has no subcommand that runs a task; asserted
            from the program's own argparse, not from a comment.
  DISCLOSED The capabilities() string and GROK-BOT.md tell the user there is no
            mission adapter. Those are disclosures, pinned so they cannot rot
            into a lie. A string is not a control and is not counted as one.
  NOT ENFORCED  Nothing in the architecture can tell a GUI launcher from a
            headless agent. `/opt` is a packaged prefix and the vendor binary is
            root-owned, so classify_executable() would call Grok Bot
            distro-managed and be right. What keeps it out is this determination
            plus the policy pin -- not a mechanism that understands the
            difference. Anyone who adds an approved policy entry and an adapter
            gets a Grok Bot "provider", and no test but this one will object.
"""
from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import provider_conformance as pc
from sf_providers import ProviderRegistry

REPO_ROOT = pc.REPO_ROOT
PACKAGE_DIR = pc.PACKAGE_DIR
SHIPPED_POLICY_ROOT = PACKAGE_DIR / "data/usr/share/shadowfetch/provider-policy"

GROK_BOT_HELPER = REPO_ROOT / "packages/shadowfetch-defaults/data/usr/bin/shadowfetch-grok-bot"
GROK_BOT_RELEASE = REPO_ROOT / "packages/shadowfetch-defaults/data/usr/share/shadowfetch/grok-bot/release.json"
GROK_BOT_DOC = REPO_ROOT / "packages/shadowfetch-defaults/data/usr/share/doc/shadowfetch/GROK-BOT.md"
MISSIONS_SOURCE = REPO_ROOT / "packages/shadowfetch-missions/data/usr/lib/shadowfetch/missions/sf_missions.py"

# Every spelling a Grok provider could plausibly be registered under.
GROK_IDS = ("grok", "grok-bot", "grok-build", "grokbot", "xai", "xai-grok")

DISCLOSURE = ("Launch the official desktop cloud teammate separately; "
              "it has no supported mission CLI adapter")

# A schema-valid manifest that tries to make the native GUI application a
# provider. It is written to a temporary directory, never into the tree: the
# shipped provider directory is globbed for *.json, so a determination file
# parked there would itself be read as a manifest.
ROGUE_GROK_BOT_MANIFEST = {
    "schema_version": 1,
    "id": "grok-bot",
    "display_name": "Grok Bot (native desktop)",
    "interface_version": 1,
    "adapter_module": "sf_provider_grok",
    "adapter_class": "GrokBotProvider",
    "capabilities": ["code_change"],
    "credential_ids": [],
    "network_policy": "allowlist",
    "egress_allowlist": ["api.x.ai"],
    "sandbox_profile": {
        "workspace_mode": "workspace-write",
        "memory_mb": 3072,
        "cpu_seconds": 900,
        "processes": 96,
        "read_grants": [],
        "masked_paths": [],
    },
    "executable": {"kind": "absolute", "path": "/opt/Grok Bot/grok-bot"},
    "package": "shadowfetch-missions",
    "version": "4.0.0",
    "notes": "Stage L adversarial fixture. Not a real provider; must never load.",
}


def _rogue_manifest_file() -> Path:
    folder = Path(tempfile.mkdtemp(prefix="sf-stage-l-"))
    path = folder / "grok-bot.json"
    path.write_text(json.dumps(ROGUE_GROK_BOT_MANIFEST, indent=2) + "\n",
                    encoding="utf-8")
    return path


class GrokIsNotAProvider(unittest.TestCase):
    """The determination, stated against the real registry."""

    def test_no_shipped_manifest_declares_a_grok_provider(self):
        for path in pc.shipped_manifest_files():
            manifest = json.loads(path.read_text(encoding="utf-8"))
            self.assertNotIn(
                manifest["id"], GROK_IDS,
                f"{path.name} ships a Grok provider. Stage L determined there is "
                "no honest one; if that changed, change this file's docstring "
                "and say what evidence changed it.")

    def test_the_approved_provider_policy_contains_no_grok_entry(self):
        policy = json.loads((SHIPPED_POLICY_ROOT / "approved.json").read_text(encoding="utf-8"))
        for provider_id in policy["providers"]:
            self.assertNotIn(provider_id, GROK_IDS,
                             "approved.json approves a Grok provider that Stage L "
                             "found no supportable interface for.")

    def test_no_grok_adapter_module_ships(self):
        for path in pc.shipped_adapter_files():
            self.assertNotIn("grok", path.name,
                             f"{path.name} ships a Grok adapter with no captured "
                             "stream fixture behind it.")

    def test_a_grok_bot_manifest_in_the_directory_is_refused_by_the_shipped_policy(self):
        """ENFORCED: adding the manifest is not enough. The policy pin refuses it."""
        root = pc.manifest_root(*pc.shipped_manifest_files(), _rogue_manifest_file())
        registry = ProviderRegistry(root=root,
                                    module_root=pc.MISSION_MODULES,
                                    policy_root=SHIPPED_POLICY_ROOT)
        self.assertNotIn("grok-bot", registry.ids())
        self.assertTrue(
            any("grok-bot" in error and "approved-provider policy" in error
                for error in registry.errors),
            f"expected an approval refusal naming grok-bot, got {registry.errors!r}")
        # The refusal is targeted, not a collapse: the approved providers still
        # load. Stated as a subset so that approving a FUTURE provider -- which
        # is the architecture working -- does not fail this determination.
        self.assertLessEqual({"codex", "offline-media"}, set(registry.ids()))

    def test_an_approved_grok_manifest_still_fails_closed_with_no_adapter(self):
        """ENFORCED: forging the policy entry does not conjure an adapter either."""
        root = pc.manifest_root(_rogue_manifest_file())
        registry = ProviderRegistry(root=root,
                                    module_root=pc.MISSION_MODULES,
                                    policy_root=pc.policy_root_for(root))
        self.assertEqual(registry.list(), [],
                         "a Grok Bot manifest produced a usable provider")
        self.assertTrue(
            any("sf_provider_grok" in error and "not installed" in error
                for error in registry.errors),
            f"expected an adapter-missing refusal, got {registry.errors!r}")


class GrokBotShipsNoTaskInterface(unittest.TestCase):
    """ENFORCED: the integration Shadowfetch does ship cannot run a task."""

    def test_the_helper_exposes_only_install_verify_and_launch_subcommands(self):
        result = subprocess.run([sys.executable, str(GROK_BOT_HELPER), "--help"],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        choices = re.search(r"\{([a-z_,]+)\}", result.stdout)
        self.assertIsNotNone(choices, f"could not read subcommands from:\n{result.stdout}")
        self.assertEqual(
            set(choices.group(1).split(",")),
            {"setup", "status", "doctor", "open", "launch", "info", "_install"},
            "shadowfetch-grok-bot grew or lost a subcommand. If one of them now "
            "runs a task, Stage L's determination is stale and must be redone "
            "with evidence -- not amended here to make the test pass.")

    def test_the_helper_declares_no_prompt_task_or_headless_argument(self):
        tree = ast.parse(GROK_BOT_HELPER.read_text(encoding="utf-8"))
        flags = {node.value for node in ast.walk(tree)
                 if isinstance(node, ast.Constant) and isinstance(node.value, str)
                 and node.value.startswith("--")}
        for forbidden in ("--prompt", "--task", "--headless", "--json-events",
                          "--exec", "--message"):
            self.assertNotIn(forbidden, flags)

    def test_the_release_manifest_describes_a_gui_product_with_no_automation_endpoint(self):
        release = json.loads(GROK_BOT_RELEASE.read_text(encoding="utf-8"))
        self.assertEqual(release["kind"], "native-desktop-cloud-agent")
        self.assertIs(release["api_keys_supported_by_installer"], False)
        self.assertTrue(release["cloud_storage_required"])
        # Every command the manifest advertises is a Shadowfetch install/verify/
        # launch command. None of them is, or reaches, a task interface.
        for field in ("installer", "launcher", "status_command"):
            self.assertTrue(release[field].startswith("shadowfetch-grok-bot "),
                            f"{field} = {release[field]!r}")
        for key in release:
            self.assertNotRegex(
                key, r"(api_endpoint|task|headless|automation|socket|adapter)",
                f"release.json key {key!r} advertises an automation interface "
                "that Stage L found no evidence for.")


class TheDisclosureStaysHonest(unittest.TestCase):
    """DISCLOSED, not enforced: pinned so the user-facing text cannot rot."""

    def test_capabilities_still_states_there_is_no_supported_mission_cli_adapter(self):
        self.assertIn(DISCLOSURE, MISSIONS_SOURCE.read_text(encoding="utf-8"),
                      "capabilities() stopped telling clients that Grok Bot has "
                      "no mission adapter, while it still has none.")

    def test_the_shipped_documentation_denies_a_headless_task_api(self):
        self.assertIn("does not expose a headless task API",
                      GROK_BOT_DOC.read_text(encoding="utf-8"))

    def test_the_documentation_keeps_grok_bot_and_grok_build_distinct(self):
        text = GROK_BOT_DOC.read_text(encoding="utf-8")
        self.assertIn("Grok Bot and Grok Build are separate products.", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
