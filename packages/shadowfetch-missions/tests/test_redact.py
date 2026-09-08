"""Secret redaction: pattern coverage, block-boundary safety, and restraint.

Every credential in this file is a fixture assembled at runtime from pieces.
The pieces are joined by code rather than written as single literals so that
the release secret scan (tools/source_gate_4_0_0.py, gitleaks) does not flag
this file, and so that nobody reading it mistakes a fixture for a live key.
The bodies are deliberately low-entropy digit runs: the rules match on shape,
never on entropy, so a run of zeroes exercises them exactly as a real key would.
"""
import importlib.util
import os
import random
import time
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "data/usr/lib/shadowfetch/missions/sf_redact.py"
spec = importlib.util.spec_from_file_location("sf_redact", SOURCE)
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)

P = r.PLACEHOLDER


def build(*pieces: str) -> str:
    """Assemble a fixture credential. See the module docstring."""
    return "".join(pieces)


# One sample per rule id in sf_redact.rules(). test_every_rule_has_a_sample
# fails if a rule is added without one, so the inventory cannot drift.
SAMPLES = {
    "private_key_block": build(
        "-----BEGIN", " RSA PRIVATE KEY-----\n",
        "MIIBOgIBAAJBAK", "7" * 60, "\n", "9" * 60, "\n",
        "-----END", " RSA PRIVATE KEY-----"),
    "jwt": build("ey", "J", "hbGciOiJIUzI1NiJ9", ".", "eyJzdWIiOiIxMjM0NSJ9", ".", "4" * 43),
    "authorization_header": build("Authorization: ", "Digest ", "8" * 40),
    "http_auth_scheme": build("Bearer ", "2" * 44),
    "named_value_quoted": build('"api_key": "', "3" * 32, '"'),
    "named_value_single_quoted": build("DOCKER_PASSWORD='", "5" * 24, "'"),
    "named_value_bare": build("CODEX_API_KEY=", "6" * 48),
    "url_userinfo": build("https://deploy:", "7" * 24, "@registry.example.com/v2/"),
    "openai_family": build("sk", "-", "proj-", "0" * 40),
    "stripe": build("sk", "_live_", "1" * 24),
    "xai": build("xai", "-", "2" * 40),
    "groq": build("gsk", "_", "3" * 48),
    "github_token": build("gh", "p", "_", "4" * 36),
    "github_pat": build("github", "_pat_", "11ABCDE", "5" * 40),
    "gitlab_pat": build("glpat", "-", "6" * 20),
    "huggingface": build("hf", "_", "7" * 34),
    "cloudflare_user_token": build("cfut", "_", "8" * 32),
    "npm": build("npm", "_", "9" * 36),
    "pypi": build("pypi", "-", "AgEIcHlwaS5vcmc", "0" * 20),
    "digitalocean": build("dop", "_v1_", "a" * 64),
    "slack_token": build("xox", "b", "-", "1" * 12, "-", "2" * 24),
    "slack_app_token": build("xapp", "-", "1-", "3" * 20),
    "aws_access_key_id": build("AKIA", "Q" * 16),
    "google_api_key": build("AIza", "S" * 35),
}

# Text that must survive untouched. Anything mangled here makes the redactor
# actively harmful to debugging, which is worse than the gap it closes.
INNOCENT = {
    "uuid": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "git_sha": "9c1e5b0d3f2a4b6c8d0e1f2a3b4c5d6e7f8a9b0c",
    "short_sha": "9c1e5b0",
    "png_data_uri": (
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ"
        "AAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="),
    "prose": "The launch is Friday. Passwords are not stored in the mission log.",
    "path_env": "PATH=/usr/local/bin:/usr/bin:/bin",
    "audit_line": "shadowfetch-firebreak run --credential-env CODEX_API_KEY --net allow",
    "credential_names_json": '"credential_names": ["CODEX_API_KEY", "codex-account"]',
    "monkey": "MONKEY=banana TURKEY=roast DONKEY=grey",
    "iso_date": "2026-09-08T11:04:33+00:00",
    "sha256_line": "sha256:3b2f1c0d9e8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c",
    "url_no_userinfo": "https://api.openai.com/v1/responses",
    "diff_hunk": "@@ -12,7 +12,9 @@ def execute(self):",
    "python_traceback": 'File "/usr/lib/shadowfetch/missions/sf_missions.py", line 660, in run_process',
}


class PatternInventory(unittest.TestCase):
    def test_every_rule_has_a_sample(self):
        """A new rule without a fixture would ship untested."""
        declared = {identifier for identifier, _, _ in r.rules()}
        self.assertEqual(declared, set(SAMPLES), "rules() and SAMPLES disagree")

    def test_every_rule_description_is_written(self):
        for identifier, description, _ in r.rules():
            self.assertTrue(description.strip(), identifier)

    def test_each_pattern_class_is_caught_in_context(self):
        for identifier, sample in sorted(SAMPLES.items()):
            with self.subTest(rule=identifier):
                line = f"controller: agent printed {sample} while starting"
                out = r.redact(line, values=())
                self.assertIn(P, out, identifier)
                body = sample.split("-----")[2] if identifier == "private_key_block" else sample
                for run in ("0" * 12, "1" * 12, "2" * 12, "3" * 12, "4" * 12,
                            "5" * 12, "6" * 12, "7" * 12, "8" * 12, "9" * 12,
                            "a" * 12, "Q" * 12, "S" * 12):
                    if run in body:
                        self.assertNotIn(run, out, f"{identifier} leaked {run[:3]}...")
                self.assertTrue(out.startswith("controller: agent printed "))
                self.assertTrue(out.endswith(" while starting"))

    def test_credential_name_survives_so_the_log_stays_debuggable(self):
        out = r.redact(SAMPLES["named_value_bare"], values=())
        self.assertEqual(out, "CODEX_API_KEY=" + P)

    def test_vendor_tag_survives_so_the_provider_is_still_identifiable(self):
        self.assertEqual(r.redact(SAMPLES["openai_family"], values=()), "sk-" + P)
        self.assertEqual(r.redact(SAMPLES["http_auth_scheme"], values=()), "Bearer " + P)

    def test_url_keeps_scheme_user_and_host(self):
        out = r.redact(SAMPLES["url_userinfo"], values=())
        self.assertEqual(out, "https://deploy:" + P + "@registry.example.com/v2/")

    def test_auth_scheme_keyword_survives_and_the_rest_of_the_line_does_too(self):
        """Regression: the header rule used to swallow the rest of the line."""
        line = ("curl -H 'Authorization: Bearer " + "2" * 44
                + "' https://api.openai.com/v1/responses")
        out = r.redact(line, values=())
        self.assertNotIn("2" * 12, out)
        self.assertIn("Authorization: Bearer ", out)
        self.assertIn("https://api.openai.com/v1/responses", out)
        self.assertTrue(out.endswith("' https://api.openai.com/v1/responses"))

    def test_a_hyphenated_header_name_is_recognised(self):
        out = r.redact("X-Api-Key: " + "4" * 40, values=())
        self.assertEqual(out, "X-Api-Key: " + P)

    def test_over_redaction_is_the_documented_failure_direction(self):
        """A credential-shaped name is all we have, so these lose their values."""
        self.assertEqual(r.redact("PRIMARY_KEY=id", values=()), "PRIMARY_KEY=" + P)
        self.assertEqual(r.redact("SORT_KEY: name", values=()), "SORT_KEY: " + P)


class TriggerPrefilter(unittest.TestCase):
    """The pre-filter skips the regex entirely; prove it can only skip safely.

    The required implication is: a rule matches => a trigger is present.
    A false "no trigger" would silently disable redaction for that block, so
    this is the highest-consequence property in the module.
    """

    def triggers(self):
        return r._compiled(())[2]

    def pattern(self):
        return r._compiled(())[0]

    def test_each_rule_declares_a_trigger_its_own_sample_contains(self):
        for identifier, _, rule_triggers in r.rules():
            with self.subTest(rule=identifier):
                self.assertTrue(rule_triggers, f"{identifier} declares no trigger")
                lowered = SAMPLES[identifier].lower()
                self.assertTrue(
                    any(trigger.lower() in lowered for trigger in rule_triggers),
                    f"{identifier}: sample contains none of {rule_triggers}")

    def test_each_rule_actually_matches_its_own_sample(self):
        """Otherwise the trigger test above proves nothing."""
        for identifier, source, *_rest in r._RULES:
            with self.subTest(rule=identifier):
                probe = r.re.compile(source.replace("(?P<S>", "(?:"))
                self.assertIsNotNone(probe.search(SAMPLES[identifier]), identifier)

    def test_a_match_always_implies_a_trigger(self):
        corpus = list(SAMPLES.values()) + list(INNOCENT.values()) + [
            "Authorization: Bearer " + "2" * 44,
            "PASSPHRASE = " + "5" * 20,
            "credentials: '" + "6" * 20 + "'",
            "APIKEY:" + "7" * 20,
        ]
        for text in corpus:
            with self.subTest(text=text[:40]):
                if self.pattern().search(text):
                    self.assertTrue(r._has_trigger(text, self.triggers()),
                                    f"regex matched but no trigger fired: {text[:60]!r}")

    def test_fuzz_a_match_always_implies_a_trigger(self):
        rng = random.Random(1337)
        pieces = SlidingWindow.NOISE + ["TOKEN", "Secret", "PassPhrase", "CREDENTIALS",
                                        "apikey", "://", "-----BEGIN", "xox", "AIza",
                                        "dop_v1_", "glpat-", "hf_", "npm_", "cfut_"]
        matched = 0
        for _ in range(3000):
            text = "".join(rng.choice(pieces) for _ in range(rng.randrange(2, 25)))
            if self.pattern().search(text):
                matched += 1
                self.assertTrue(r._has_trigger(text, self.triggers()),
                                f"regex matched but no trigger fired: {text!r}")
        self.assertGreater(matched, 100, "fuzz produced too few matching samples")

    def test_ascii_case_folding_keeps_the_implication_true(self):
        """Unicode IGNORECASE would let a rule match text whose lower() has no
        contiguous trigger. The table uses (?ai:) so that cannot happen."""
        for text in ("KEY=" + "0" * 20,          # Kelvin sign instead of K
                     "CREDENTİAL=" + "0" * 20):   # dotted capital I
            with self.subTest(text=text[:20]):
                self.assertIsNone(self.pattern().search(text),
                                  "a non-ASCII letter matched a name word")
                self.assertEqual(r.redact(text, values=()), text)

    def test_the_prefilter_does_not_change_any_result(self):
        """Fast path and slow path must agree on every corpus string."""
        pattern, groups, _ = r._compiled(())
        for text in list(SAMPLES.values()) + list(INNOCENT.values()):
            with self.subTest(text=text[:40]):
                slow = pattern.sub(lambda m: r._rewrite(m, groups, r.PLACEHOLDER), text)
                self.assertEqual(r.redact(text, values=()), slow)

    def test_an_exact_credential_value_is_its_own_trigger(self):
        value = build("Zz", "-Mixed-Case-", "0" * 20)
        _, _, triggers = r._compiled((value,))
        self.assertIn(value.lower(), triggers)
        self.assertNotIn(value, r.redact("saw " + value, values=(value,)))


class Restraint(unittest.TestCase):
    def test_non_secrets_are_returned_byte_for_byte(self):
        for label, text in sorted(INNOCENT.items()):
            with self.subTest(case=label):
                self.assertEqual(r.redact(text, values=()), text)

    def test_innocent_text_survives_the_streaming_path_too(self):
        for label, text in sorted(INNOCENT.items()):
            with self.subTest(case=label):
                red = r.StreamRedactor(values=(), carry=4)
                self.assertEqual(red.feed(text) + red.flush(), text)

    def test_a_short_credential_value_is_not_used_as_a_needle(self):
        """KEY=x must not turn every x in the log into a placeholder."""
        env = {"CODEX_API_KEY": "abc"}
        self.assertEqual(r.credential_values(env=env), ())
        text = "abc def abc"
        self.assertEqual(r.redact(text, values=r.credential_values(env=env)), text)

    def test_a_long_credential_value_is_struck_out_wherever_it_appears(self):
        value = build("private", "-test-", "credential-", "0" * 20)
        env = {"CODEX_API_KEY": value}
        out = r.redact("agent said " + value + " twice: " + value,
                       values=r.credential_values(env=env))
        self.assertNotIn(value, out)
        self.assertEqual(out, "agent said " + P + " twice: " + P)

    def test_credential_identities_in_an_audit_trail_are_never_rewritten(self):
        """Firebreak records which credential was granted. That must stay legible."""
        for text in (INNOCENT["audit_line"], INNOCENT["credential_names_json"]):
            self.assertIn("CODEX_API_KEY", r.redact(text, values=()))

    def test_ssh_auth_sock_is_not_a_secret(self):
        self.assertNotIn("SSH_AUTH_SOCK", r.CREDENTIAL_NAMES)


class Idempotence(unittest.TestCase):
    def corpus(self):
        return list(SAMPLES.values()) + list(INNOCENT.values()) + [
            build("export CODEX_API_KEY=", "6" * 48, "; echo done"),
            build('{"api_key": "', "3" * 32, '", "id": "', INNOCENT["uuid"], '"}'),
            build("Authorization: Bearer ", "2" * 44, "\r\n"),
        ]

    def test_redacting_twice_changes_nothing(self):
        for text in self.corpus():
            with self.subTest(text=text[:40]):
                once = r.redact(text, values=())
                self.assertEqual(r.redact(once, values=()), once)

    def test_redacting_three_times_changes_nothing(self):
        for text in self.corpus():
            once = r.redact(text, values=())
            self.assertEqual(r.redact(r.redact(once, values=()), values=()), once)

    def test_placeholder_alone_is_stable(self):
        self.assertEqual(r.redact(P, values=()), P)
        self.assertEqual(r.redact("CODEX_API_KEY=" + P, values=()), "CODEX_API_KEY=" + P)


class SlidingWindow(unittest.TestCase):
    """The point of the exercise: a secret split across two reads.

    A per-block re.sub sees two innocent fragments and writes the whole key to
    the log in two pieces. These tests split at EVERY offset.
    """

    def split_proof(self, secret, carry, prefix="agent output before ",
                    suffix=" and after the key"):
        text = prefix + secret + suffix
        failures = []
        for offset in range(len(text) + 1):
            red = r.StreamRedactor(values=(), carry=carry)
            out = red.feed(text[:offset]) + red.feed(text[offset:]) + red.flush()
            if secret in out:
                failures.append((offset, "leaked"))
            elif out != r.redact(text, values=()):
                failures.append((offset, "diverged from one-shot: " + repr(out)))
        return failures

    def test_every_split_offset_of_every_rule_sample(self):
        for identifier, sample in sorted(SAMPLES.items()):
            with self.subTest(rule=identifier):
                carry = max(64, len(sample) * 2)
                failures = self.split_proof(sample, carry)
                self.assertEqual(failures, [], f"{identifier}: {failures[:3]}")

    def test_three_way_split_at_every_pair_of_offsets(self):
        secret = SAMPLES["openai_family"]
        text = "start " + secret + " end"
        for first in range(len(text) + 1):
            for second in range(first, len(text) + 1):
                red = r.StreamRedactor(values=(), carry=128)
                out = (red.feed(text[:first]) + red.feed(text[first:second])
                       + red.feed(text[second:]) + red.flush())
                self.assertNotIn(secret, out, f"split {first}/{second}")
                self.assertEqual(out, r.redact(text, values=()), f"split {first}/{second}")

    def test_one_byte_at_a_time(self):
        text = "prefix " + SAMPLES["named_value_bare"] + " suffix"
        red = r.StreamRedactor(values=(), carry=128)
        out = "".join(red.feed(char) for char in text) + red.flush()
        self.assertEqual(out, r.redact(text, values=()))
        self.assertNotIn("6" * 12, out)

    def test_real_65536_byte_read_boundary(self):
        """The actual failure mode in Mission Control's os.read(fd, 65536).

        The key is placed so that it straddles offset 65536 exactly, then the
        split is walked through every character of the key.
        """
        block = 65536
        secret = SAMPLES["openai_family"]
        line = "mission log line: workspace scan complete\n"
        filler = line * ((block // len(line)) + 1)
        filler = filler[:block - 20] + "\ncontroller: key "
        text = filler + secret + "\ntrailing output\n"
        self.assertLess(len(filler), block)
        self.assertGreater(len(filler) + len(secret), block)
        for offset in range(len(secret) + 1):
            cut = len(filler) + offset
            red = r.StreamRedactor(values=())
            out = red.feed(text[:cut]) + red.feed(text[cut:]) + red.flush()
            self.assertNotIn(secret, out, f"leaked when split {offset} chars into the key")
            self.assertNotIn("0" * 12, out, f"key body leaked at offset {offset}")
            self.assertEqual(out, r.redact(text, values=()))
            self.assertIn("trailing output", out)

    def test_a_lookbehind_guard_is_not_fooled_by_the_buffer_start(self):
        """Regression: a held buffer's first character is not start-of-text.

        Without re-presenting LEFT_CONTEXT, the guard that stops MONKEY being
        read as ...KEY succeeds at offset 0 of the second buffer, and
        "TUR" + "KEY=roast" gets redacted when the one-shot path leaves it be.
        """
        text = "MONKEY=banana TURKEY=roast DONKEY=grey"
        self.assertEqual(r.redact(text, values=()), text)
        for offset in range(len(text) + 1):
            red = r.StreamRedactor(values=(), carry=1)
            out = red.feed(text[:offset]) + red.feed(text[offset:]) + red.flush()
            self.assertEqual(out, text, f"mangled innocent text at split {offset}")

    def test_a_key_packed_against_a_word_is_a_known_gap(self):
        """Pins the documented cost of the base64 guard, in both paths.

        If a future change makes this redact, the guard has been loosened and
        the base64-blob tests must be re-checked; this test then needs updating
        deliberately rather than by accident.
        """
        glued = "scan complsk" + "-" + "0" * 40
        self.assertEqual(r.redact(glued, values=()), glued)
        red = r.StreamRedactor(values=(), carry=8)
        self.assertEqual(red.feed(glued) + red.flush(), glued)

    def test_exact_environment_value_split_across_the_boundary(self):
        value = build("live", "-value-", "0" * 40)
        red_values = r.credential_values(env={"CODEX_API_KEY": value})
        text = "x" * 200 + value + "y" * 200
        for offset in range(len(value) + 1):
            cut = 200 + offset
            red = r.StreamRedactor(values=red_values, carry=64)
            out = red.feed(text[:cut]) + red.feed(text[cut:]) + red.flush()
            self.assertNotIn(value, out, f"offset {offset}")

    def test_streaming_matches_one_shot_over_a_mixed_stream(self):
        rng = random.Random(4021)
        pieces = list(SAMPLES.values()) + list(INNOCENT.values())
        rng.shuffle(pieces)
        text = "\n".join(f"[{n:04d}] controller: {piece}" for n, piece in enumerate(pieces * 3))
        expected = r.redact(text, values=())
        for _ in range(40):
            cuts = sorted(rng.randrange(len(text) + 1) for _ in range(5))
            red = r.StreamRedactor(values=(), carry=512)
            out, previous = "", 0
            for cut in cuts + [len(text)]:
                out += red.feed(text[previous:cut])
                previous = cut
            out += red.flush()
            self.assertEqual(out, expected, f"cuts={cuts}")

    def test_the_shipped_carry_is_wider_than_any_rule_can_match(self):
        """The guarantee has to cover the module's own patterns.

        Every rule is bounded, and the default carry is bigger than the largest
        bound. Without this, a long match could outgrow the hold window and the
        split-safety claim would be false for the module's own rule table.
        """
        self.assertGreater(r.DEFAULT_CARRY, r.MAX_MATCH)
        oversized = []
        for identifier, source, *_rest in r._RULES:
            probe = "\n" + ("Z" * 200000) + "\n"
            for match in r.re.compile(source.replace("(?P<S>", "(?:")).finditer(probe):
                if match.end() - match.start() > r.MAX_MATCH:
                    oversized.append(identifier)
        self.assertEqual(oversized, [])

    def test_a_maximum_length_pem_key_is_split_safe(self):
        """The longest shape in the table, straddling a 65536-byte read."""
        body = "\n".join("M" * 64 for _ in range(120))
        pem = ("-----BEGIN" + " RSA PRIVATE KEY-----\n" + body
               + "\n-----END" + " RSA PRIVATE KEY-----")
        self.assertLess(len(pem), r.MAX_MATCH)
        filler = "controller: still working\n" * 2600
        text = filler[:65500] + "\nagent printed:\n" + pem + "\ndone\n"
        for offset in (0, 1, len(pem) // 2, len(pem) - 1, len(pem)):
            cut = text.index(pem) + offset
            red = r.StreamRedactor(values=())
            out = red.feed(text[:cut]) + red.feed(text[cut:]) + red.flush()
            self.assertNotIn("M" * 64, out, f"PEM body leaked at offset {offset}")
            self.assertEqual(out, r.redact(text, values=()))
            self.assertIn("done", out)

    def test_a_2048_character_named_value_is_split_safe(self):
        secret = build("CODEX_API_KEY=", "7" * 2048)
        text = "x" * 70000 + " " + secret + " tail\n"
        for offset in (0, 14, 1000, 2048, len(secret)):
            cut = text.index(secret) + offset
            red = r.StreamRedactor(values=())
            out = red.feed(text[:cut]) + red.feed(text[cut:]) + red.flush()
            self.assertNotIn("7" * 20, out, f"offset {offset}")
            self.assertEqual(out, r.redact(text, values=()))

    def test_a_secret_longer_than_carry_is_a_documented_gap_not_a_silent_one(self):
        """carry bounds the guarantee. Prove where the bound actually is."""
        secret = build("sk", "-", "0" * 200)
        text = "before " + secret + " after"
        inside = r.StreamRedactor(values=(), carry=len(text) + 1)
        cut = len("before ") + 100
        out = inside.feed(text[:cut]) + inside.feed(text[cut:]) + inside.flush()
        self.assertNotIn(secret, out)
        # carry smaller than the match: the guarantee does not extend here.
        tiny = r.StreamRedactor(values=(), carry=8)
        out = tiny.feed(text[:cut]) + tiny.feed(text[cut:]) + tiny.flush()
        self.assertNotIn(secret, out, "even below carry the whole secret must not appear")

    NOISE = ["KEY", "TUR", "MON", "=", ":", " ", "sk", "-", "_", "+", "/",
             "0", "9", "a", "Z", "\n", '"', "'", "@", "Bearer ", "api",
             "AKIA", "eyJ", "ghp", ".", "Authorization", "PASSWORD"]

    def longest_match(self, text):
        """Length of the longest single match, so a test can pick a valid carry.

        Reaches into the compiled table deliberately: the streaming guarantee is
        stated in terms of match length, so a test of that guarantee has to
        measure it rather than guess.
        """
        pattern = r._compiled(())[0]
        return max((match.end() - match.start() for match in pattern.finditer(text)),
                   default=0)

    def test_differential_fuzz_streaming_equals_one_shot(self):
        """The invariant that caught the lookbehind bug, run over noise.

        The alphabet is stocked with the fragments that make guards interesting:
        truncated name words, vendor prefixes, base64 characters, separators.
        Carry is set above the longest match in each text, which is exactly the
        condition the guarantee is stated under.
        """
        rng = random.Random(90210)
        for trial in range(120):
            text = "".join(rng.choice(self.NOISE) for _ in range(rng.randrange(20, 90)))
            expected = r.redact(text, values=())
            carry = self.longest_match(text) + 1
            for offset in range(len(text) + 1):
                red = r.StreamRedactor(values=(), carry=carry)
                out = red.feed(text[:offset]) + red.feed(text[offset:]) + red.flush()
                self.assertEqual(
                    out, expected,
                    f"trial {trial} carry {carry} offset {offset}: {text!r}")

    def test_fuzz_innocent_text_is_never_mangled_at_any_carry(self):
        """A false positive needs no carry budget, so no carry excuses one.

        Where the one-shot path redacts nothing, the streaming path must also
        redact nothing -- at carry=1, where a buffer boundary lands between
        almost every pair of characters. This is the property the lookbehind
        bug violated.
        """
        rng = random.Random(5150)
        checked = 0
        for _ in range(400):
            text = "".join(rng.choice(self.NOISE) for _ in range(rng.randrange(4, 50)))
            if r.redact(text, values=()) != text:
                continue  # this one really does contain a secret shape
            checked += 1
            for carry in (1, 2, 3, 7):
                for offset in range(len(text) + 1):
                    red = r.StreamRedactor(values=(), carry=carry)
                    out = red.feed(text[:offset]) + red.feed(text[offset:]) + red.flush()
                    self.assertEqual(out, text,
                                     f"invented a redaction: carry {carry} "
                                     f"offset {offset}: {text!r}")
        self.assertGreater(checked, 20, "fuzz produced too few innocent samples")

    def test_flush_returns_the_held_tail(self):
        red = r.StreamRedactor(values=(), carry=64)
        self.assertEqual(red.feed("short"), "")
        self.assertEqual(red.flush(), "short")
        self.assertEqual(red.flush(), "")


class ByteStream(unittest.TestCase):
    def test_multibyte_character_split_across_two_reads_survives(self):
        raw = "commit méssage — ok\n".encode("utf-8")
        cut = raw.index("é".encode("utf-8")) + 1
        red = r.StreamRedactor(values=(), carry=1)
        out = red.feed_bytes(raw[:cut]) + red.feed_bytes(raw[cut:]) + red.flush_bytes()
        self.assertEqual(out.decode("utf-8"), "commit méssage — ok\n")

    def test_bytes_path_redacts_across_a_block_boundary(self):
        secret = SAMPLES["github_token"]
        raw = ("log " + secret + " end").encode("utf-8")
        for offset in range(len(raw) + 1):
            red = r.StreamRedactor(values=(), carry=64)
            out = red.feed_bytes(raw[:offset]) + red.feed_bytes(raw[offset:]) + red.flush_bytes()
            self.assertNotIn(secret.encode(), out, f"offset {offset}")
            self.assertEqual(out, ("log gh" + "p_" + P + " end").encode())

    def test_redact_bytes_one_shot(self):
        raw = ("x " + SAMPLES["aws_access_key_id"] + " y").encode()
        self.assertEqual(r.redact_bytes(raw, values=()), ("x " + P + " y").encode())

    def test_invalid_utf8_does_not_raise(self):
        red = r.StreamRedactor(values=(), carry=1)
        out = red.feed_bytes(b"before \xff\xfe after") + red.flush_bytes()
        self.assertIn(b"before ", out)
        self.assertIn(b"after", out)


class BoundedMemory(unittest.TestCase):
    def test_a_match_larger_than_max_hold_does_not_grow_the_buffer(self):
        red = r.StreamRedactor(values=(), carry=16, max_hold=64)
        body = "A" * 4000
        out = red.feed(build("-----BEGIN", " PRIVATE KEY-----\n") + body)
        out += red.flush()
        self.assertNotIn("A" * 100, out)
        self.assertIn(P, out)

    def test_held_tail_stays_bounded_over_many_blocks(self):
        red = r.StreamRedactor(values=(), carry=32, max_hold=256)
        for _ in range(200):
            red.feed(build("-----BEGIN", " PRIVATE KEY-----\n") + "B" * 500)
            self.assertLessEqual(len(red._tail), red.max_hold + 600)
        red.flush()

    def test_carry_and_max_hold_are_validated(self):
        with self.assertRaises(ValueError):
            r.StreamRedactor(values=(), carry=0)
        with self.assertRaises(ValueError):
            r.StreamRedactor(values=(), carry=64, max_hold=8)


class DebuggableOutput(unittest.TestCase):
    LOG = "\n".join([
        "process-started codex",
        "+ export CODEX_API_KEY=" + "6" * 48,
        "+ curl -H 'Authorization: Bearer " + "2" * 44 + "' https://api.openai.com/v1/responses",
        'codex: {"type":"error","message":"401 invalid_api_key","request_id":"req_01HZ"}',
        "Traceback (most recent call last):",
        '  File "/home/agent/run.py", line 42, in main',
        "RuntimeError: authentication failed after 3 attempts",
        "process-finished codex: exit 1; log=/home/agent/.local/state/codex.log",
    ])

    def test_a_redacted_log_still_explains_the_failure(self):
        out = r.redact(self.LOG, values=())
        for keep in ("process-started codex", "export CODEX_API_KEY=",
                     "Authorization:", "https://api.openai.com/v1/responses",
                     "401 invalid_api_key", "req_01HZ", "Traceback",
                     "/home/agent/run.py", "line 42",
                     "RuntimeError: authentication failed after 3 attempts",
                     "exit 1", "/home/agent/.local/state/codex.log"):
            self.assertIn(keep, out, f"lost debugging context: {keep}")

    def test_the_secrets_are_gone(self):
        out = r.redact(self.LOG, values=())
        self.assertNotIn("6" * 12, out)
        self.assertNotIn("2" * 12, out)

    def test_line_structure_is_preserved(self):
        out = r.redact(self.LOG, values=())
        self.assertEqual(len(out.splitlines()), len(self.LOG.splitlines()))

    def test_streamed_log_matches_the_one_shot_log(self):
        red = r.StreamRedactor(values=(), carry=64)
        out = "".join(red.feed(self.LOG[i:i + 7]) for i in range(0, len(self.LOG), 7))
        out += red.flush()
        self.assertEqual(out, r.redact(self.LOG, values=()))


class Cost(unittest.TestCase):
    def test_a_megabyte_of_clean_log_is_cheap(self):
        line = ("2026-09-08T11:04:33+00:00 controller: scanned 12 files, "
                "sha 9c1e5b0d3f2a4b6c8d0e1f2a3b4c5d6e7f8a9b0c, no changes\n")
        text = line * (1_000_000 // len(line))
        red = r.StreamRedactor(values=())
        start = time.monotonic()
        out = "".join(red.feed(text[i:i + 65536]) for i in range(0, len(text), 65536))
        out += red.flush()
        elapsed = time.monotonic() - start
        self.assertEqual(out, text)
        print(f"\n  throughput: {len(text) / 1048576 / elapsed:.1f} MiB/s "
              f"({len(text)} bytes in {elapsed:.3f}s)")
        # Deterministic companion to the wall clock, which is noisy on a shared
        # machine: an ordinary log block must take the pre-filter's fast path.
        self.assertFalse(r._has_trigger(text, r._compiled(())[2]),
                         "a clean log block should not reach the regex at all")
        self.assertLess(elapsed, 10.0, "redaction must not dominate log writing")

    def test_only_the_blocks_containing_a_trigger_pay_the_regex_cost(self):
        line = "controller: scanned 12 files, no changes\n"
        clean = line * 2000
        secret = build("export CODEX_API_KEY=", "6" * 48, "\n")
        triggers = r._compiled(())[2]
        self.assertFalse(r._has_trigger(clean, triggers))
        self.assertTrue(r._has_trigger(clean + secret, triggers))
        red = r.StreamRedactor(values=())
        out = red.feed(clean) + red.feed(secret + clean) + red.flush()
        self.assertNotIn("6" * 12, out)
        self.assertIn("CODEX_API_KEY=" + P, out)


class DefaultEnvironment(unittest.TestCase):
    def test_values_come_from_the_environment_by_default(self):
        value = build("environment", "-sourced-", "0" * 24)
        previous = os.environ.get("CODEX_API_KEY")
        os.environ["CODEX_API_KEY"] = value
        try:
            self.assertIn(value, r.credential_values())
            self.assertNotIn(value, r.redact("leaked " + value))
        finally:
            if previous is None:
                os.environ.pop("CODEX_API_KEY", None)
            else:
                os.environ["CODEX_API_KEY"] = previous

    def test_redact_accepts_non_strings_like_an_exception(self):
        error = RuntimeError("failed with " + SAMPLES["openai_family"])
        out = r.redact(error, values=())
        self.assertNotIn("0" * 12, out)
        self.assertTrue(out.startswith("failed with sk-"))

    def test_empty_input(self):
        self.assertEqual(r.redact("", values=()), "")
        self.assertEqual(r.redact(None, values=()), "None")


class OneImplementation(unittest.TestCase):
    """W-29 is "one shared implementation". Guard against a second one.

    These read shipped source as text rather than importing it: the Control
    Center needs PyQt6 and Firebreak is an extensionless executable, and the
    point here is what the code says, not what it does at runtime.
    """

    PACKAGES = ("shadowfetch-missions", "shadowfetch-fireline",
                "shadowfetch-control-center")
    VENDOR_PREFIXES = ("sk-", "xai-", "ghp_", "AKIA", "github_pat_", "-----BEGIN")
    REGEX_MARKERS = ("re.sub", "re.compile", "re.search", "re.match",
                     "[A-Za-z0-9", "[A-Z0-9", "{12,", "{16,", "{20,")

    # Files allowed to contain their own secret patterns.
    #   sf_redact.py  -- is the shared implementation.
    #   sf_missions.py -- HANDOFF: still carries the original clean() regex.
    #      The lead is rewiring Store/Executor onto the provider seam; once
    #      clean() delegates to sf_redact, delete this entry and this test
    #      starts enforcing the rule there too.
    ALLOWED = {"sf_redact.py", "sf_missions.py"}

    def shipped_sources(self):
        root = Path(__file__).resolve().parents[3]
        for package in self.PACKAGES:
            base = root / "packages" / package / "data"
            if not base.is_dir():
                continue
            for path in sorted(base.rglob("*")):
                if not path.is_file() or path.suffix not in ("", ".py"):
                    continue
                try:
                    text = path.read_text()
                except (UnicodeDecodeError, OSError):
                    continue
                if path.suffix != ".py" and not text.startswith("#!"):
                    continue
                yield path, text

    def test_no_second_secret_pattern_ships_anywhere(self):
        offenders = []
        for path, text in self.shipped_sources():
            if path.name in self.ALLOWED:
                continue
            for number, line in enumerate(text.splitlines(), 1):
                if (any(prefix in line for prefix in self.VENDOR_PREFIXES)
                        and any(marker in line for marker in self.REGEX_MARKERS)):
                    offenders.append(f"{path.name}:{number}: {line.strip()[:90]}")
        self.assertEqual(offenders, [], "a second secret-pattern implementation appeared")

    def test_the_scan_would_actually_catch_one(self):
        """A guard test that cannot fail is worthless; prove this one bites."""
        planted = 're.sub(r"sk-[A-Za-z0-9]{12,}", "x", message)'
        self.assertTrue(any(prefix in planted for prefix in self.VENDOR_PREFIXES))
        self.assertTrue(any(marker in planted for marker in self.REGEX_MARKERS))
        innocent = 'run_to("disk-space.txt", ["df", "-h"])'
        self.assertFalse(any(marker in innocent for marker in self.REGEX_MARKERS))

    def test_the_control_center_transport_calls_the_shared_redactor(self):
        root = Path(__file__).resolve().parents[3]
        source = (root / "packages/shadowfetch-control-center/data/usr/share"
                  / "shadowfetch/control-center/sfcc/mission_client.py").read_text()
        self.assertIn("from sf_redact import redact", source)
        self.assertIn("redact(error) if error else error", source)

    def test_the_firebreak_error_funnel_calls_a_redactor(self):
        root = Path(__file__).resolve().parents[3]
        source = (root / "packages/shadowfetch-fireline/data/usr/bin"
                  / "shadowfetch-firebreak").read_text()
        self.assertIn("from sf_redact import redact as shared", source)
        self.assertIn('print("Firebreak: " + redact(exc)', source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
