#!/usr/bin/env python3
"""One secret redactor for every place Shadowfetch records agent output.

Mission Control, the Firebreak error funnel and the Control Center transport all
show text that a subprocess produced. Any of them can pick up a credential the
agent echoed, a shell trace of ``export CODEX_API_KEY=...``, a curl
``Authorization`` header or a private key someone cat'd into the terminal. This
module is the single implementation those call sites share, so a pattern added
here is added everywhere at once.

Two entry points:

  * ``redact(text)`` -- one-shot, stateless. Drop-in for a ``clean()``-shaped
    helper: it accepts any object, coerces with ``str()`` and returns ``str``.
  * ``StreamRedactor()`` -- stateful, for output that arrives in blocks.
    ``feed()`` / ``feed_bytes()`` per block, ``flush()`` / ``flush_bytes()``
    at end of stream.

WHY THE STREAMING FORM EXISTS
-----------------------------
Mission Control's process reader calls ``os.read(fd, 65536)``. A 51-character
API key that happens to straddle offset 65536 is two harmless-looking fragments
to a per-block ``re.sub``, and the log then holds the whole key in two pieces.
``StreamRedactor`` holds back a bounded tail (``DEFAULT_CARRY``) and never cuts
inside a match, so a secret whose matched text is at most ``carry`` characters
long is redacted no matter where the block boundary falls. Every rule in the
table is bounded below ``MAX_MATCH`` and the default carry is larger still, so
in the shipped configuration every shape this module recognises is split-safe.

It also keeps ``LEFT_CONTEXT`` already-emitted characters in front of the scan
position, because otherwise the start of a held buffer looks like the start of
the text and every ``(?<!...)`` guard in the table silently succeeds there --
that turns ``...TUR`` + ``KEY=roast`` into a redaction the one-shot path would
never make. Streaming output is therefore identical to ``redact()`` over the
whole stream, which the tests assert directly.

``feed_bytes`` drives an incremental UTF-8 decoder, so a multi-byte character
split across two reads is reassembled instead of becoming two replacement
characters.

WHAT THIS CATCHES
-----------------
Two families, both enumerated in ``rules()`` and each exercised by
``packages/shadowfetch-missions/tests/test_redact.py``:

  1. By NAME. ``NAME=value`` / ``NAME: value`` / ``"name": "value"`` where the
     final underscore- or hyphen-separated word of the name is TOKEN, KEY,
     APIKEY, SECRET, PASSWORD, PASSWD, PASSPHRASE, CREDENTIAL(S) or
     AUTHORIZATION. That covers ``CODEX_API_KEY``, ``OPENAI_API_KEY``,
     ``AWS_SECRET_ACCESS_KEY``, ``api_key`` and ``password`` without
     enumerating them. The name and separator survive; only the value is
     replaced, which is what keeps a redacted log debuggable.
  2. By VALUE SHAPE. Vendor prefixes (``sk-`` incl. sk-proj-/sk-ant-/sk-or-v1-,
     ``sk_live_``, ``xai-``, ``gsk_``, ``ghp_``/``gho_``/``ghu_``/``ghs_``/
     ``ghr_``, ``github_pat_``, ``glpat-``, ``hf_``, ``cfut_``, ``npm_``,
     ``pypi-``, ``dop_v1_``, the ``xox?-`` Slack tags, ``xapp-``,
     ``AKIA``/``ASIA``/``ABIA``/``ACCA``/``A3T``, ``AIza``), plus
     ``Bearer <token>``, ``Basic <token>``, JSON Web Tokens, ``PRIVATE KEY``
     PEM blocks, and the password field of a ``scheme://user:password@host``
     URL.

Plus the EXACT VALUES of the credential environment variables named in
``CREDENTIAL_NAMES`` that are set in this process. Values shorter than
``MIN_VALUE_LENGTH`` are ignored: replacing every occurrence of a
two-character value would shred the surrounding text.

WHAT THIS DOES NOT CATCH -- read this before trusting it
--------------------------------------------------------
Deciding whether an arbitrary string is a secret is undecidable. This is a
filter that removes shapes we know, not a guarantee. Known gaps:

  * A high-entropy value with no recognisable prefix and no adjacent name. A
    bare ``9f3ac1d0e5b74a28...`` on its own line is indistinguishable from a
    hash. There is deliberately no entropy heuristic here, because an entropy
    rule mangles git shas, UUIDs and base64 images -- a redactor that corrupts
    logs stops being used, and that is a worse outcome than this gap.
  * Anything the emitting program transformed: base64- or hex-wrapped
    credentials, a key printed one character per line, a key that was escaped
    into a JSON string, a key inside gzip/zip/tar output, a key rendered into
    an image or a PDF. This module sees bytes, not intent.
  * A secret longer than ``carry`` split across blocks: past that bound the
    leading part is written before the rest arrives. The shipped default puts
    ``carry`` above ``MAX_MATCH``, so this only bites a caller that lowers it.
  * A single match longer than ``max_hold`` (1 MiB): its first ``max_hold``
    characters are redacted and the remainder is re-examined as fresh input,
    so the tail of a PEM body that large would be emitted in clear. Bounded
    memory is chosen over an unbounded hold; the PEM rule's own 16384-character
    limit bites long before this does.
  * ``NAME value`` separated only by whitespace. This is deliberate:
    ``--credential-env CODEX_API_KEY`` and the ``credential_names`` field of a
    Firebreak receipt are the audit trail, and redacting credential IDENTITIES
    would destroy the record of what was granted. Only ``=`` and ``:`` are
    treated as assignment.
  * Credential names outside those shapes -- ``DATABASE_URL``, ``SENTRY_DSN``,
    ``COOKIE``, ``LICENCE`` -- unless the value itself has a known prefix.
  * A token packed directly against alphanumeric text with no separator, such
    as ``...scan complsk-AAAA...`` produced by an interleaved write. Every rule
    is guarded against starting inside a base64 run, and that guard cannot
    distinguish a truncated word from base64. Protecting image blobs and
    encoded payloads from being mangled was judged worth this gap; both
    behaviours are pinned by tests.
  * Anything already recorded elsewhere. This redacts what passes through it.
    It does not scrub files on disk, sqlite rows written before it was wired
    in, or a terminal the user already read.

It also OVER-redacts, which is the intended direction to fail in: ``PRIMARY_KEY
= id``, ``SORT_KEY: name`` and ``LICENSE_KEY=demo`` all lose their values,
because a credential-shaped name is the only signal available.

Redaction is idempotent: running it again over its own output changes nothing.

This is a filter of last resort. The primary control is unchanged: credential
VALUES are injected at the Firebreak boundary and never travel in an
Invocation.
"""
from __future__ import annotations

import codecs
import functools
import os
import re
import sys

__all__ = [
    "PLACEHOLDER",
    "MIN_VALUE_LENGTH",
    "DEFAULT_CARRY",
    "DEFAULT_MAX_HOLD",
    "MAX_MATCH",
    "LEFT_CONTEXT",
    "CREDENTIAL_NAMES",
    "StreamRedactor",
    "credential_values",
    "redact",
    "redact_bytes",
    "rules",
]

#: What replaces a secret. Chosen so that it cannot itself be matched by any
#: rule below -- that is what makes redaction idempotent.
PLACEHOLDER = "[REDACTED]"

#: Exact credential values shorter than this are never struck out literally.
MIN_VALUE_LENGTH = 8

#: The longest text any single rule in the table below can match: the PEM
#: rule's 16384-character body bound plus its BEGIN/END markers. Every other
#: rule is bounded far below this on purpose -- an open-ended quantifier would
#: let one match outgrow the carry window and break the guarantee underneath.
MAX_MATCH = 16384 + 128

#: Characters :class:`StreamRedactor` holds back between blocks. Any secret
#: whose matched text is at most this long is caught at every split offset, so
#: this is deliberately larger than ``MAX_MATCH``: every shape the table can
#: recognise is therefore split-safe, and ``test_redact.py`` asserts the
#: relationship rather than trusting this comment.
DEFAULT_CARRY = MAX_MATCH + 4096

#: Hard ceiling on the held-back tail. A single match longer than this is
#: redacted in pieces rather than buffered without bound.
DEFAULT_MAX_HOLD = 1 << 20

#: Already-emitted characters re-presented to the matcher on each streaming
#: pass, so that a ``(?<!...)`` guard sees the real preceding character instead
#: of a fake start-of-string. The widest lookbehind below is one character;
#: the margin is headroom, not a requirement.
LEFT_CONTEXT = 8

#: Credential identities providers declare. Kept in step with the Firebreak
#: grant list in packages/shadowfetch-fireline/data/usr/bin/shadowfetch-firebreak.
#: SSH_AUTH_SOCK is deliberately absent: it is a socket path, not a secret, and
#: redacting it would remove debugging context for no security benefit.
CREDENTIAL_NAMES = (
    "ANTHROPIC_API_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "CF_API_TOKEN",
    "CLOUDFLARE_API_TOKEN",
    "CODEX_API_KEY",
    "DEEPSEEK_API_KEY",
    "DIGITALOCEAN_TOKEN",
    "DOCKER_PASSWORD",
    "GEMINI_API_KEY",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GITLAB_TOKEN",
    "GOOGLE_API_KEY",
    "GROQ_API_KEY",
    "HF_TOKEN",
    "HUGGING_FACE_HUB_TOKEN",
    "MISTRAL_API_KEY",
    "NPM_TOKEN",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
    "PYPI_TOKEN",
    "XAI_API_KEY",
)

# --------------------------------------------------------------------------- #
# Pattern inventory. One table, so "what does Shadowfetch redact" has exactly
# one answer. Each entry is (id, regex, description). A rule may mark the part
# of its match that is the secret with (?P<S>...); everything else in the match
# is preserved. A rule with no (?P<S>...) has its whole match replaced.
# --------------------------------------------------------------------------- #

# A value-shape rule may not start immediately after a base64 character.
# Standard base64 uses A-Za-z0-9+/ and base64url uses A-Za-z0-9-_, so this one
# guard keeps every prefix rule from firing inside an image blob or an encoded
# payload. Its cost is the "packed against a truncated word" gap documented
# above.
_EDGE = r"(?<![A-Za-z0-9_+/-])"

# A credential-shaped name is recognised by its FINAL word: CODEX_API_KEY,
# api_key, X-Api-Key, password. Only that word is matched -- any prefix stays
# outside the match and is therefore preserved verbatim in the output, which
# is both cheaper (no backtracking over an optional identifier prefix at every
# alphabetic position) and better for debugging.
#
# The guard rejects an alphanumeric, + or / before the word, so MONKEY, TURKEY
# and DONKEY are not read as ...KEY, while the _ and - of a compound name are
# allowed through. A base64 run cannot reach a name rule either: standard
# base64 has no _ or -, and inside a base64url blob the character after a name
# would have to be "=", which only appears as terminal padding.
_NAME_WORD = (r"(?:TOKEN|KEY|APIKEY|SECRET|PASSWORD|PASSWD|PASSPHRASE"
              r"|CREDENTIAL|CREDENTIALS|AUTHORIZATION)")
_NAME = r"(?<![A-Za-z0-9+/])" + _NAME_WORD

# Between a name and its value: an optional closing quote on the name, then
# = or :, then whitespace. The opening quote of the value is handled per rule.
_ASSIGN = r"[\"']?\s*[:=]\s*"

# An unquoted value stops at whitespace, at a structural character, and at a
# square bracket. Excluding brackets is what makes the bare rule idempotent:
# it cannot re-match the "[REDACTED]" it just wrote.
_BARE_VALUE = r"[^\s\"',;)(\]\[}{<>\r\n]{1,2048}"

_RULES: tuple = (
    (
        "private_key_block",
        r"-----BEGIN[ A-Z]{0,40}PRIVATE KEY-----[\s\S]{0,16384}?"
        r"(?:-----END[ A-Z]{0,40}PRIVATE KEY-----|\Z)",
        "PEM private key block, including one truncated by the end of the stream",
    ),
    (
        "jwt",
        _EDGE + r"eyJ[A-Za-z0-9_-]{6,1024}\.[A-Za-z0-9_-]{4,1024}\.[A-Za-z0-9_-]{0,1024}",
        "JSON Web Token (base64url header.payload.signature)",
    ),
    (
        "authorization_header",
        r"(?<![A-Za-z0-9+/])(?i:authorization)" + _ASSIGN
        + r"(?i:(?:Bearer|Basic|Digest|Token|ApiKey|Negotiate)\s+)?"
        + r"(?P<S>[^\s\"'\r\n]{1,2048})",
        "Authorization header credential, keeping the auth scheme keyword",
    ),
    (
        "http_auth_scheme",
        _EDGE + r"(?i:(?:Bearer|Basic|Token)\s+)(?P<S>[A-Za-z0-9._~+/=-]{8,2048})",
        "Credential following a Bearer / Basic / Token auth scheme keyword",
    ),
    (
        "named_value_quoted",
        r"(?i:" + _NAME + r")" + _ASSIGN + r"\"(?P<S>[^\"\r\n]{1,2048})\"",
        "Double-quoted value of a credential-shaped name (JSON)",
    ),
    (
        "named_value_single_quoted",
        r"(?i:" + _NAME + r")" + _ASSIGN + r"'(?P<S>[^'\r\n]{1,2048})'",
        "Single-quoted value of a credential-shaped name",
    ),
    (
        "named_value_bare",
        r"(?i:" + _NAME + r")" + _ASSIGN + r"(?P<S>" + _BARE_VALUE + r")",
        "Unquoted value of a credential-shaped name (env dumps, shell traces)",
    ),
    (
        "url_userinfo",
        _EDGE + r"(?i:[a-z][a-z0-9+.-]{1,20}://[^\s/@:]{1,256}:)"
        r"(?P<S>[^\s/@]{1,256})(?=@)",
        "Password field of a scheme://user:password@host URL",
    ),
    (
        "openai_family",
        _EDGE + r"sk-(?P<S>[A-Za-z0-9_-]{12,512})",
        "OpenAI / Anthropic / OpenRouter sk- key (covers sk-proj-, sk-ant-, sk-or-v1-)",
    ),
    (
        "stripe",
        _EDGE + r"sk_(?:live|test)_(?P<S>[A-Za-z0-9]{16,512})",
        "Stripe secret key",
    ),
    (
        "xai",
        _EDGE + r"xai-(?P<S>[A-Za-z0-9_-]{12,512})",
        "xAI key",
    ),
    (
        "groq",
        _EDGE + r"gsk_(?P<S>[A-Za-z0-9]{20,512})",
        "Groq key",
    ),
    (
        "github_token",
        _EDGE + r"gh[pousr]_(?P<S>[A-Za-z0-9]{16,512})",
        "GitHub personal / OAuth / user / server / refresh token",
    ),
    (
        "github_pat",
        _EDGE + r"github_pat_(?P<S>[A-Za-z0-9_]{20,512})",
        "GitHub fine-grained personal access token",
    ),
    (
        "gitlab_pat",
        _EDGE + r"glpat-(?P<S>[A-Za-z0-9_-]{16,512})",
        "GitLab personal access token",
    ),
    (
        "huggingface",
        _EDGE + r"hf_(?P<S>[A-Za-z0-9]{20,512})",
        "Hugging Face token",
    ),
    (
        "cloudflare_user_token",
        _EDGE + r"cfut_(?P<S>[A-Za-z0-9_-]{16,512})",
        "Cloudflare user API token",
    ),
    (
        "npm",
        _EDGE + r"npm_(?P<S>[A-Za-z0-9]{30,512})",
        "npm automation token",
    ),
    (
        "pypi",
        _EDGE + r"pypi-(?P<S>[A-Za-z0-9_-]{16,512})",
        "PyPI upload token",
    ),
    (
        "digitalocean",
        _EDGE + r"dop_v1_(?P<S>[A-Fa-f0-9]{64})",
        "DigitalOcean personal access token",
    ),
    (
        "slack_token",
        _EDGE + r"xox[abeprs]-(?P<S>[A-Za-z0-9-]{10,512})",
        "Slack bot / user / app / refresh token",
    ),
    (
        "slack_app_token",
        _EDGE + r"xapp-(?P<S>[0-9A-Za-z-]{10,512})",
        "Slack app-level token",
    ),
    (
        "aws_access_key_id",
        _EDGE + r"(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16}",
        "AWS access key id",
    ),
    (
        "google_api_key",
        _EDGE + r"AIza[A-Za-z0-9_-]{35}",
        "Google API key",
    ),
)


def rules() -> tuple:
    """The pattern inventory as ``(id, description)`` pairs, for docs and tests."""
    return tuple((identifier, description) for identifier, _, description in _RULES)


# --------------------------------------------------------------------------- #
# Compilation
# --------------------------------------------------------------------------- #

def _rule_source(index: int, source: str) -> str:
    """Give this rule's ``S`` group a pattern-unique name."""
    return "(?:" + source.replace("(?P<S>", f"(?P<s_{index}>") + ")"


@functools.lru_cache(maxsize=8)
def _compiled(values: tuple):
    """Build the combined pattern for this set of exact credential values.

    Cached because the executor calls this once per 64 KiB block. The cache
    retains the credential values in memory, which is no worse than the
    environment they were read from, and it is bounded to 8 entries.
    """
    parts = ["(?:" + re.escape(value) + ")" for value in values]
    parts += [_rule_source(index, source)
              for index, (_, source, _) in enumerate(_RULES)]
    pattern = re.compile("|".join(parts))
    secret_groups = tuple(name for name in pattern.groupindex if name.startswith("s_"))
    return pattern, secret_groups


def credential_values(env=None, names=None) -> tuple:
    """Exact secret values to strike out, longest first.

    Reads ``CREDENTIAL_NAMES`` from ``env`` (default ``os.environ``). Values
    shorter than ``MIN_VALUE_LENGTH`` are skipped; see the module docstring.
    """
    environment = os.environ if env is None else env
    wanted = CREDENTIAL_NAMES if names is None else tuple(names)
    found = {environment[name] for name in wanted
             if environment.get(name) and len(environment[name]) >= MIN_VALUE_LENGTH}
    return tuple(sorted(found, key=lambda item: (-len(item), item)))


def _resolve(values) -> tuple:
    if values is None:
        return credential_values()
    chosen = {str(value) for value in values
              if value and len(str(value)) >= MIN_VALUE_LENGTH}
    return tuple(sorted(chosen, key=lambda item: (-len(item), item)))


def _rewrite(match, secret_groups, placeholder: str) -> str:
    """Replace only the secret span of this match, keeping its context."""
    whole = match.group(0)
    base = match.start()
    for name in secret_groups:
        start, end = match.span(name)
        if start >= 0:
            return whole[:start - base] + placeholder + whole[end - base:]
    return placeholder


# --------------------------------------------------------------------------- #
# One-shot
# --------------------------------------------------------------------------- #

def redact(text, *, values=None, placeholder: str = PLACEHOLDER) -> str:
    """Redact a complete string. Accepts any object; coerces with ``str()``.

    This is the drop-in replacement for a per-message ``clean()``. For output
    that arrives in blocks use :class:`StreamRedactor` instead: this function
    cannot see a secret split across two calls.
    """
    if not isinstance(text, str):
        text = str(text)
    if not text:
        return text
    pattern, secret_groups = _compiled(_resolve(values))
    return pattern.sub(lambda m: _rewrite(m, secret_groups, placeholder), text)


def redact_bytes(data: bytes, *, values=None, placeholder: str = PLACEHOLDER,
                 errors: str = "replace") -> bytes:
    """Redact complete bytes: decode UTF-8 with ``errors``, redact, re-encode."""
    return redact(data.decode("utf-8", errors), values=values,
                  placeholder=placeholder).encode("utf-8")


# --------------------------------------------------------------------------- #
# Streaming
# --------------------------------------------------------------------------- #

class StreamRedactor:
    """Redact output that arrives in blocks, without leaking across boundaries.

    Usage::

        redactor = StreamRedactor()
        while block := os.read(fd, 65536):
            stream.write(redactor.feed_bytes(block))
        stream.write(redactor.flush_bytes())

    ``feed`` returns only the prefix it can prove is complete: it holds back at
    least ``carry`` characters, and when a match straddles that boundary it
    holds back from the start of that match instead. ``flush`` returns the
    remainder and resets the instance.

    Always flush. Whatever is not flushed is never returned, so a caller that
    forgets loses the last ``carry`` characters of the log.
    """

    def __init__(self, values=None, *, placeholder: str = PLACEHOLDER,
                 carry: int = DEFAULT_CARRY, max_hold: int = DEFAULT_MAX_HOLD):
        if carry < 1:
            raise ValueError("carry must be at least 1 character")
        if max_hold < carry:
            raise ValueError("max_hold must be at least carry")
        self.placeholder = placeholder
        self.carry = carry
        self.max_hold = max_hold
        self.values = _resolve(values)
        self._pattern, self._secret_groups = _compiled(self.values)
        self._left = ""
        self._tail = ""
        self._decoder = codecs.getincrementaldecoder("utf-8")("replace")

    # -- text ------------------------------------------------------------- #

    def feed(self, chunk: str) -> str:
        """Absorb one block; return the part that is safe to emit now."""
        if chunk:
            self._tail += chunk
        if len(self._tail) <= self.carry:
            return ""
        buf = self._left + self._tail
        origin = len(self._left)
        emitted, cut = self._scan(buf, origin, len(buf) - self.carry)
        if len(buf) - cut > self.max_hold:
            # One match is longer than the hold budget. Redacting it now costs
            # a split marker in the log, but memory stays bounded and the value
            # itself still never reaches the output.
            emitted, cut = self._scan(buf, origin, len(buf))
        self._left = buf[max(0, cut - LEFT_CONTEXT):cut]
        self._tail = buf[cut:]
        return emitted

    def flush(self) -> str:
        """Return everything still held, redacted, and reset the instance."""
        buf = self._left + self._tail + self._decoder.decode(b"", True)
        origin = len(self._left)
        self._left = ""
        self._tail = ""
        self._decoder = codecs.getincrementaldecoder("utf-8")("replace")
        if len(buf) <= origin:
            return ""
        emitted, _ = self._scan(buf, origin, len(buf))
        return emitted

    # -- bytes ------------------------------------------------------------ #

    def feed_bytes(self, block: bytes) -> bytes:
        """``feed`` for byte blocks, driving an incremental UTF-8 decoder.

        A multi-byte character split across two reads is reassembled rather
        than turned into two replacement characters.
        """
        return self.feed(self._decoder.decode(block)).encode("utf-8")

    def flush_bytes(self) -> bytes:
        return self.flush().encode("utf-8")

    # -- internals -------------------------------------------------------- #

    def _scan(self, buf: str, origin: int, limit: int):
        """Redact ``buf[origin:cut]`` where no match crosses ``cut``.

        ``buf[:origin]`` is ``LEFT_CONTEXT`` characters that were already
        emitted. Matching starts at ``origin``, but the characters before it
        stay in the string on purpose: ``finditer(buf, origin)`` still
        evaluates a ``(?<!...)`` guard against the real preceding character
        (while ``\\A`` correctly refuses to match at ``origin``). Scanning a
        bare tail instead would make every guard succeed at offset 0, and
        ``...TUR`` + ``KEY=roast`` would be redacted when the one-shot path
        leaves it alone.

        Returns ``(emitted, cut)`` with ``origin <= cut <= limit``. When a match
        ends after ``limit`` the cut is pulled back to that match's start, so a
        partially-seen secret is held rather than emitted in fragments.
        """
        out = []
        pos = origin
        cut = limit
        for match in self._pattern.finditer(buf, origin):
            if match.end() > limit:
                # finditer yields non-overlapping matches in order, so every
                # later match starts at or after this one's end -- also past
                # the limit. Nothing from here on can be emitted yet.
                cut = min(cut, match.start())
                break
            out.append(buf[pos:match.start()])
            out.append(_rewrite(match, self._secret_groups, self.placeholder))
            pos = match.end()
        if pos < cut:
            out.append(buf[pos:cut])
        return "".join(out), cut


# --------------------------------------------------------------------------- #
# Filter mode: python3 sf_redact.py < noisy.log > safe.log
# --------------------------------------------------------------------------- #

def _main(argv=None) -> int:
    redactor = StreamRedactor()
    reader, writer = sys.stdin.buffer, sys.stdout.buffer
    while True:
        block = reader.read(65536)
        if not block:
            break
        writer.write(redactor.feed_bytes(block))
    writer.write(redactor.flush_bytes())
    writer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
