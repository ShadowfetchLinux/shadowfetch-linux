The first five JSONL fixtures preserve message text and logger identifiers from
the completed mq-deadline development journal, lines 201, 288, 293, 294 and 82.
The original journal SHA256 is
`f62a73c4e23de2b2f11c83c842df4b7b6b9708e1a16ecb10a82efa069e446c24`.
Host names, PIDs and the human journal prefix were removed; these wrappers are
fixtures, not a claim that the original capture used journalctl JSON output.
They include three actual admission timeouts, the `/query` response503 and a
Redis AOF fsync-delay message.
The three admission timeouts and HTTP503 are hard service faults. The AOF-only
record is retained and counted as disk-latency telemetry; it cannot establish a
failed client request by itself. These criteria apply to the new canonical QA
helper and do not rewrite prior diagnostic or raw helper results.

The sixth fixture uses the actual guest-agent command-log prefix and metadata
from the prior v2 observation, with its long QA search program reduced to its
pattern line. It is a negative control: the echoed pattern is observer input,
not an actual failed service. Complete original raw evidence remains preserved
separately; these tests do not constitute workload or release acceptance.
