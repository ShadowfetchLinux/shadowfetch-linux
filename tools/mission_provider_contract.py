"""Shared source/package/ISO contract for the deferred local-AI release."""
import ast
import re

REMOVED_AI_PATH = re.compile(
    r"^(?:usr/bin/(?:shadowfetch-(?:buzz(?:-[^/]+)?|model-check|ai-ignition)|buzz(?:-desktop)?)$|"
    r"usr/libexec/shadowfetch-buzz(?:-[^/]+)?$|"
    r"usr/lib/systemd/user/shadowfetch-buzz[^/]*$|"
    r"usr/share/applications/shadowfetch-buzz\.desktop$|"
    r"usr/share/shadowfetch/(?:buzz|ai-ignition)(?:/|$)|"
    r"usr/lib/shadowfetch/missions/sf_local_compute\.py$|"
    r"usr/share/shadowfetch/control-center/sfcc/(?:local_model_card|local_ai_page)\.py$)"
)


def validate_provider_payload(paths, mission_source):
    retired = sorted(path for path in paths if REMOVED_AI_PATH.search(path))
    if retired:
        raise RuntimeError("Deferred local-AI payload remains: " + ", ".join(retired))
    tree = ast.parse(mission_source)
    capability = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "capabilities")
    value = next(node.value for node in capability.body if isinstance(node, ast.Return))
    fields = {ast.literal_eval(k): v for k, v in zip(value.keys, value.values)}
    runtimes = {ast.literal_eval(k): v for k, v in zip(fields["runtimes"].keys, fields["runtimes"].values)}
    if set(runtimes) != {"codex", "offline"} or ast.literal_eval(fields["local_ai"]) != "deferred":
        raise RuntimeError("Mission capabilities advertise a removed or unsupported provider")
    for runtime, kinds in (("codex", ["code", "report"]), ("offline", ["media"])):
        fields = {ast.literal_eval(k): v for k, v in zip(runtimes[runtime].keys, runtimes[runtime].values)}
        if ast.literal_eval(fields["kinds"]) != kinds:
            raise RuntimeError("Mission provider/kind contract differs: " + runtime)
        if ast.literal_eval(fields["requires_network_approval"]) != (runtime == "codex"):
            raise RuntimeError("Mission provider network consent contract differs: " + runtime)
    if "sf_local_compute" in mission_source:
        raise RuntimeError("Mission backend still loads the removed local provider")
