"""Release boundaries for the separately packaged KDE pickup correction."""

import hashlib
from pathlib import PurePosixPath

PACKAGE = "shadowfetch-drkonqi-pickup"
VERSION = "4.0.0-1"
UPSTREAM_VERSION = "6.6.5-3"
HELPER = "usr/libexec/shadowfetch-drkonqi-pickup"
DROPIN = "usr/lib/systemd/user/drkonqi-coredump-pickup.service.d/10-shadowfetch-pickup.conf"
UPSTREAM_PROCESSOR = "usr/lib/x86_64-linux-gnu/libexec/drkonqi-coredump-processor"

# KDE v6.6.5 service templates, with only KDE_INSTALL_FULL_LIBEXECDIR replaced
# by Debian's /usr/lib/x86_64-linux-gnu/libexec. These vendor units stay intact.
UPSTREAM_UNITS = {
    "usr/lib/systemd/user/drkonqi-coredump-pickup.service":
        "949c6801f654eada93e57a235bae75cdec23f7ef23ff8d5b427fc34bb14de206",
    "usr/lib/systemd/system/drkonqi-coredump-processor@.service":
        "a87bdd8f364620d8be753b29a1bed96a8d398050f8a182222a2db7627047280c",
}


def validate_dropin(content: str) -> None:
    lines = [line.strip() for line in content.splitlines()
             if line.strip() and not line.lstrip().startswith(("#", ";"))]
    expected = ["[Service]", "ExecStart=",
                f"ExecStart=/{HELPER} --settle-first --pickup --uid %U"]
    if lines != expected:
        raise RuntimeError("DrKonqi correction must override only pickup ExecStart")


def validate_package_paths(paths) -> None:
    for path in paths:
        if PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts:
            raise RuntimeError("Pickup package path is not relative and contained: " + path)
        if path not in (HELPER, DROPIN, "usr/share/lintian/overrides/" + PACKAGE) and not path.startswith(
                "usr/share/doc/" + PACKAGE + "/"):
            raise RuntimeError("Pickup package owns a path outside its narrow scope: " + path)


def validate_upstream_unit(path: str, content: bytes) -> None:
    if hashlib.sha256(content).hexdigest() != UPSTREAM_UNITS[path]:
        raise RuntimeError("Upstream DrKonqi unit was changed: " + path)
