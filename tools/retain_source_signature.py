#!/usr/bin/env python3
"""Retain a published DSC only when its signed contents and source bytes match."""
import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess

FINGERPRINT = "8F13CE1535EE1F4A2916A1F73C5C900B7BE80CA1"

def verified_body(path):
    result = subprocess.run(["gpg", "--batch", "--status-fd", "2", "--decrypt", str(path)], capture_output=True, check=True)
    if f"[GNUPG:] VALIDSIG {FINGERPRINT} ".encode() not in result.stderr:
        raise ValueError("DSC does not carry the official release signature")
    return result.stdout

def retain(candidate, published):
    current = verified_body(candidate)
    if current != verified_body(published):
        raise ValueError("Published source description differs; bump the package version")
    section = False
    checked = 0
    for line in current.decode().splitlines():
        if line == "Checksums-Sha256:":
            section = True
            continue
        if not line.startswith(" "):
            section = False
        if section:
            checksum, size, name = line.split()
            if Path(name).name != name:
                raise ValueError("Source archive path is not a basename")
            archive = candidate.parent / name
            if archive.is_symlink() or not archive.is_file() or archive.stat().st_size != int(size):
                raise ValueError("Source archive differs: " + name)
            with archive.open("rb") as stream:
                if hashlib.file_digest(stream, "sha256").hexdigest() != checksum:
                    raise ValueError("Source archive hash differs: " + name)
            checked += 1
    if not checked:
        raise ValueError("Source description contains no SHA256 archive entries")
    shutil.copyfile(published, candidate)
    print(f"RETAINED_PUBLISHED_SOURCE_SIGNATURE {candidate.name} archives={checked}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("published", type=Path)
    args = parser.parse_args()
    retain(args.candidate, args.published)
