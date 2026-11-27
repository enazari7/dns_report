#!/usr/bin/env python3
"""Build the single-file self-extracting installer (install.py).

The dashboard normally ships as a directory, but transferring a directory (or
a .tar.gz) with a Windows SFTP client that is in text mode corrupts it. A .py
file survives that: Python does not care about CRLF, and the embedded payload
is base64, which we whitespace-strip before decoding. A SHA-256 check turns a
mangled transfer into a clear message instead of a confusing failure.
"""

import base64
import hashlib
import io
import os
import sys
import zipfile

# tools/ lives at the repo root, so the project is one level up.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "install.py")

# The repo uses a src/ layout, but the installer drops a plain importable
# package next to the venv. Map src/smartdns_dash/** -> smartdns_dash/** in the
# payload so the deployed tree needs no packaging machinery at all.
PACKAGE_SRC = os.path.join(ROOT, "src", "smartdns_dash")

SKIP_DIRS = {"__pycache__", ".git", "venv", ".venv", ".mypy_cache",
             ".pytest_cache", ".ruff_cache"}
SKIP_NAMES = {".DS_Store"}

# Repo files that ship inside the payload, mapped to their path in the
# deployed tree. deploy/install.sh is included for reference; install.py
# supersedes it.
EXTRA_FILES = {
    "requirements.txt": "requirements.txt",
    "config.example.ini": "config.example.ini",
    "README.md": "README.md",
    "LICENSE": "LICENSE",
    "pyproject.toml": "pyproject.toml",
    "deploy/smartdns-dashboard.service": "smartdns-dashboard.service",
    "deploy/install.sh": "install.sh",
}


def build_zip() -> bytes:
    buf = io.BytesIO()
    n = 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for root, dirs, files in os.walk(PACKAGE_SRC):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            rel_root = os.path.relpath(root, PACKAGE_SRC)
            for name in sorted(files):
                if name in SKIP_NAMES or name.endswith(".pyc"):
                    continue
                rel = os.path.normpath(os.path.join("smartdns_dash",
                                                    rel_root, name))
                z.write(os.path.join(root, name), rel.replace(os.sep, "/"))
                n += 1
        for src_rel, dst_rel in sorted(EXTRA_FILES.items()):
            src = os.path.join(ROOT, src_rel)
            if os.path.exists(src):
                z.write(src, dst_rel)
                n += 1
            else:
                print(f"  note: {src_rel} not found, skipping")
    print(f"  packed {n} files")
    return buf.getvalue()


def main() -> int:
    if not os.path.isdir(PACKAGE_SRC):
        print(f"package not found: {PACKAGE_SRC}", file=sys.stderr)
        return 1
    print("Building payload...")
    blob = build_zip()
    digest = hashlib.sha256(blob).hexdigest()
    b64 = base64.b64encode(blob).decode("ascii")
    wrapped = "\n".join(b64[i:i + 76] for i in range(0, len(b64), 76))

    tmpl_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "installer_template.py")
    with open(tmpl_path, encoding="utf-8") as fh:
        tmpl = fh.read()

    out = (tmpl
           .replace("@@PAYLOAD_SHA256@@", digest)
           .replace("@@PAYLOAD_SIZE@@", str(len(blob)))
           .replace("@@PAYLOAD@@", wrapped))

    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(out)
    os.chmod(OUT, 0o755)
    print(f"  zip      {len(blob):,} bytes")
    print(f"  sha256   {digest}")
    print(f"  wrote    {OUT} ({os.path.getsize(OUT):,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
