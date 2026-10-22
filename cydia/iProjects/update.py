#!/usr/bin/env python3
import bz2
import gzip
import hashlib
import io
import lzma
import os
import tarfile
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
DEBS = os.path.join(ROOT, "debs")

RELEASE = {
    "Origin": "iProjects",
    "Label": "iProjects",
    "Suite": "stable",
    "Version": "1.0",
    "Codename": "iprojects",
    "Architectures": "iphoneos-arm",
    "Components": "main",
    "Description": "Revivals and fixes for legacy iOS devices",
}


def ar_members(data):
    if data[:8] != b"!<arch>\n":
        raise ValueError("not a deb")
    pos = 8
    while pos + 60 <= len(data):
        header = data[pos:pos + 60]
        name = header[:16].decode().strip().rstrip("/")
        size = int(header[48:58].decode().strip())
        yield name, data[pos + 60:pos + 60 + size]
        pos += 60 + size + (size % 2)


def control_of(path):
    data = open(path, "rb").read()
    for name, blob in ar_members(data):
        if not name.startswith("control.tar"):
            continue
        if name.endswith(".gz"):
            blob = gzip.decompress(blob)
        elif name.endswith(".xz") or name.endswith(".lzma"):
            blob = lzma.decompress(blob)
        elif name.endswith(".bz2"):
            blob = bz2.decompress(blob)
        with tarfile.open(fileobj=io.BytesIO(blob)) as tar:
            for member in tar.getmembers():
                if member.name.lstrip("./") == "control":
                    return tar.extractfile(member).read().decode("utf-8"), data
    raise ValueError("no control file in " + path)


def stanza(path):
    text, data = control_of(path)
    lines = [l for l in text.rstrip("\n").split("\n") if l.strip()]
    lines.append("Filename: debs/" + os.path.basename(path))
    lines.append("Size: %d" % len(data))
    lines.append("MD5sum: " + hashlib.md5(data).hexdigest())
    lines.append("SHA1: " + hashlib.sha1(data).hexdigest())
    lines.append("SHA256: " + hashlib.sha256(data).hexdigest())
    return "\n".join(lines) + "\n"


def write(name, data):
    with open(os.path.join(ROOT, name), "wb") as f:
        f.write(data)
    return data


def main():
    debs = sorted(f for f in os.listdir(DEBS) if f.endswith(".deb") and not f.startswith("."))
    packages = "\n".join(stanza(os.path.join(DEBS, f)) for f in debs).encode("utf-8")
    files = {
        "Packages": write("Packages", packages),
        "Packages.gz": write("Packages.gz", gzip.compress(packages, mtime=0)),
        "Packages.bz2": write("Packages.bz2", bz2.compress(packages)),
    }
    release = ["%s: %s" % kv for kv in RELEASE.items()]
    release.append("Date: " + time.strftime("%a, %d %b %Y %H:%M:%S UTC", time.gmtime()))
    for field, algo in (("MD5Sum", hashlib.md5), ("SHA1", hashlib.sha1), ("SHA256", hashlib.sha256)):
        release.append(field + ":")
        for name, data in files.items():
            release.append(" %s %d %s" % (algo(data).hexdigest(), len(data), name))
    write("Release", ("\n".join(release) + "\n").encode("utf-8"))
    print("%d packages" % len(debs))
    for f in debs:
        print("  " + f)


if __name__ == "__main__":
    main()
