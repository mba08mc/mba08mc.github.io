#!/usr/bin/env python
"""Rebuild a flat Cydia repo index (Packages, Packages.bz2, Packages.gz).

Drop .deb files into debs/, then run from anywhere:

    python3 update_repo.py            (repo = folder this script is in)
    python  update_repo.py /path/to/repo

Works on Python 2.6+ and 3.x (Snow Leopard's python or a modern Mac's).
Reads each deb's control file directly; no dpkg needed. Release is left
alone apart from creating a default one if it's missing.
"""
import bz2, gzip, hashlib, io, os, subprocess, sys, tarfile, zlib

PY3 = sys.version_info[0] >= 3

FIELD_ORDER = ["Package", "Version", "Architecture", "Maintainer", "Installed-Size",
               "Pre-Depends", "Depends", "Recommends", "Suggests", "Conflicts",
               "Breaks", "Replaces", "Provides"]
INDEX_FIELDS = ["Filename", "Size", "MD5sum", "SHA1", "SHA256"]

DEFAULT_RELEASE = """Origin: iPhoneOS 2
Label: iPhoneOS 2 Repository
Suite: stable
Version: 1.0
Architectures: iphoneos-arm
Components: main
Description: iPhoneOS 2 like it's 2008 again!
"""


def text(b):
    return b.decode("utf-8", "replace") if PY3 else b


def ar_members(data):
    if data[:8] != b"!<arch>\n":
        raise ValueError("not an ar archive")
    pos, out = 8, {}
    while pos + 60 <= len(data):
        hdr = data[pos:pos + 60]
        name = hdr[:16].decode("ascii").strip().rstrip("/")
        size = int(hdr[48:58].decode("ascii").strip())
        out[name] = data[pos + 60:pos + 60 + size]
        pos += 60 + size + (size & 1)
    return out


def unxz(blob):
    try:
        import lzma
        return lzma.decompress(blob)
    except ImportError:
        pass
    for tool in ("xz", "/opt/local/bin/xz", "/usr/local/bin/xz", "/opt/homebrew/bin/xz"):
        try:
            p = subprocess.Popen([tool, "-dc"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            out = p.communicate(blob)[0]
            if p.returncode == 0:
                return out
        except OSError:
            pass
    raise ValueError("needs xz to read this deb (use python3, or install xz)")


def control_text(path):
    f = open(path, "rb")
    data = f.read()
    f.close()
    members = ar_members(data)
    for name in members:
        if not name.startswith("control.tar"):
            continue
        blob = members[name]
        if name.endswith(".gz"):
            blob = zlib.decompress(blob, 16 + zlib.MAX_WBITS)
        elif name.endswith(".bz2"):
            blob = bz2.decompress(blob)
        elif name.endswith(".xz") or name.endswith(".lzma"):
            blob = unxz(blob)
        tf = tarfile.open(fileobj=io.BytesIO(blob))
        for m in tf.getmembers():
            if m.isfile() and m.name.lstrip("./") == "control":
                return text(tf.extractfile(m).read()), data
    raise ValueError("no control file inside")


def parse_control(s):
    fields, order, last = {}, [], None
    for line in s.replace("\r\n", "\n").split("\n"):
        line = line.rstrip()
        if not line:
            continue
        if line[0] in " \t" and last:
            fields[last] += "\n" + line
        elif ":" in line:
            k, v = line.split(":", 1)
            k = k.strip()
            if k not in fields:
                order.append(k)
            fields[k] = v.strip()
            last = k
    return fields, order


def stanza(fields, order, rel, data):
    fields = dict(fields)
    fields["Filename"] = "./" + rel
    fields["Size"] = str(len(data))
    fields["MD5sum"] = hashlib.md5(data).hexdigest()
    fields["SHA1"] = hashlib.sha1(data).hexdigest()
    fields["SHA256"] = hashlib.sha256(data).hexdigest()
    keys = [k for k in FIELD_ORDER if k in fields] + INDEX_FIELDS
    keys += [k for k in order if k not in keys]
    return "".join("%s: %s\n" % (k, fields[k]) for k in keys)


def old_stanzas(repo):
    """Old Packages entries by MD5, used when a deb can't be read here."""
    out = {}
    try:
        f = open(os.path.join(repo, "Packages"), "rb")
        s = text(f.read())
        f.close()
    except IOError:
        return out
    for block in s.split("\n\n"):
        fields, order = parse_control(block)
        if "MD5sum" in fields:
            out[fields["MD5sum"]] = block.strip("\n") + "\n"
    return out


def write(path, data):
    f = open(path, "wb")
    f.write(data)
    f.close()


def main():
    repo = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__)))
    debdir = os.path.join(repo, "debs")
    if not os.path.isdir(debdir):
        sys.exit("No debs/ folder in " + repo)
    previous = old_stanzas(repo)
    entries, problems = [], 0
    for name in sorted(os.listdir(debdir), key=lambda n: n.lower()):
        if not name.endswith(".deb") or name.startswith("."):
            continue
        path = os.path.join(debdir, name)
        rel = "debs/" + name
        try:
            ctl, data = control_text(path)
            fields, order = parse_control(ctl)
            if "Package" not in fields:
                raise ValueError("control has no Package field")
            entries.append((fields["Package"].lower(), fields.get("Version", ""), stanza(fields, order, rel, data)))
            print("  ok   %-45s %s %s" % (name, fields["Package"], fields.get("Version", "")))
        except Exception:
            err = sys.exc_info()[1]
            f = open(path, "rb")
            md5 = hashlib.md5(f.read()).hexdigest()
            f.close()
            if md5 in previous:
                entries.append((name.lower(), "", previous[md5]))
                print("  kept %-45s (unchanged; %s)" % (name, err))
            else:
                problems += 1
                print("  FAIL %-45s %s" % (name, err))
    entries.sort()
    packages = "\n".join(e[2] for e in entries) + "\n"
    raw = packages.encode("utf-8")
    write(os.path.join(repo, "Packages"), raw)
    write(os.path.join(repo, "Packages.bz2"), bz2.compress(raw, 9))
    gz = gzip.GzipFile(os.path.join(repo, "Packages.gz"), "wb", 9)
    gz.write(raw)
    gz.close()
    if not os.path.exists(os.path.join(repo, "Release")):
        write(os.path.join(repo, "Release"), DEFAULT_RELEASE.encode("utf-8"))
    print("%d package(s) indexed in %s" % (len(entries), repo))
    if problems:
        sys.exit("%d deb(s) left out, see FAIL lines above" % problems)


if __name__ == "__main__":
    main()
