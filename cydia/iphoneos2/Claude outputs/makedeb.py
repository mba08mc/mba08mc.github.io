#!/usr/bin/env python
# Builds the Cydia package for mailtls (works with the Python 2.6 that ships with Snow Leopard).
# Everything is owned by root:wheel inside the package, which launchd insists on.
import gzip, io, os, sys, tarfile, time

VERSION = "1.2"
PKG = "com.claudeclassic.mailtls"

# (name, local port, server, server port, extra mailtls flags)
SERVICES = [
    ("gmail-imap",  1143, "imap.gmail.com",      993, []),
    ("gmail-smtp",  1465, "smtp.gmail.com",      465, []),
    ("icloud-imap", 2143, "imap.mail.me.com",    993, []),
    ("icloud-smtp", 2587, "smtp.mail.me.com",    587, ["-s"]),
    ("yahoo-imap",  3143, "imap.mail.yahoo.com", 993, []),
    ("yahoo-smtp",  3465, "smtp.mail.yahoo.com", 465, []),
    ("aol-imap",    4143, "imap.aol.com",        993, []),
    ("aol-smtp",    4465, "smtp.aol.com",        465, []),
]

CONTROL = """Package: %s
Name: MailTLS
Version: %s
Architecture: iphoneos-arm
Section: Networking
Maintainer: Bilal Ahmed
Author: ClaudeClassic
Description: Lets Mail on iPhone OS 2 reach Gmail, iCloud, Yahoo and AOL again.
 Mail connects to 127.0.0.1 in plain text and MailTLS forwards the connection
 to the real server over TLS 1.2. Started on demand by launchd, so it uses no
 battery while Mail is idle. See /usr/share/mailtls/README.txt for setup.
""" % (PKG, VERSION)

README = """MailTLS %s

Set each account up in Settings > Mail > Add Account > Other, with SSL OFF and
these servers (Advanced > Server Port). User name is your full address; for
Gmail, Yahoo, AOL and iCloud the password must be an app password.

  Gmail    incoming 127.0.0.1 port 1143    outgoing 127.0.0.1 port 1465
  iCloud   incoming 127.0.0.1 port 2143    outgoing 127.0.0.1 port 2587
  Yahoo    incoming 127.0.0.1 port 3143    outgoing 127.0.0.1 port 3465
  AOL      incoming 127.0.0.1 port 4143    outgoing 127.0.0.1 port 4465

Outlook.com / Hotmail / Live can't work: Microsoft only accepts OAuth sign-in
for IMAP and SMTP now, which iPhone OS 2's Mail doesn't support.

Plain text only travels inside the phone; everything that leaves it is TLS 1.2
with the server's certificate checked against /usr/share/mailtls/cacert.pem.

Problems are logged to syslog (tag "mailtls"). If they mention certificate
dates, set the phone's date and time correctly.

To see exactly what happens on a connection (passwords are blanked out):
  touch /tmp/mailtls-debug      then try in Mail, then:  cat /tmp/mailtls.log
  rm /tmp/mailtls-debug /tmp/mailtls.log     when you're done

Another provider: copy one of /Library/LaunchDaemons/%s.*.plist, change the
Label, the port after -l and the server, then: launchctl load <file>
(add "-s" before the server for SMTP servers that only offer STARTTLS on 587).
""" % (VERSION, PKG)

PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%(label)s</string>
	<key>ProgramArguments</key>
	<array>
%(args)s	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>10</integer>
</dict>
</plist>
"""

POSTINST = """#!/bin/sh
for f in /Library/LaunchDaemons/%(pkg)s.*.plist; do
    launchctl unload "$f" 2>/dev/null
    launchctl load "$f"
done
exit 0
""" % {"pkg": PKG}

PRERM = """#!/bin/sh
for f in /Library/LaunchDaemons/%(pkg)s.*.plist; do
    launchctl unload "$f" 2>/dev/null
done
exit 0
""" % {"pkg": PKG}


def tar_bytes(entries):
    """entries: list of (path, mode, bytes or None for a directory)"""
    buf = io.BytesIO()
    gz = gzip.GzipFile(filename="", mode="wb", fileobj=buf)   # (no mtime arg: Python 2.6)
    t = tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT)
    for path, mode, data in entries:
        ti = tarfile.TarInfo(path)
        ti.uid = ti.gid = 0
        ti.uname, ti.gname = "root", "wheel"
        ti.mtime = int(time.time())
        ti.mode = mode
        if data is None:
            ti.type = tarfile.DIRTYPE
            t.addfile(ti)
        else:
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    t.close()
    gz.close()
    return buf.getvalue()


def ar_member(name, data):
    hdr = "%-16s%-12d%-6d%-6d%-8s%-10d`\n" % (name, int(time.time()), 0, 0, "100644", len(data))
    out = hdr.encode("ascii") + data
    if len(data) % 2:
        out += b"\n"
    return out


def main():
    binary, cacert, outdir = sys.argv[1:4]
    b = lambda s: s.encode("utf-8")
    data = [
        ("./usr", 0o755, None), ("./usr/libexec", 0o755, None),
        ("./usr/libexec/mailtls", 0o755, open(binary, "rb").read()),
        ("./usr/share", 0o755, None), ("./usr/share/mailtls", 0o755, None),
        ("./usr/share/mailtls/cacert.pem", 0o644, open(cacert, "rb").read()),
        ("./usr/share/mailtls/README.txt", 0o644, b(README)),
        ("./Library", 0o755, None), ("./Library/LaunchDaemons", 0o755, None),
    ]
    for name, lport, host, port, flags in SERVICES:
        args = ["/usr/libexec/mailtls", "-l", str(lport)] + flags + [host, str(port)]
        argxml = "".join("\t\t<string>%s</string>\n" % a for a in args)
        label = "%s.%s" % (PKG, name)
        data.append(("./Library/LaunchDaemons/%s.plist" % label, 0o644,
                     b(PLIST % {"label": label, "args": argxml, "port": lport})))
    control = [
        ("./control", 0o644, b(CONTROL)),
        ("./postinst", 0o755, b(POSTINST)),
        ("./prerm", 0o755, b(PRERM)),
    ]
    deb = b"!<arch>\n" + ar_member("debian-binary", b"2.0\n") \
        + ar_member("control.tar.gz", tar_bytes(control)) \
        + ar_member("data.tar.gz", tar_bytes(data))
    path = os.path.join(outdir, "%s_%s_iphoneos-arm.deb" % (PKG, VERSION))
    f = open(path, "wb")
    f.write(deb)
    f.close()
    print("Built " + path)

if __name__ == "__main__":
    main()
