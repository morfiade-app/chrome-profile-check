#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tell what is actually inside your Chrome profiles — and what a plain copy loses.

Copying a Chrome profile folder to another computer looks like it works: the
size matches, the files are all there. Then you open it and the logins are gone,
the passwords are blank, and there is nothing in the error message to explain
why. This script explains why *before* you copy, not after.

It reads metadata only:

* sizes — what is data and what is cache you never needed to move;
* counts — cookies, saved logins, bookmarks, extensions;
* encryption markers — which key your cookies are tied to.

⚠️ It never decrypts anything and never prints a single value. No cookie
content, no password, no encryption key: only how many there are and which
scheme protects them. Databases are opened read-only and immutable, so a
running Chrome is not disturbed.

    python chrome_profile_check.py            # every Chrome profile found
    python chrome_profile_check.py --json     # same, machine-readable
    python chrome_profile_check.py --dir "D:\\Profiles"

Windows-first: that is where the interesting failure lives (App-Bound
Encryption ties cookies to one Windows account). macOS and Linux paths are
detected too, and the report says plainly what it cannot determine there.
"""

import argparse
import json
import os
import sqlite3
import sys

# Chrome's cookie values carry a version prefix in front of the ciphertext.
# These three bytes are not a secret — they say which key encrypted the rest.
PREFIXES = {
    b"v10": "v10 (machine key, DPAPI)",
    b"v11": "v11 (machine key, DPAPI)",
    b"v20": "v20 (App-Bound, tied to this Windows account)",
}

CACHE_DIRS = (
    "Cache", "Code Cache", "GPUCache", "ShaderCache", "GrShaderCache",
    "DawnCache", "DawnGraphiteCache", "DawnWebGPUCache",
    os.path.join("Service Worker", "CacheStorage"),
    os.path.join("Service Worker", "ScriptCache"),
)


def user_data_dirs():
    """Where Chrome keeps its profiles on this system."""
    home = os.path.expanduser("~")
    if os.name == "nt":
        local = os.environ.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local")
        return [
            os.path.join(local, "Google", "Chrome", "User Data"),
            os.path.join(local, "Google", "Chrome Beta", "User Data"),
            os.path.join(local, "Chromium", "User Data"),
        ]
    if sys.platform == "darwin":
        base = os.path.join(home, "Library", "Application Support")
        return [os.path.join(base, "Google", "Chrome"),
                os.path.join(base, "Chromium")]
    return [os.path.join(home, ".config", "google-chrome"),
            os.path.join(home, ".config", "chromium")]


def dir_size(path):
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass            # файл исчез или занят — на итог это не влияет
    return total


def human(size):
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return "%.0f %s" % (size, unit) if unit != "GB" else "%.1f %s" % (size, unit)
        size /= 1024.0


def open_ro(path):
    """Open a Chrome database without touching it.

    immutable=1 is what lets this work while Chrome is running: sqlite reads the
    file without taking locks and without replaying the journal. The worst case
    is a slightly stale count, which is fine for a report.
    """
    uri = "file:%s?mode=ro&immutable=1" % path.replace("?", "%3f").replace("#", "%23")
    return sqlite3.connect(uri, uri=True)


def count_rows(path, table):
    if not os.path.isfile(path):
        return None
    try:
        with open_ro(path) as db:
            return db.execute("SELECT COUNT(*) FROM %s" % table).fetchone()[0]
    except sqlite3.Error:
        return None


def cookie_schemes(path):
    """Which encryption prefixes the cookies carry, and how many of each.

    Only the first three bytes of each value are read. That is a version tag,
    not content — the point is to tell a portable cookie from one that is
    locked to this machine.
    """
    if not os.path.isfile(path):
        return {}
    found = {}
    try:
        with open_ro(path) as db:
            rows = db.execute("SELECT encrypted_value FROM cookies")
            for (blob,) in rows:
                head = bytes(blob or b"")[:3]
                key = PREFIXES.get(head, "unencrypted or unknown")
                found[key] = found.get(key, 0) + 1
    except sqlite3.Error:
        return {}
    return found


def bookmark_count(path):
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None

    def walk(node):
        if node.get("type") == "url":
            return 1
        return sum(walk(child) for child in node.get("children", []))

    return sum(walk(root) for root in (data.get("roots") or {}).values()
               if isinstance(root, dict))


def extension_count(path):
    if not os.path.isdir(path):
        return None
    return sum(1 for name in os.listdir(path)
               if os.path.isdir(os.path.join(path, name)))


def local_state(user_data):
    path = os.path.join(user_data, "Local State")
    if not os.path.isfile(path):
        return {}, {}
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}, {}
    crypt = data.get("os_crypt") or {}
    names = {}
    for key, info in ((data.get("profile") or {}).get("info_cache") or {}).items():
        names[key] = info.get("name") or key
    # Presence only. The key itself is never read into the report.
    flags = {
        "has_machine_key": bool(crypt.get("encrypted_key")),
        "has_app_bound_key": bool(crypt.get("app_bound_encrypted_key")),
    }
    return flags, names


def inspect_profile(path, display_name):
    total = dir_size(path)
    cache = 0
    for rel in CACHE_DIRS:
        sub = os.path.join(path, rel)
        if os.path.isdir(sub):
            cache += dir_size(sub)
    cookies_db = os.path.join(path, "Network", "Cookies")
    if not os.path.isfile(cookies_db):
        cookies_db = os.path.join(path, "Cookies")
    return {
        "name": display_name,
        "path": path,
        "size_total": total,
        "size_cache": cache,
        "size_payload": max(total - cache, 0),
        "cookies": count_rows(cookies_db, "cookies"),
        "cookie_schemes": cookie_schemes(cookies_db),
        "logins": count_rows(os.path.join(path, "Login Data"), "logins"),
        "bookmarks": bookmark_count(os.path.join(path, "Bookmarks")),
        "extensions": extension_count(os.path.join(path, "Extensions")),
    }


def profiles_in(user_data):
    """Profile folders, in the order Chrome itself lists them."""
    flags, names = local_state(user_data)
    found = []
    for name in sorted(os.listdir(user_data)):
        path = os.path.join(user_data, name)
        if not os.path.isdir(path):
            continue
        if name != "Default" and not name.startswith("Profile "):
            continue
        if not os.path.isfile(os.path.join(path, "Preferences")):
            continue
        found.append(inspect_profile(path, names.get(name, name)))
    return flags, found


def report(user_data, flags, found):
    print("=" * 72)
    print(user_data)
    if flags:
        print("  cookie key:      %s" % ("App-Bound (v20) present - cookies are tied to this Windows account"
                                         if flags.get("has_app_bound_key")
                                         else "machine key only"))
    print("=" * 72)
    if not found:
        print("  no profiles found here")
        return
    for p in found:
        print()
        print("  %s   (%s)" % (p["name"], os.path.basename(p["path"])))
        print("    size          %s total, of which %s is cache you never need to move"
              % (human(p["size_total"]), human(p["size_cache"])))
        print("    worth moving  %s" % human(p["size_payload"]))
        for label, value in (("cookies", p["cookies"]), ("saved logins", p["logins"]),
                             ("bookmarks", p["bookmarks"]), ("extensions", p["extensions"])):
            print("    %-13s %s" % (label, "unreadable (Chrome running?)" if value is None else value))
        for scheme, count in sorted(p["cookie_schemes"].items()):
            print("    %-13s %d cookies" % ("  " + scheme, count))


def verdict(flags, everything):
    print()
    print("-" * 72)
    print("WHAT A PLAIN FOLDER COPY LOSES")
    print("-" * 72)
    v20 = sum(c for p in everything for s, c in p["cookie_schemes"].items() if s.startswith("v20"))
    v1x = sum(c for p in everything for s, c in p["cookie_schemes"].items()
              if s.startswith("v10") or s.startswith("v11"))
    if v20:
        print("  %d cookies use App-Bound encryption (v20). They are bound to this" % v20)
        print("  Windows account: copied to another machine - or to another account on")
        print("  this one - they decrypt to nothing, and every site asks you to log in")
        print("  again. This is Chrome's own protection, not a bug in your copy.")
    if v1x:
        print("  %d cookies use the older machine key (v10/v11). Same story across" % v1x)
        print("  machines: the key lives in your Windows profile, not in the folder.")
    if not v20 and not v1x:
        print("  Cookie encryption could not be read (Chrome may be running, or this")
        print("  is not Windows). Sizes and counts above are still valid.")
    print()
    print("  Passwords: stored encrypted with the same account-bound key. Chrome's own")
    print("  export to CSV is the supported way to move them.")
    print("  Bookmarks, history, extensions and settings: these do survive a copy.")
    print()
    print("  So the honest summary: a folder copy moves your bookmarks and settings,")
    print("  not your sessions. Anyone promising otherwise is describing an older")
    print("  Chrome, or something you should not run.")


def main(argv=None):
    # A profile path can contain anything, and a Windows console is rarely UTF-8.
    # Replace what the console cannot show instead of dying on one character.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    parser = argparse.ArgumentParser(
        description="Inspect local Chrome profiles: sizes, counts, cookie encryption. "
                    "Reads metadata only — never decrypts, never prints values.")
    parser.add_argument("--dir", action="append", default=[],
                        help="extra User Data directory to inspect (repeatable)")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    roots = [d for d in (args.dir or user_data_dirs()) if os.path.isdir(d)]
    if not roots:
        print("No Chrome profile directory found. Point at one with --dir.")
        return 1

    collected, everything = [], []
    for root in roots:
        flags, found = profiles_in(root)
        collected.append({"user_data": root, "flags": flags, "profiles": found})
        everything.extend(found)

    if args.json:
        print(json.dumps(collected, ensure_ascii=False, indent=2))
        return 0

    for item in collected:
        report(item["user_data"], item["flags"], item["profiles"])
    if everything:
        verdict(collected[0]["flags"], everything)
    return 0


if __name__ == "__main__":
    sys.exit(main())
