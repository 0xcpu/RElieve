#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
import argparse
import re
import shutil
import sqlite3
import struct
import sys
import tempfile
import zlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

try:
    import brotli
except ImportError:
    brotli = None

HOME = Path.home()
APP_SUPPORT = HOME / "Library/Application Support"
CACHES = HOME / "Library/Caches"

CHROMIUM = {
    "Chrome": "Google/Chrome",
    "Brave": "BraveSoftware/Brave-Browser",
    "Edge": "Microsoft Edge",
    "Arc": "Arc/User Data",
    "Vivaldi": "Vivaldi",
    "Chromium": "Chromium",
}
CHROMIUM_STATE = ("Sessions", "Local Storage", "Session Storage", "IndexedDB", "Web Data")

# Each query yields (unix seconds, title, url). Chrome counts microseconds from 1601,
# Safari seconds from 2001, Firefox microseconds from 1970.
HISTORY_QUERIES = {
    "chromium": "SELECT v.visit_time / 1e6 - 11644473600, u.title, u.url FROM visits v JOIN urls u ON v.url = u.id",
    "safari": "SELECT v.visit_time + 978307200, v.title, i.url "
    "FROM history_visits v JOIN history_items i ON v.history_item = i.id",
    "firefox": "SELECT v.visit_date / 1e6, p.title, p.url "
    "FROM moz_historyvisits v JOIN moz_places p ON v.place_id = p.id",
}

SIMPLE_CACHE_MAGIC = 0xFCFB6D1BA7725C30
SIMPLE_CACHE_EOF = struct.pack("<Q", 0xF4FA6F45970D41D8)
SIMPLE_CACHE_HEADER = 24
MAX_FILE_SIZE = 64 * 1024 * 1024

EXAMPLES = """examples:
  browser_dig.py -d example.com -p "\\bABC[0-9]{6}\\b" --since 2026-10-01
  browser_dig.py -d example.com --since 2026-09-01
  browser_dig.py -p "(?i)\\border\\s*#?\\s*\\d{3}-\\d{7}-\\d{7}\\b"

Wrap the pattern in \\b...\\b: without it, IDs match inside hex GUIDs and base64 blobs.
"""


@dataclass
class Visit:
    ts: float
    source: str
    title: str
    url: str


@dataclass
class Hit:
    source: str
    path: Path
    match: str
    context: str
    url: str = ""


def warn(msg: str) -> None:
    print(f"warning: {msg}", file=sys.stderr)


def stamp(ts: float) -> str:
    return datetime.fromtimestamp(ts).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def section(title: str) -> None:
    print(f"\n== {title}")


def history_sources() -> list[tuple[str, Path, str]]:
    sources = []
    for name, rel in CHROMIUM.items():
        for db in sorted((APP_SUPPORT / rel).glob("*/History")):
            sources.append((f"{name}/{db.parent.name}", db, HISTORY_QUERIES["chromium"]))
    sources.append(("Safari", HOME / "Library/Safari/History.db", HISTORY_QUERIES["safari"]))
    for db in sorted((APP_SUPPORT / "Firefox/Profiles").glob("*/places.sqlite")):
        sources.append((f"Firefox/{db.parent.name}", db, HISTORY_QUERIES["firefox"]))
    return [s for s in sources if s[1].exists()]


def cache_dirs() -> list[tuple[str, Path, bool]]:
    dirs = []
    for name, rel in CHROMIUM.items():
        for d in sorted((CACHES / rel).glob("*/Cache/Cache_Data")):
            dirs.append((f"{name}/{d.parent.parent.name}", d, True))
    dirs.append(("Safari", CACHES / "com.apple.Safari", False))
    dirs.append(("Safari", HOME / "Library/Containers/com.apple.Safari/Data/Library/Caches", False))
    for d in sorted((CACHES / "Firefox/Profiles").glob("*/cache2")):
        dirs.append((f"Firefox/{d.parent.name}", d, False))
    return dirs


def state_paths() -> list[tuple[str, Path]]:
    paths = []
    for name, rel in CHROMIUM.items():
        for history in sorted((APP_SUPPORT / rel).glob("*/History")):
            paths += [(f"{name}/{history.parent.name}", history.parent / item) for item in CHROMIUM_STATE]
    return paths


def read_history(source: str, db: Path, query: str, tmp: Path) -> list[Visit]:
    copy = Path(tempfile.mkdtemp(dir=tmp)) / db.name
    for suffix in ("", "-wal", "-journal"):
        src = db.with_name(db.name + suffix)
        if src.exists():
            shutil.copyfile(src, copy.with_name(copy.name + suffix))
    con = sqlite3.connect(copy)
    try:
        rows = con.execute(query).fetchall()
    finally:
        con.close()
    return [Visit(ts, source, title or "", url) for ts, title, url in rows]


def read_files(root: Path):
    try:
        paths = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()]
    except PermissionError:
        warn(f"{root}: permission denied (give the terminal Full Disk Access)")
        return
    denied = 0
    for path in paths:
        try:
            if path.stat().st_size <= MAX_FILE_SIZE:
                yield path, path.read_bytes()
        except PermissionError:
            denied += 1
        except OSError:
            continue
    if denied:
        warn(f"{root}: {denied} files unreadable (give the terminal Full Disk Access)")


def printable(text: str) -> str:
    return "".join(c if " " <= c <= "~" else "." for c in text)


def find(regex: re.Pattern, data: bytes, utf16: bool = False):
    texts = [data.decode("latin-1")]
    if utf16:
        texts += [data[i:].decode("utf-16-le", "ignore") for i in (0, 1)]
    for text in texts:
        for m in regex.finditer(text):
            yield m.group(0), printable(text[max(0, m.start() - 50) : m.end() + 50])


def decode_body(body: bytes, encoding: bytes) -> bytes:
    try:
        if encoding in (b"gzip", b"deflate"):
            return zlib.decompressobj(zlib.MAX_WBITS | 32).decompress(body)
        if encoding == b"br" and brotli is not None:
            return brotli.decompress(body)
    except Exception:
        pass
    return body


def parse_simple_cache_entry(data: bytes) -> tuple[str, bytes] | None:
    if len(data) < SIMPLE_CACHE_HEADER or struct.unpack_from("<Q", data)[0] != SIMPLE_CACHE_MAGIC:
        return None
    key_end = SIMPLE_CACHE_HEADER + struct.unpack_from("<I", data, 12)[0]
    key = data[SIMPLE_CACHE_HEADER:key_end].decode("utf-8", "replace")
    body_end = data.find(SIMPLE_CACHE_EOF, key_end)
    if body_end < 0:
        return key, b""
    encoding = re.search(rb"content-encoding:\s*([\w-]+)", data[body_end:], re.IGNORECASE)
    return key, decode_body(data[key_end:body_end], encoding.group(1).lower() if encoding else b"")


def key_url(key: str) -> str:
    m = re.search(r"https?://\S+$", key)
    return m.group(0) if m else key


def scan_cache(source: str, root: Path, chromium: bool, regex: re.Pattern | None, domain: str | None):
    hits, entries = [], []
    for path, data in read_files(root):
        entry = parse_simple_cache_entry(data) if chromium else None
        if entry is None:
            if regex:
                hits += [Hit(source, path, m, ctx) for m, ctx in find(regex, data)]
            continue
        key, body = entry
        url = key_url(key)
        if domain and domain in key.lower():
            entries.append((path.stat().st_mtime, source, url))
        if regex:
            hits += [Hit(source, path, m, ctx, url) for blob in (key.encode(), body) for m, ctx in find(regex, blob)]
    return hits, entries


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Search local browser history, cache and session files for a lost identifier. "
        "Nothing is modified; history databases are read from temporary copies.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-p", "--pattern", help="regex for the identifier; prefix (?i) to ignore case")
    parser.add_argument("-d", "--domain", help="site the identifier came from, e.g. example.com")
    parser.add_argument("--since", help="only show history visits on or after YYYY-MM-DD")
    args = parser.parse_args()
    if not args.pattern and not args.domain:
        parser.error("give --pattern, --domain, or both")
    regex = re.compile(args.pattern) if args.pattern else None
    domain = args.domain.lower() if args.domain else None
    since = datetime.fromisoformat(args.since).timestamp() if args.since else 0

    visits = []
    with tempfile.TemporaryDirectory() as tmp:
        for source, db, query in history_sources():
            try:
                visits += read_history(source, db, query, Path(tmp))
            except PermissionError:
                warn(f"{source}: permission denied (give the terminal Full Disk Access)")
            except (OSError, sqlite3.Error) as e:
                warn(f"{source}: {e}")

    if domain:
        timeline = sorted((v for v in visits if domain in v.url.lower() and v.ts >= since), key=lambda v: v.ts)
        section(f"History: {len(timeline)} visits to {domain}")
        for v in timeline:
            print(f"{stamp(v.ts)}  {v.source}  {v.title[:80]}")
            print(f"    {v.url[:160]}")

    if regex:
        latest = {}
        for v in visits:
            for m in regex.finditer(f"{v.title} {v.url}"):
                key = (m.group(0), v.url)
                if key not in latest or v.ts > latest[key].ts:
                    latest[key] = v
        section(f"History: {len(latest)} URLs or titles matching the pattern")
        for (match, _), v in sorted(latest.items(), key=lambda kv: kv[1].ts):
            print(f"{match}  {stamp(v.ts)}  {v.source}  {v.url[:160]}")

    hits, entries = [], []
    for source, root, chromium in cache_dirs():
        h, e = scan_cache(source, root, chromium, regex, domain)
        hits += h
        entries += e

    if domain:
        section(f"Cache: {len(entries)} entries from {domain}")
        for mtime, source, url in sorted(entries):
            print(f"{stamp(mtime)}  {source}  {url[:160]}")

    if regex:
        for source, root in state_paths():
            for path, data in read_files(root):
                hits += [Hit(source, path, m, ctx) for m, ctx in find(regex, data, utf16=True)]

        def related(h: Hit) -> bool:
            return bool(domain) and domain in f"{h.url} {h.context}".lower()

        ranked = sorted({(h.path, h.match): h for h in hits}.values(), key=lambda h: (not related(h), str(h.path)))
        legend = f" (* = tied to {domain})" if domain else ""
        section(f"Cache and session files: {len(ranked)} pattern matches{legend}")
        for h in ranked:
            print(f"{'*' if related(h) else ' '} {h.match}  {h.source}  {h.url[:140] or h.path}")
            print(f"    {h.context}")
            if h.url:
                print(f"    {h.path}")


if __name__ == "__main__":
    main()
