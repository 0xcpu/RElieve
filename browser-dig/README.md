Search local browser history, cache and session files (macOS) for a lost identifier: a confirmation number, order ID, etc.

Covers Chrome, Brave, Edge, Arc, Vivaldi, Chromium, Safari and Firefox. Read-only; history databases are copied to a temp dir before reading.

## Usage

Requires [uv](https://docs.astral.sh/uv/). Give the terminal Full Disk Access, otherwise Safari and some caches are unreadable.

```sh
./browser_dig.py -p REGEX        # find the identifier in URLs, titles, cache and session files
./browser_dig.py -d DOMAIN       # timeline of visits and cached entries for a site
./browser_dig.py -d DOMAIN -p REGEX --since YYYY-MM-DD
```

Example:

```sh
./browser_dig.py -d example.com -p "\bABC[0-9]{6}\b" --since 2026-10-01
```

Wrap the pattern in `\b...\b`, otherwise it matches inside GUIDs and base64 blobs. With `-d`, matches tied to that domain are marked with `*`.

Optional: `brotli` (`uv run --with brotli browser_dig.py ...`) to search brotli-compressed cache bodies.
