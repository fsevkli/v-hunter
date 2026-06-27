"""
Download specific plugin versions from WordPress.org for rule validation.
Usage: python fetch.py <slug> <version>
"""
import io, sys, zipfile, time
from pathlib import Path
import requests

BASE = Path(__file__).parent / "plugins"
UA = "wp-hunter-validation/0.1 (security research)"

def fetch(slug: str, version: str) -> Path:
    dest = BASE / slug / version
    if dest.exists() and any(dest.rglob("*.php")):
        print(f"  already extracted: {dest}")
        return dest

    url = f"https://downloads.wordpress.org/plugin/{slug}.{version}.zip"
    print(f"  downloading {url} ...")
    r = requests.get(url, timeout=60, headers={"User-Agent": UA})
    if r.status_code != 200:
        print(f"  ERROR {r.status_code}")
        return dest

    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
        for m in zf.infolist():
            parts = Path(m.filename).parts
            if len(parts) < 2:
                continue
            rel = Path(*parts[1:])
            tgt = dest / rel
            if m.is_dir():
                tgt.mkdir(parents=True, exist_ok=True)
            else:
                tgt.parent.mkdir(parents=True, exist_ok=True)
                tgt.write_bytes(zf.read(m.filename))

    php = list(dest.rglob("*.php"))
    print(f"  extracted {len(php)} PHP files to {dest}")
    time.sleep(1)
    return dest

if __name__ == "__main__":
    slug, version = sys.argv[1], sys.argv[2]
    fetch(slug, version)
