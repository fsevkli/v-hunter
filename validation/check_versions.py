"""
Check which versions of a plugin are available on WP.org.
"""
import sys, requests

UA = "wp-hunter-validation/0.1"

def check(slug: str):
    url = f"https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]={slug}&request[fields][versions]=1"
    r = requests.get(url, timeout=15, headers={"User-Agent": UA})
    data = r.json()
    if not isinstance(data, dict):
        print(f"{slug}: not found")
        return
    versions = list(data.get("versions", {}).keys())
    versions = [v for v in versions if v != "trunk"]
    versions.sort(key=lambda x: [int(p) if p.isdigit() else p for p in x.split(".")])
    print(f"{slug}: latest={data.get('version','?')}, versions (last 10): {versions[-10:]}")

for slug in sys.argv[1:]:
    check(slug)
