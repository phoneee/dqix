# ooni_loader.py
import csv, io, requests, tldextract, concurrent.futures
from pathlib import Path

RAW_URL = "https://github.com/citizenlab/test-lists/raw/master/lists/{code}.csv"

def fetch_ooni_list(country_code="th", cache_dir=Path("./cache"), force=False):
    """
    Download <country_code>.csv from Citizen Lab test-lists (or use on-disk cache).
    Returns a list of URL rows (dicts).
    """
    cache_dir.mkdir(exist_ok=True)
    fpath = cache_dir / f"{country_code}.csv"
    if force or not fpath.exists():
        r = requests.get(RAW_URL.format(code=country_code), timeout=20)
        r.raise_for_status()
        fpath.write_bytes(r.content)
    with fpath.open("r", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))

def unique_domains(rows, only_tld="th"):
    ext = tldextract.TLDExtract(cache_dir=False)  # avoid remote call
    seen = set()
    for row in rows:
        dom = ext(row["url"]).registered_domain
        if only_tld and not dom.endswith("." + only_tld):
            continue
        if dom and dom not in seen:
            seen.add(dom)
            yield dom

def score_domains(domains, scorer, max_workers=10):
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for dom, res in zip(domains, ex.map(scorer, domains)):
            yield dom, res

# --- quick CLI demo ---------------------------------------------------------
if __name__ == "__main__":
    from dqi_scorer import score  # ← your previous module
    rows = fetch_ooni_list("th")            # 1 Download
    domains = list(unique_domains(rows))    # 2 Filter & de-dup
    for dom, (dqi, detail) in score_domains(domains[:50], score):  # sample 50
        print(f"{dom:30}  DQI={dqi}  → {detail}")